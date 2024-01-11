package gokhttp_ja3spoof

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	device_utils "github.com/BRUHItsABunny/go-device-utils"
	oohttp "github.com/ooni/oohttp"
	utls "github.com/refraction-networking/utls"
	"math/rand"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// uconn is an adapter from utls.UConn to TLSConn.
type uconn struct {
	*utls.UConn
}

// ConnectionState implements TLSConn's ConnectionState.
func (c *uconn) ConnectionState() tls.ConnectionState {
	cs := c.UConn.ConnectionState()
	return tls.ConnectionState{
		Version:                     cs.Version,
		HandshakeComplete:           cs.HandshakeComplete,
		DidResume:                   cs.DidResume,
		CipherSuite:                 cs.CipherSuite,
		NegotiatedProtocol:          cs.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  cs.NegotiatedProtocolIsMutual,
		ServerName:                  cs.ServerName,
		PeerCertificates:            cs.PeerCertificates,
		VerifiedChains:              cs.VerifiedChains,
		SignedCertificateTimestamps: cs.SignedCertificateTimestamps,
		OCSPResponse:                cs.OCSPResponse,
		// TLSUnique:                   cs.TLSUnique,
	}
}

// HandshakeContext implements TLSConn's HandshakeContext.
func (c *uconn) HandshakeContext(ctx context.Context) error {
	errch := make(chan error, 1)
	go func() {
		errch <- c.UConn.Handshake()
	}()
	select {
	case err := <-errch:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

type Ja3SpoofingOptionV2 struct {
	TLSConfig       *tls.Config
	ClientHelloSpec *utls.ClientHelloSpec
	Browser         *device_utils.Browser
	ClientHelloID   *utls.ClientHelloID
	ExtensionMap    func() map[int32]utls.TLSExtension
}

func DefaultExtensionMapV2() map[int32]utls.TLSExtension {
	return map[int32]utls.TLSExtension{
		0: &utls.SNIExtension{},
		5: &utls.StatusRequestExtension{},
		13: &utls.SignatureAlgorithmsExtension{
			SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.SignatureScheme(utls.GREASE_PLACEHOLDER),
				utls.ECDSAWithP256AndSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.ECDSAWithP521AndSHA512,
				utls.PSSWithSHA256,
				utls.PSSWithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA256,
				utls.PKCS1WithSHA384,
				utls.PKCS1WithSHA512,
				utls.ECDSAWithSHA1,
				utls.PKCS1WithSHA1,
			},
		},
		16: &utls.ALPNExtension{
			AlpnProtocols: []string{"h2", "http/1.1"},
		},
		17: &utls.GenericExtension{Id: 17},
		18: &utls.SCTExtension{},
		21: &utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle},
		22: &utls.GenericExtension{Id: 22},
		23: &utls.UtlsExtendedMasterSecretExtension{},
		27: &utls.UtlsCompressCertExtension{
			Algorithms: []utls.CertCompressionAlgo{utls.CertCompressionBrotli},
		},
		28: &utls.FakeRecordSizeLimitExtension{},
		35: &utls.SessionTicketExtension{},
		34: &utls.GenericExtension{Id: 34},
		41: &utls.GenericExtension{Id: 41},
		43: &utls.SupportedVersionsExtension{Versions: []uint16{
			utls.GREASE_PLACEHOLDER,
			utls.VersionTLS13,
			utls.VersionTLS12,
		}},
		44: &utls.CookieExtension{},
		45: &utls.PSKKeyExchangeModesExtension{Modes: []uint8{
			utls.PskModeDHE,
		}},
		49: &utls.GenericExtension{Id: 49},
		50: &utls.GenericExtension{Id: 50},
		51: &utls.KeyShareExtension{KeyShares: []utls.KeyShare{
			{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
			{Group: utls.X25519},
		}},
		13172: &utls.NPNExtension{},
		17513: &utls.ApplicationSettingsExtension{
			SupportedProtocols: []string{
				"h2",
			},
		},
		65281: &utls.RenegotiationInfoExtension{
			Renegotiation: utls.RenegotiateOnceAsClient,
		},
	}

}

func NewJa3SpoofingOptionV2(clientHelloSpec *utls.ClientHelloSpec, clientHelloId *utls.ClientHelloID) *Ja3SpoofingOptionV2 {
	if clientHelloSpec != nil {
		clientHelloId = &utls.HelloCustom
	}
	if clientHelloSpec == nil && clientHelloId == nil {
		clientHelloId = &utls.HelloRandomized
	}

	return &Ja3SpoofingOptionV2{ClientHelloSpec: clientHelloSpec, ClientHelloID: clientHelloId}
}

func (o *Ja3SpoofingOptionV2) factoryFunc(conn net.Conn, config *tls.Config) oohttp.TLSConn {
	uConfig := &utls.Config{
		RootCAs:                     config.RootCAs,
		NextProtos:                  config.NextProtos,
		ServerName:                  config.ServerName,
		InsecureSkipVerify:          config.InsecureSkipVerify,
		DynamicRecordSizingDisabled: config.DynamicRecordSizingDisabled,
	}

	uTLSConn := utls.UClient(conn, uConfig, *o.ClientHelloID)
	if *o.ClientHelloID == utls.HelloCustom && o.ClientHelloSpec != nil {
		if err := uTLSConn.ApplyPreset(o.ClientHelloSpec); err != nil {
			panic(fmt.Errorf("Ja3SpoofingOptionV2.factoryFunc: dialTLSCtx: uTLSConn.ApplyPreset: %w", err))
		}
	}

	return &uconn{uTLSConn}
}

func (o *Ja3SpoofingOptionV2) Execute(client *http.Client) error {
	client.Transport = &oohttp.StdlibTransport{
		Transport: &oohttp.Transport{
			// DialContext:           DefaultNetDialer.DialContext,
			// DialTLSContext:        tlsDialer,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientFactory:      o.factoryFunc,
		},
	}

	return nil
}

func (o *Ja3SpoofingOptionV2) ExecuteV2(client *oohttp.Client) error {
	client.Transport = &oohttp.Transport{
		// DialContext:           DefaultNetDialer.DialContext,
		// DialTLSContext:        tlsDialer,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientFactory:      o.factoryFunc,
	}

	return nil
}

type ExtensionMapFunc func() map[int32]utls.TLSExtension

func BrowserToClientHelloSpec(browser *device_utils.Browser, extensionMapFunc ExtensionMapFunc) (*utls.ClientHelloSpec, error) {
	if extensionMapFunc == nil {
		extensionMapFunc = DefaultExtensionMapV2
	}

	cipherSuites := make([]uint16, len(browser.TlsFingerprint.CipherSuites))
	for i, suite := range browser.TlsFingerprint.CipherSuites {
		cipherSuites[i] = uint16(suite)
	}

	extensionMap := extensionMapFunc()

	ellipticCurves := make([]utls.CurveID, len(browser.TlsFingerprint.EllipticCurves))
	for i, curve := range browser.TlsFingerprint.EllipticCurves {
		ellipticCurves[i] = utls.CurveID(curve)
	}
	extensionMap[10] = &utls.SupportedCurvesExtension{Curves: ellipticCurves}

	ellipticPointFmts := make([]byte, len(browser.TlsFingerprint.EllipticCurvePointFormats))
	for i, pointFmt := range browser.TlsFingerprint.EllipticCurvePointFormats {
		ellipticPointFmts[i] = byte(pointFmt)
	}
	extensionMap[11] = &utls.SupportedPointsExtension{SupportedPoints: ellipticPointFmts}

	var extensions []utls.TLSExtension

	// Don't just implement GREASE, tell them the GREASE, except for 21 and 41
	isChromium := strings.Contains(browser.BrandHeader, "Chromium")
	extensionsRaw := make([]device_utils.Browser_TLSFingerprint_Extensions, len(browser.TlsFingerprint.Extensions))
	copy(extensionsRaw, browser.TlsFingerprint.Extensions)
	if isChromium {
		rand.Shuffle(len(extensionsRaw), func(i, j int) {
			extensionsRaw[i], extensionsRaw[j] = extensionsRaw[j], extensionsRaw[i]
		})
	}
	extensionsRawSpecial := make([]int, 0)

	for _, e := range extensionsRaw {
		te, ok := extensionMap[int32(e)]
		if !ok {
			fmt.Println(fmt.Sprintf("extension not found: %s", e))
		} else {
			if e == 21 || e == 41 {
				extensionsRawSpecial = append(extensionsRawSpecial, int(e))
				continue
			}
			extensions = append(extensions, te)
		}
	}
	sort.Ints(extensionsRawSpecial)
	for _, e := range extensionsRawSpecial {
		if e == 21 && isChromium {
			extensions = append(extensions, &utls.UtlsGREASEExtension{})
		}
		te, ok := extensionMap[int32(e)]
		if ok {
			extensions = append(extensions, te)
		}
	}

	tlsSpec := &utls.ClientHelloSpec{
		CipherSuites:       cipherSuites,
		CompressionMethods: []byte{0},
		Extensions:         extensions,
		GetSessionID:       sha256.Sum256,
	}

	return tlsSpec, nil
}

// Source: https://github.com/gospider007/ja3

// TLSVersion，Ciphers，Extensions，EllipticCurves，EllipticCurvePointFormats
func createTlsVersion(ver uint16) (tlsMaxVersion uint16, tlsMinVersion uint16, tlsSuppor utls.TLSExtension, err error) {
	switch ver {
	case utls.VersionTLS13:
		tlsMaxVersion = utls.VersionTLS13
		tlsMinVersion = utls.VersionTLS10
		tlsSuppor = &utls.SupportedVersionsExtension{
			Versions: []uint16{
				utls.GREASE_PLACEHOLDER,
				utls.VersionTLS13,
				utls.VersionTLS12,
				utls.VersionTLS11,
				utls.VersionTLS10,
			},
		}
	case utls.VersionTLS12:
		tlsMaxVersion = utls.VersionTLS12
		tlsMinVersion = utls.VersionTLS11
		tlsSuppor = &utls.SupportedVersionsExtension{
			Versions: []uint16{
				utls.GREASE_PLACEHOLDER,
				utls.VersionTLS12,
				utls.VersionTLS11,
			},
		}
	case utls.VersionTLS11:
		tlsMaxVersion = utls.VersionTLS11
		tlsMinVersion = utls.VersionTLS10
		tlsSuppor = &utls.SupportedVersionsExtension{
			Versions: []uint16{
				utls.GREASE_PLACEHOLDER,
				utls.VersionTLS11,
				utls.VersionTLS10,
			},
		}
	default:
		err = errors.New("ja3Str tls version error")
	}
	return
}

func createCiphers(ciphers []string) ([]uint16, error) {
	cipherSuites := []uint16{utls.GREASE_PLACEHOLDER}
	for _, val := range ciphers {
		if n, err := strconv.ParseUint(val, 10, 16); err != nil {
			return nil, errors.New("ja3Str cipherSuites error")
		} else {
			cipherSuites = append(cipherSuites, uint16(n))
		}
	}
	return cipherSuites, nil
}

func createCurves(curves []string) (curvesExtension utls.TLSExtension, err error) {
	curveIds := []utls.CurveID{utls.GREASE_PLACEHOLDER}
	for _, val := range curves {
		if n, err := strconv.ParseUint(val, 10, 16); err != nil {
			return nil, errors.New("ja3Str curves error")
		} else {
			curveIds = append(curveIds, utls.CurveID(uint16(n)))
		}
	}
	return &utls.SupportedCurvesExtension{Curves: curveIds}, nil
}

func createPointFormats(points []string) (curvesExtension utls.TLSExtension, err error) {
	supportedPoints := []uint8{}
	for _, val := range points {
		if n, err := strconv.ParseUint(val, 10, 8); err != nil {
			return nil, errors.New("ja3Str point error")
		} else {
			supportedPoints = append(supportedPoints, uint8(n))
		}
	}
	return &utls.SupportedPointsExtension{SupportedPoints: supportedPoints}, nil
}

// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
type extensionOption struct {
	data []byte
	ext  utls.TLSExtension
}

func createExtension(extensionId uint16, options ...extensionOption) (utls.TLSExtension, bool) {
	var option extensionOption
	if len(options) > 0 {
		option = options[0]
	}
	switch extensionId {
	case 0:
		if option.ext != nil {
			extV := *(option.ext.(*utls.SNIExtension))
			return &extV, true
		}
		extV := new(utls.SNIExtension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 5:
		if option.ext != nil {
			extV := *(option.ext.(*utls.StatusRequestExtension))
			return &extV, true
		}
		extV := new(utls.StatusRequestExtension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 10:
		if option.ext != nil {
			extV := *(option.ext.(*utls.SupportedCurvesExtension))
			return &extV, true
		}
		extV := new(utls.SupportedCurvesExtension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 11:
		if option.ext != nil {
			extV := *(option.ext.(*utls.SupportedPointsExtension))
			return &extV, true
		}
		extV := new(utls.SupportedPointsExtension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 13:
		if option.ext != nil {
			extV := *(option.ext.(*utls.SignatureAlgorithmsExtension))
			return &extV, true
		}
		extV := new(utls.SignatureAlgorithmsExtension)
		if option.data != nil {
			extV.Write(option.data)
		} else {
			// Default Golang
			extV.SupportedSignatureAlgorithms = []utls.SignatureScheme{
				utls.PSSWithSHA256,
				utls.ECDSAWithP256AndSHA256,
				utls.Ed25519,
				utls.PSSWithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA256,
				utls.PKCS1WithSHA384,
				utls.PKCS1WithSHA512,
				utls.ECDSAWithP384AndSHA384,
				utls.ECDSAWithP521AndSHA512,
				utls.ECDSAWithSHA1,
				utls.PKCS1WithSHA1,
			}
		}
		return extV, true
	case 16:
		if option.ext != nil {
			extV := *(option.ext.(*utls.ALPNExtension))
			return &extV, true
		}
		extV := new(utls.ALPNExtension)
		if option.data != nil {
			extV.Write(option.data)
		} else {
			extV.AlpnProtocols = []string{"h2", "http/1.1"}
		}
		return extV, true
	case 17:
		if option.ext != nil {
			extV := *(option.ext.(*utls.StatusRequestV2Extension))
			return &extV, true
		}
		extV := new(utls.StatusRequestV2Extension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 18:
		if option.ext != nil {
			extV := *(option.ext.(*utls.SCTExtension))
			return &extV, true
		}
		extV := new(utls.SCTExtension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 21:
		if option.ext != nil {
			extV := *(option.ext.(*utls.UtlsPaddingExtension))
			return &extV, true
		}
		extV := new(utls.UtlsPaddingExtension)
		if option.data != nil {
			extV.Write(option.data)
		} else {
			extV.GetPaddingLen = utls.BoringPaddingStyle
		}
		return extV, true
	case 23:
		if option.ext != nil {
			extV := *(option.ext.(*utls.ExtendedMasterSecretExtension))
			return &extV, true
		}
		extV := new(utls.ExtendedMasterSecretExtension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 24:
		if option.ext != nil {
			extV := *(option.ext.(*utls.FakeTokenBindingExtension))
			return &extV, true
		}
		extV := new(utls.FakeTokenBindingExtension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 27:
		if option.ext != nil {
			extV := *(option.ext.(*utls.UtlsCompressCertExtension))
			return &extV, true
		}
		extV := new(utls.UtlsCompressCertExtension)
		if option.data != nil {
			extV.Write(option.data)
		} else {
			extV.Algorithms = []utls.CertCompressionAlgo{utls.CertCompressionBrotli}
		}
		return extV, true
	case 28:
		if option.ext != nil {
			extV := *(option.ext.(*utls.FakeRecordSizeLimitExtension))
			return &extV, true
		}
		extV := new(utls.FakeRecordSizeLimitExtension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 34:
		if option.ext != nil {
			extV := *(option.ext.(*utls.FakeDelegatedCredentialsExtension))
			return &extV, true
		}
		extV := new(utls.FakeDelegatedCredentialsExtension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 35:
		if option.ext != nil {
			extV := *(option.ext.(*utls.SessionTicketExtension))
			return &extV, true
		}
		extV := new(utls.SessionTicketExtension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 41:
		if option.ext != nil {
			extV := *(option.ext.(*utls.UtlsPreSharedKeyExtension))
			return &extV, true
		}
		extV := new(utls.UtlsPreSharedKeyExtension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 43:
		if option.ext != nil {
			extV := *(option.ext.(*utls.SupportedVersionsExtension))
			return &extV, true
		}
		extV := new(utls.SupportedVersionsExtension)
		extV.Versions = []uint16{
			utls.GREASE_PLACEHOLDER,
			utls.VersionTLS13,
			utls.VersionTLS12,
		}
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 44:
		if option.ext != nil {
			extV := *(option.ext.(*utls.CookieExtension))
			return &extV, true
		}
		extV := new(utls.CookieExtension)
		if option.data != nil {
			extV.Cookie = option.data
		}
		return extV, true
	case 45:
		if option.ext != nil {
			extV := *(option.ext.(*utls.PSKKeyExchangeModesExtension))
			return &extV, true
		}
		extV := new(utls.PSKKeyExchangeModesExtension)
		if option.data != nil {
			extV.Write(option.data)
		} else {
			extV.Modes = []uint8{utls.PskModeDHE}
		}
		return extV, true
	case 50:
		if option.ext != nil {
			extV := *(option.ext.(*utls.SignatureAlgorithmsCertExtension))
			return &extV, true
		}
		extV := new(utls.SignatureAlgorithmsCertExtension)
		if option.data != nil {
			extV.Write(option.data)
		} else {
			extV.SupportedSignatureAlgorithms = []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.ECDSAWithP521AndSHA512,
				utls.PSSWithSHA256,
				utls.PSSWithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA256,
				utls.PKCS1WithSHA384,
				utls.PKCS1WithSHA512,
				utls.ECDSAWithSHA1,
				utls.PKCS1WithSHA1,
			}
		}
		return extV, true
	case 51:
		if option.ext != nil {
			extt := new(utls.KeyShareExtension)
			if keyShares := option.ext.(*utls.KeyShareExtension).KeyShares; keyShares != nil {
				extt.KeyShares = make([]utls.KeyShare, len(keyShares))
				copy(extt.KeyShares, keyShares)
			}
			return extt, true
		}
		extV := new(utls.KeyShareExtension)
		if option.data != nil {
			extV.Write(option.data)
		} else {
			extV.KeyShares = []utls.KeyShare{
				{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
				{Group: utls.X25519},
			}
		}
		return extV, true
	case 57:
		if option.ext != nil {
			extV := *(option.ext.(*utls.QUICTransportParametersExtension))
			return &extV, true
		}
		return new(utls.QUICTransportParametersExtension), true
	case 13172:
		if option.ext != nil {
			extV := *(option.ext.(*utls.NPNExtension))
			return &extV, true
		}
		extV := new(utls.NPNExtension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 17513:
		if option.ext != nil {
			extV := *(option.ext.(*utls.ApplicationSettingsExtension))
			return &extV, true
		}
		extV := new(utls.ApplicationSettingsExtension)
		if option.data != nil {
			extV.Write(option.data)
		} else {
			extV.SupportedProtocols = []string{"h2", "http/1.1"}
		}
		return extV, true
	case 30031:
		if option.ext != nil {
			extV := *(option.ext.(*utls.FakeChannelIDExtension))
			return &extV, true
		}
		extV := new(utls.FakeChannelIDExtension)
		if option.data != nil {
			extV.Write(option.data)
		} else {
			extV.OldExtensionID = true
		}
		return extV, true
	case 30032:
		if option.ext != nil {
			extV := *(option.ext.(*utls.FakeChannelIDExtension))
			return &extV, true
		}
		extV := new(utls.FakeChannelIDExtension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 65281:
		if option.ext != nil {
			extV := *(option.ext.(*utls.RenegotiationInfoExtension))
			return &extV, true
		}
		extV := new(utls.RenegotiationInfoExtension)
		if option.data != nil {
			extV.Write(option.data)
		} else {
			extV.Renegotiation = utls.RenegotiateOnceAsClient
		}
		return extV, true
	default:
		if option.data != nil {
			return &utls.GenericExtension{
				Id:   extensionId,
				Data: option.data,
			}, false
		}
		return option.ext, false
	}
}

func IsGREASEUint16(v uint16) bool {
	// First byte is same as second byte
	// and lowest nibble is 0xa
	return ((v >> 8) == v&0xff) && v&0xf == 0xa
}

func createExtensions(extensions []string, tlsExtension, curvesExtension, pointExtension utls.TLSExtension) ([]utls.TLSExtension, error) {
	allExtensions := []utls.TLSExtension{&utls.UtlsGREASEExtension{}}
	for _, extension := range extensions {
		var extensionId uint16
		if n, err := strconv.ParseUint(extension, 10, 16); err != nil {
			return nil, errors.New("ja3Str extension error,utls not support: " + extension)
		} else {
			extensionId = uint16(n)
		}
		switch extensionId {
		case 10:
			allExtensions = append(allExtensions, curvesExtension)
		case 11:
			allExtensions = append(allExtensions, pointExtension)
		case 43:
			allExtensions = append(allExtensions, tlsExtension)
		default:
			ext, _ := createExtension(extensionId)
			if ext == nil {
				if IsGREASEUint16(extensionId) {
					allExtensions = append(allExtensions, &utls.UtlsGREASEExtension{})
				}
				allExtensions = append(allExtensions, &utls.GenericExtension{Id: extensionId})
			} else {
				if ext == nil {
					return nil, errors.New("ja3Str extension error,utls not support: " + extension)
				}
				if extensionId == 21 {
					allExtensions = append(allExtensions, &utls.UtlsGREASEExtension{})
				}
				allExtensions = append(allExtensions, ext)
			}
		}
	}
	return allExtensions, nil
}

func CreateSpecWithJA3Str(ja3Str string) (clientHelloSpec utls.ClientHelloSpec, err error) {
	tokens := strings.Split(ja3Str, ",")
	if len(tokens) != 5 {
		return clientHelloSpec, errors.New("ja3Str format error")
	}
	// ver, err := strconv.ParseUint(tokens[0], 10, 16)
	// if err != nil {
	// 	return clientHelloSpec, errors.New("ja3Str tlsVersion error")
	// }
	ciphers := strings.Split(tokens[1], "-")
	extensions := strings.Split(tokens[2], "-")
	curves := strings.Split(tokens[3], "-")
	pointFormats := strings.Split(tokens[4], "-")
	tlsMaxVersion, tlsMinVersion, tlsExtension, err := createTlsVersion(utls.VersionTLS13)
	if err != nil {
		return clientHelloSpec, err
	}
	clientHelloSpec.TLSVersMax = tlsMaxVersion
	clientHelloSpec.TLSVersMin = tlsMinVersion
	if clientHelloSpec.CipherSuites, err = createCiphers(ciphers); err != nil {
		return
	}
	curvesExtension, err := createCurves(curves)
	if err != nil {
		return clientHelloSpec, err
	}
	pointExtension, err := createPointFormats(pointFormats)
	if err != nil {
		return clientHelloSpec, err
	}
	clientHelloSpec.CompressionMethods = []byte{0}
	clientHelloSpec.GetSessionID = sha256.Sum256
	clientHelloSpec.Extensions, err = createExtensions(extensions, tlsExtension, curvesExtension, pointExtension)
	return
}
