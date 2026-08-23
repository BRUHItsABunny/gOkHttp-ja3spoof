package gokhttp_ja3spoof

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BRUHItsABunny/gOkHttp-ja3spoof/compat/tls_compat"

	device_utils "github.com/BRUHItsABunny/go-device-utils"
	oohttp "github.com/BRUHItsABunny/oohttp"
	utls "github.com/refraction-networking/utls"
	"github.com/refraction-networking/utls/dicttls"
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
	TLSConfig                *tls.Config
	ClientHelloSpec          *utls.ClientHelloSpec
	Browser                  *device_utils.Browser
	ClientHelloID            *utls.ClientHelloID
	ExtensionMap             func() map[int32]utls.TLSExtension
	IsHTTP1                  bool
	ECHConfig                *utls.GREASEEncryptedClientHelloExtension
	TrackResponseHeaderOrder bool
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
		// ALPS moved to codepoint 17613 in Chrome 124+, see chromestatus.com/feature/5149147365900288
		17613: &utls.ApplicationSettingsExtensionNew{
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
	uConfig := tls_compat.STDConfigToConfig(config)

	uTLSConn := utls.UClient(conn, uConfig, utls.HelloCustom)
	if *o.ClientHelloID != utls.HelloCustom {
		spec, err := utls.UTLSIdToSpec(*o.ClientHelloID)
		if err != nil {
			panic(fmt.Errorf("Failed to convert client hello spec to spec: %w", err))
		}
		o.ClientHelloSpec = &spec
	}

	if o.IsHTTP1 {
		uConfig.NextProtos = []string{
			"http/1.1",
		}
	}

	for i, ext := range o.ClientHelloSpec.Extensions {
		switch typedExt := ext.(type) {
		case *utls.ALPNExtension:
			if o.IsHTTP1 {
				typedExt.AlpnProtocols = []string{"http/1.1"}
			}
			break
		case *utls.ApplicationSettingsExtension:
			if o.IsHTTP1 {
				// typedExt.SupportedProtocols = []string{"http/1.1"}
			}
			break
		case *utls.GREASEEncryptedClientHelloExtension:
			// UTLS doesn't like re-using specs, so just always do a deepclone of values we care about
			if rECH := o.ECHConfig; rECH != nil {
				ech := &utls.GREASEEncryptedClientHelloExtension{}
				if rECH.CandidateCipherSuites != nil {
					for _, suite := range rECH.CandidateCipherSuites {
						ech.CandidateCipherSuites = append(ech.CandidateCipherSuites, utls.HPKESymmetricCipherSuite{
							KdfId:  suite.KdfId,
							AeadId: suite.AeadId,
						})
					}
				}
				if rECH.CandidateConfigIds != nil {
					ech.CandidateConfigIds = append([]uint8{}, rECH.CandidateConfigIds...)
				}
				if rECH.EncapsulatedKey != nil {
					ech.EncapsulatedKey = append([]byte{}, rECH.EncapsulatedKey...)
				}
				if rECH.CandidatePayloadLens != nil {
					ech.CandidatePayloadLens = append([]uint16{}, rECH.CandidatePayloadLens...)
				}
				o.ClientHelloSpec.Extensions[i] = ech
			}
			break
		}
	}

	if o.ClientHelloSpec != nil {
		// TODO: We NEED deepcopy here.
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
			ForceAttemptHTTP2:        true,
			MaxIdleConns:             100,
			IdleConnTimeout:          90 * time.Second,
			TLSHandshakeTimeout:      10 * time.Second,
			ExpectContinueTimeout:    1 * time.Second,
			TLSClientFactory:         o.factoryFunc,
			TLSClientConfig:          o.TLSConfig,
			TrackResponseHeaderOrder: o.TrackResponseHeaderOrder,
		},
	}

	return nil
}

func (o *Ja3SpoofingOptionV2) ExecuteV2(client *oohttp.Client) error {
	client.Transport = &oohttp.Transport{
		// DialContext:           DefaultNetDialer.DialContext,
		// DialTLSContext:        tlsDialer,
		ForceAttemptHTTP2:        true,
		MaxIdleConns:             100,
		IdleConnTimeout:          90 * time.Second,
		TLSHandshakeTimeout:      10 * time.Second,
		ExpectContinueTimeout:    1 * time.Second,
		TLSClientFactory:         o.factoryFunc,
		TrackResponseHeaderOrder: o.TrackResponseHeaderOrder,
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
	extensionsRaw := make([]device_utils.Browser_TLSFingerprint_Extension, len(browser.TlsFingerprint.Extensions))
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
		extV.Curves = []utls.CurveID{
			utls.CurveID(utls.GREASE_PLACEHOLDER),
			utls.X25519,
			utls.CurveP256,
			utls.CurveP384,
		}

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
		extV.SupportedPoints = make([]uint8, 1, 1)
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
			extV.SupportedSignatureAlgorithms = []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.PSSWithSHA256,
				utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.PSSWithSHA384,
				utls.PKCS1WithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA512,
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
			extV.SupportedProtocols = []string{"h2"}
		}
		return extV, true
	case 17613:
		if option.ext != nil {
			extV := *(option.ext.(*utls.ApplicationSettingsExtensionNew))
			return &extV, true
		}
		extV := new(utls.ApplicationSettingsExtensionNew)
		if option.data != nil {
			extV.Write(option.data)
		} else {
			extV.SupportedProtocols = []string{"h2"}
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
	case 65037:
		// https://github.com/Noooste/azuretls-client/blob/3012ac665ef7984f06feb375daa12e00be044567/ja3.go#L419C3-L436C6
		if option.ext != nil {
			src := option.ext.(*utls.GREASEEncryptedClientHelloExtension)
			// Never copy the struct itself: it embeds a sync.Once and utls requires
			// fresh randomness (config_id, payload) per ClientHello.
			extV := &utls.GREASEEncryptedClientHelloExtension{
				CandidateCipherSuites: append([]utls.HPKESymmetricCipherSuite(nil), src.CandidateCipherSuites...),
				CandidateConfigIds:    append([]uint8(nil), src.CandidateConfigIds...),
				EncapsulatedKey:       append([]byte(nil), src.EncapsulatedKey...),
				CandidatePayloadLens:  append([]uint16(nil), src.CandidatePayloadLens...),
			}
			return extV, true
		}
		extV := &utls.GREASEEncryptedClientHelloExtension{
			CandidateCipherSuites: []utls.HPKESymmetricCipherSuite{
				{
					KdfId:  dicttls.HKDF_SHA256,
					AeadId: dicttls.AEAD_AES_128_GCM,
				},
				{
					KdfId:  dicttls.HKDF_SHA256,
					AeadId: dicttls.AEAD_AES_256_GCM,
				},
				{
					KdfId:  dicttls.HKDF_SHA256,
					AeadId: dicttls.AEAD_CHACHA20_POLY1305,
				},
			},
			CandidatePayloadLens: []uint16{128, 160},
		}
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
					// allExtensions = append(allExtensions, &utls.UtlsGREASEExtension{})
				}
				allExtensions = append(allExtensions, &utls.GenericExtension{Id: extensionId})
			} else {
				if ext == nil {
					return nil, errors.New("ja3Str extension error,utls not support: " + extension)
				}
				if extensionId == 21 {
					// allExtensions = append(allExtensions, &utls.UtlsGREASEExtension{})
				}
				allExtensions = append(allExtensions, ext)
			}
		}
	}
	return append(allExtensions, &utls.UtlsGREASEExtension{}), nil
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

// CreateSpecWithTLSFingerprint builds a ClientHelloSpec from a parsed browser TLS
// fingerprint, using DefaultTLSGREASEConfig. Unlike BrowserToClientHelloSpec it also honours
// fingerprint.ExtensionData, so the contents of supported_versions, key_share, ALPN, ECH and
// friends come from the fingerprint rather than the defaults in DefaultExtensionMapV2.
//
// FromPEET drops every GREASE value it sees, so a fingerprint on its own cannot say where the
// browser put them. Use ExtractGREASEFromPEET with CreateSpecWithTLSFingerprintAndGREASE to
// keep the real positions.
func CreateSpecWithTLSFingerprint(fingerprint *device_utils.Browser_TLSFingerprint) (clientHelloSpec utls.ClientHelloSpec, err error) {
	return CreateSpecWithTLSFingerprintAndGREASE(fingerprint, DefaultTLSGREASEConfig())
}

// CreateSpecWithTLSFingerprintAndGREASE is CreateSpecWithTLSFingerprint with explicit control
// over where GREASE values are placed. A nil grease means no GREASE at all.
func CreateSpecWithTLSFingerprintAndGREASE(fingerprint *device_utils.Browser_TLSFingerprint, grease *TLSGREASEConfig) (clientHelloSpec utls.ClientHelloSpec, err error) {
	if fingerprint == nil {
		return clientHelloSpec, errors.New("fingerprint is nil")
	}
	if len(fingerprint.CipherSuites) == 0 {
		return clientHelloSpec, errors.New("fingerprint has no cipher suites")
	}
	if grease == nil {
		grease = &TLSGREASEConfig{}
	}

	cipherSuites := make([]uint16, 0, len(fingerprint.CipherSuites)+1)
	if grease.CipherSuites {
		cipherSuites = append(cipherSuites, utls.GREASE_PLACEHOLDER)
	}
	for _, suite := range fingerprint.CipherSuites {
		cipherSuites = append(cipherSuites, uint16(suite))
	}

	extensionMap := DefaultExtensionMapV2()

	curves := make([]utls.CurveID, 0, len(fingerprint.EllipticCurves)+1)
	if grease.SupportedGroups {
		curves = append(curves, utls.CurveID(utls.GREASE_PLACEHOLDER))
	}
	for _, curve := range fingerprint.EllipticCurves {
		curves = append(curves, utls.CurveID(curve))
	}
	extensionMap[10] = &utls.SupportedCurvesExtension{Curves: curves}

	pointFmts := make([]byte, len(fingerprint.EllipticCurvePointFormats))
	for i, pointFmt := range fingerprint.EllipticCurvePointFormats {
		pointFmts[i] = byte(pointFmt)
	}
	extensionMap[11] = &utls.SupportedPointsExtension{SupportedPoints: pointFmts}

	applyFingerprintExtensionData(extensionMap, fingerprint.ExtensionData, grease)

	extensions, err := fingerprintExtensions(fingerprint.Extensions, extensionMap, grease)
	if err != nil {
		return clientHelloSpec, err
	}

	clientHelloSpec.TLSVersMax, clientHelloSpec.TLSVersMin = fingerprintVersionRange(fingerprint)
	clientHelloSpec.CipherSuites = cipherSuites
	clientHelloSpec.CompressionMethods = []byte{0}
	clientHelloSpec.GetSessionID = sha256.Sum256
	clientHelloSpec.Extensions = extensions
	return clientHelloSpec, nil
}

// fingerprintVersionRange derives the version window from the supported_versions extension
// data, falling back to the record version the fingerprint was observed with.
func fingerprintVersionRange(fingerprint *device_utils.Browser_TLSFingerprint) (tlsVersMax, tlsVersMin uint16) {
	for _, data := range fingerprint.ExtensionData {
		supported := data.GetSupportedVersions()
		if supported == nil {
			continue
		}
		for _, version := range supported.GetVersions() {
			ver := uint16(version)
			if ver == 0 {
				continue
			}
			if tlsVersMax == 0 || ver > tlsVersMax {
				tlsVersMax = ver
			}
			if tlsVersMin == 0 || ver < tlsVersMin {
				tlsVersMin = ver
			}
		}
	}
	if tlsVersMax == 0 {
		ver := uint16(fingerprint.GetVersion())
		tlsVersMax, tlsVersMin = ver, ver
	}
	return
}

// fingerprintExtensions resolves the extension list against extensionMap, keeping the
// observed order. Padding (21) and pre_shared_key (41) have to trail the rest, same as in
// BrowserToClientHelloSpec, and the GREASE extensions bracket the whole list.
func fingerprintExtensions(raw []device_utils.Browser_TLSFingerprint_Extension, extensionMap map[int32]utls.TLSExtension, grease *TLSGREASEConfig) ([]utls.TLSExtension, error) {
	type trailingExtension struct {
		id  int
		ext utls.TLSExtension
	}

	extensions := make([]utls.TLSExtension, 0, len(raw)+2)
	if grease.LeadingExtension {
		extensions = append(extensions, &utls.UtlsGREASEExtension{})
	}
	trailing := make([]trailingExtension, 0, 2)
	for _, e := range raw {
		ext, ok := extensionMap[int32(e)]
		if !ok {
			// Not every extension has a default, createExtension covers the rest.
			if ext, ok = createExtension(uint16(e)); !ok {
				return nil, fmt.Errorf("extension not supported: %s", e)
			}
		}
		if e == 21 || e == 41 {
			trailing = append(trailing, trailingExtension{id: int(e), ext: ext})
			continue
		}
		extensions = append(extensions, ext)
	}
	sort.Slice(trailing, func(i, j int) bool { return trailing[i].id < trailing[j].id })
	for _, t := range trailing {
		extensions = append(extensions, t.ext)
	}
	if grease.TrailingExtension {
		extensions = append(extensions, &utls.UtlsGREASEExtension{})
	}
	return extensions, nil
}

// applyFingerprintExtensionData overrides the defaults in extensionMap with the
// per-extension contents captured in the fingerprint.
func applyFingerprintExtensionData(extensionMap map[int32]utls.TLSExtension, extensionData []*device_utils.Browser_TLSFingerprint_ExtensionData, grease *TLSGREASEConfig) {
	for _, data := range extensionData {
		switch data.GetExtensionId() {
		case 13:
			if d := data.GetSignatureAlgorithms(); d != nil {
				schemes := make([]utls.SignatureScheme, 0, len(d.GetSupportedSignatureAlgorithms()))
				for _, scheme := range d.GetSupportedSignatureAlgorithms() {
					schemes = append(schemes, utls.SignatureScheme(scheme))
				}
				extensionMap[13] = &utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: schemes}
			}
		case 16:
			if d := data.GetApplicationLayerProtocolNegotiation(); d != nil {
				extensionMap[16] = &utls.ALPNExtension{AlpnProtocols: d.GetProtocols()}
			}
		case 27:
			if d := data.GetCompressCertificate(); d != nil {
				algos := make([]utls.CertCompressionAlgo, 0, len(d.GetAlgorithms()))
				for _, algo := range d.GetAlgorithms() {
					algos = append(algos, utls.CertCompressionAlgo(algo))
				}
				extensionMap[27] = &utls.UtlsCompressCertExtension{Algorithms: algos}
			}
		case 28:
			if d := data.GetRecordSizeLimit(); d != nil {
				extensionMap[28] = &utls.FakeRecordSizeLimitExtension{Limit: uint16(d.GetLimit())}
			}
		case 43:
			if d := data.GetSupportedVersions(); d != nil {
				versions := make([]uint16, 0, len(d.GetVersions())+1)
				if grease.SupportedVersions {
					versions = append(versions, utls.GREASE_PLACEHOLDER)
				}
				for _, version := range d.GetVersions() {
					versions = append(versions, uint16(version))
				}
				extensionMap[43] = &utls.SupportedVersionsExtension{Versions: versions}
			}
		case 45:
			if d := data.GetPskKeyExchangeModes(); d != nil {
				modes := make([]uint8, 0, len(d.GetModes()))
				for _, mode := range d.GetModes() {
					modes = append(modes, uint8(mode))
				}
				extensionMap[45] = &utls.PSKKeyExchangeModesExtension{Modes: modes}
			}
		case 51:
			if d := data.GetKeyShareExtension(); d != nil {
				shares := make([]utls.KeyShare, 0, len(d.GetKeyShares())+1)
				if grease.KeyShare {
					shares = append(shares, utls.KeyShare{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}})
				}
				for _, share := range d.GetKeyShares() {
					shares = append(shares, utls.KeyShare{Group: utls.CurveID(share.GetGroup()), Data: share.GetData()})
				}
				extensionMap[51] = &utls.KeyShareExtension{KeyShares: shares}
			}
		case 17513:
			if d := data.GetExtensionApplicationsSettings(); d != nil {
				extensionMap[17513] = &utls.ApplicationSettingsExtension{SupportedProtocols: d.GetProtocols()}
			}
		case 17613:
			if d := data.GetExtensionApplicationsSettings(); d != nil {
				extensionMap[17613] = &utls.ApplicationSettingsExtensionNew{SupportedProtocols: d.GetProtocols()}
			}
		case 65037:
			if d := data.GetExtensionEncryptedClientHello(); d != nil {
				suites := make([]utls.HPKESymmetricCipherSuite, 0, len(d.GetCandidateCipherSuites()))
				for _, suite := range d.GetCandidateCipherSuites() {
					suites = append(suites, utls.HPKESymmetricCipherSuite{
						KdfId:  utls.HPKE_KDF_ID(suite.GetKdfId()),
						AeadId: utls.HPKE_AEAD_ID(suite.GetAeadId()),
					})
				}
				payloadLens := make([]uint16, 0, len(d.GetCandidatePayloadLens()))
				for _, payloadLen := range d.GetCandidatePayloadLens() {
					payloadLens = append(payloadLens, uint16(payloadLen))
				}
				extensionMap[65037] = &utls.GREASEEncryptedClientHelloExtension{
					CandidateCipherSuites: suites,
					CandidatePayloadLens:  payloadLens,
				}
			}
		case 65281:
			if d := data.GetExtensionRenegotiationInfo(); d != nil {
				extensionMap[65281] = &utls.RenegotiationInfoExtension{
					Renegotiation: utls.RenegotiationSupport(d.GetRenegotiationSupport()),
				}
			}
		}
	}
}
