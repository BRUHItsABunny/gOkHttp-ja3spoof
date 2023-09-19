package gokhttp_ja3spoof

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	device_utils "github.com/BRUHItsABunny/go-device-utils"
	oohttp "github.com/ooni/oohttp"
	utls "github.com/refraction-networking/utls"
	"math/rand"
	"net"
	"net/http"
	"sort"
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
			utls.VersionTLS11,
			utls.VersionTLS10,
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

func Ja3ToClientHelloSpec() (*utls.ClientHelloSpec, error) {
	return nil, nil
}
