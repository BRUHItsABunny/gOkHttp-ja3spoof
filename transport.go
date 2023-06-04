package gokhttp_ja3spoof

import (
	"context"
	"crypto/sha256"
	"fmt"
	device_utils "github.com/BRUHItsABunny/go-device-utils"
	tls "github.com/refraction-networking/utls"
	"math/rand"
	"net"
	"net/http"
	"sort"
	"strings"
)

type Ja3SpoofingOption struct {
	TLSConfig    *tls.Config
	Browser      *device_utils.Browser
	ExtensionMap func() map[int32]tls.TLSExtension
}

func DefaultExtensionMap() map[int32]tls.TLSExtension {
	return map[int32]tls.TLSExtension{
		0: &tls.SNIExtension{},
		5: &tls.StatusRequestExtension{},
		13: &tls.SignatureAlgorithmsExtension{
			SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.ECDSAWithP521AndSHA512,
				tls.PSSWithSHA256,
				tls.PSSWithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA256,
				tls.PKCS1WithSHA384,
				tls.PKCS1WithSHA512,
				tls.ECDSAWithSHA1,
				tls.PKCS1WithSHA1,
			},
		},
		16: &tls.ALPNExtension{
			AlpnProtocols: []string{"h2", "http/1.1"},
		},
		17: &tls.GenericExtension{Id: 17},
		18: &tls.SCTExtension{},
		21: &tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
		22: &tls.GenericExtension{Id: 22},
		23: &tls.UtlsExtendedMasterSecretExtension{},
		27: &tls.UtlsCompressCertExtension{
			Algorithms: []tls.CertCompressionAlgo{tls.CertCompressionBrotli},
		},
		28: &tls.FakeRecordSizeLimitExtension{},
		35: &tls.SessionTicketExtension{},
		34: &tls.GenericExtension{Id: 34},
		41: &tls.GenericExtension{Id: 41},
		43: &tls.SupportedVersionsExtension{Versions: []uint16{
			tls.GREASE_PLACEHOLDER,
			tls.VersionTLS13,
			tls.VersionTLS12,
			tls.VersionTLS11,
			tls.VersionTLS10,
		}},
		44: &tls.CookieExtension{},
		45: &tls.PSKKeyExchangeModesExtension{Modes: []uint8{
			tls.PskModeDHE,
		}},
		49: &tls.GenericExtension{Id: 49},
		50: &tls.GenericExtension{Id: 50},
		51: &tls.KeyShareExtension{KeyShares: []tls.KeyShare{
			{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
			{Group: tls.X25519},
		}},
		13172: &tls.NPNExtension{},
		17513: &tls.ApplicationSettingsExtension{
			SupportedProtocols: []string{
				"h2",
			},
		},
		65281: &tls.RenegotiationInfoExtension{
			Renegotiation: tls.RenegotiateOnceAsClient,
		},
	}
}

func NewJa3SpoofingOption(browser *device_utils.Browser, tlsConfig *tls.Config) *Ja3SpoofingOption {
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	}

	return &Ja3SpoofingOption{Browser: browser, TLSConfig: tlsConfig, ExtensionMap: DefaultExtensionMap}
}

func (o *Ja3SpoofingOption) browserToSpec() (*tls.ClientHelloSpec, error) {
	cipherSuites := make([]uint16, len(o.Browser.TlsFingerprint.CipherSuites))
	for i, suite := range o.Browser.TlsFingerprint.CipherSuites {
		cipherSuites[i] = uint16(suite)
	}

	extensionMap := o.ExtensionMap()

	ellipticCurves := make([]tls.CurveID, len(o.Browser.TlsFingerprint.EllipticCurves))
	for i, curve := range o.Browser.TlsFingerprint.EllipticCurves {
		ellipticCurves[i] = tls.CurveID(curve)
	}
	extensionMap[10] = &tls.SupportedCurvesExtension{Curves: ellipticCurves}

	ellipticPointFmts := make([]byte, len(o.Browser.TlsFingerprint.EllipticCurvePointFormats))
	for i, pointFmt := range o.Browser.TlsFingerprint.EllipticCurvePointFormats {
		ellipticPointFmts[i] = byte(pointFmt)
	}
	extensionMap[11] = &tls.SupportedPointsExtension{SupportedPoints: ellipticPointFmts}

	var extensions []tls.TLSExtension

	// Don't just implement GREASE, tell them the GREASE, except for 21 and 41
	isChromium := strings.Contains(o.Browser.BrandHeader, "Chromium")
	extensionsRaw := make([]device_utils.Browser_TLSFingerprint_Extensions, len(o.Browser.TlsFingerprint.Extensions))
	copy(extensionsRaw, o.Browser.TlsFingerprint.Extensions)
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
			// return nil, raiseExtensionError(e)
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
			extensions = append(extensions, &tls.UtlsGREASEExtension{})
		}
		te, ok := extensionMap[int32(e)]
		if ok {
			extensions = append(extensions, te)
		}
	}

	tlsSpec := &tls.ClientHelloSpec{
		CipherSuites:       cipherSuites,
		CompressionMethods: []byte{0},
		Extensions:         extensions,
		GetSessionID:       sha256.Sum256,
	}

	return tlsSpec, nil
}

func (o *Ja3SpoofingOption) Execute(client *http.Client) error {
	dialTLSCtx := func(ctx context.Context, network, addr string) (net.Conn, error) {

		tlsSpec, err := o.browserToSpec()
		if err != nil {
			return nil, fmt.Errorf("Ja3SpoofingOption.Execute: dialTLSCtx: o.browserToSpec: %w", err)
		}

		dialConn, err := net.Dial(network, addr)
		if err != nil {
			return nil, fmt.Errorf("Ja3SpoofingOption.Execute: dialTLSCtx: net.Dial: %w", err)
		}

		o.TLSConfig.ServerName = strings.Split(addr, ":")[0]

		uTLSConn := tls.UClient(dialConn, o.TLSConfig, tls.HelloCustom)
		if err := uTLSConn.ApplyPreset(tlsSpec); err != nil {
			return nil, fmt.Errorf("Ja3SpoofingOption.Execute: dialTLSCtx: uTLSConn.ApplyPreset: %w", err)
		}
		if err := uTLSConn.Handshake(); err != nil {
			return nil, fmt.Errorf("Ja3SpoofingOption.Execute: dialTLSCtx: uTLSConn.Handshake: %w", err)
		}
		return uTLSConn, nil
	}

	client.Transport.(*http.Transport).DialTLSContext = dialTLSCtx
	return nil
}
