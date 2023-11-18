package gokhttp_ja3spoof

import (
	"context"
	"crypto/tls"
	"fmt"
	gokhttp "github.com/BRUHItsABunny/gOkHttp"
	gokhttp_requests "github.com/BRUHItsABunny/gOkHttp/requests"
	gokhttp_responses "github.com/BRUHItsABunny/gOkHttp/responses"
	device_utils "github.com/BRUHItsABunny/go-device-utils"
	"github.com/davecgh/go-spew/spew"
	oohttp "github.com/ooni/oohttp"
	utls "github.com/refraction-networking/utls"
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"
	"time"
)

func TestNewJa3SpoofingOptionV2(t *testing.T) {
	browser := device_utils.AvailableBrowsers["brave"]["1.50.114"]
	fmt.Println(spew.Sdump(browser))

	/*
		spec, err := BrowserToClientHelloSpec(browser, DefaultExtensionMapV2)
		fmt.Println(spew.Sdump(spec))
		fmt.Println(spew.Sdump(utls.ClientHelloSpec{
			CipherSuites: []uint16{
				utls.GREASE_PLACEHOLDER,
				utls.TLS_AES_128_GCM_SHA256,
				utls.TLS_AES_256_GCM_SHA384,
				utls.TLS_CHACHA20_POLY1305_SHA256,
				utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				utls.TLS_RSA_WITH_AES_128_CBC_SHA,
				utls.TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			Extensions: []utls.TLSExtension{
				&utls.UtlsGREASEExtension{},
				&utls.SNIExtension{},
				&utls.UtlsExtendedMasterSecretExtension{},
				&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
				&utls.SupportedCurvesExtension{[]utls.CurveID{
					utls.GREASE_PLACEHOLDER,
					utls.X25519,
					utls.CurveP256,
					utls.CurveP384,
				}},
				&utls.SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&utls.SessionTicketExtension{},
				&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&utls.StatusRequestExtension{},
				&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
					utls.ECDSAWithP256AndSHA256,
					utls.PSSWithSHA256,
					utls.PKCS1WithSHA256,
					utls.ECDSAWithP384AndSHA384,
					utls.PSSWithSHA384,
					utls.PKCS1WithSHA384,
					utls.PSSWithSHA512,
					utls.PKCS1WithSHA512,
				}},
				&utls.SCTExtension{},
				&utls.KeyShareExtension{[]utls.KeyShare{
					{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: utls.X25519},
				}},
				&utls.PSKKeyExchangeModesExtension{[]uint8{
					utls.PskModeDHE,
				}},
				&utls.SupportedVersionsExtension{[]uint16{
					utls.GREASE_PLACEHOLDER,
					utls.VersionTLS13,
					utls.VersionTLS12,
				}},
				&utls.UtlsCompressCertExtension{[]utls.CertCompressionAlgo{
					utls.CertCompressionBrotli,
				}},
				&utls.ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
				&utls.UtlsGREASEExtension{},
				&utls.FakePreSharedKeyExtension{},
			},
		}))
		require.NoError(t, err, "BrowserToClientHelloSpec: errored unexpectedly.")
	*/
	spec, err := CreateSpecWithJA3Str("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,45-65037-11-23-5-35-10-65281-16-43-27-0-51-13-18-17513,29-23-24,0")

	hClient, err := gokhttp.NewHTTPClient(
		// gokhttp_client.NewProxyOption("http://127.0.0.1:8888"),
		// gokhttp_client.NewProxyOption("http://201.91.82.155:3128"),
		NewJa3SpoofingOptionV2(&spec, nil),
		// NewJa3SpoofingOptionV2(nil, &utls.HelloChrome_Auto),
		// NewProxyOption("http://127.0.0.1:8888"),
		// NewProxyOption("socks5://127.0.0.1:8889"),
		// NewProxyOption("http://201.91.82.155:3128"),
		// NewProxyOption("http://proxy:trWK3kn@192.154.251.136:8000"),
		// NewProxyOption("socks5://GmBNx0nh3FzAEN2T:mobile;us;;;@proxy.soax.com:9096"),
	)
	if hClient.Transport.(*oohttp.StdlibTransport).Transport.TLSClientConfig == nil {
		hClient.Transport.(*oohttp.StdlibTransport).Transport.TLSClientConfig = &tls.Config{}
	}
	hClient.Transport.(*oohttp.StdlibTransport).Transport.TLSClientConfig.InsecureSkipVerify = true

	// tr2 := hClient.Transport.(*oohttp.StdlibTransport).Transport.(*oohttp.Transport)
	require.NoError(t, err, "NewHTTPClient: errored unexpectedly.")
	doRequest(hClient, "https://api64.ipify.org?format=json", t)
	doRequest(hClient, "https://tls.peet.ws/api/clean", t)
}

func TestBaseline(t *testing.T) {
	hClient, err := gokhttp.NewHTTPClient(
	// gokhttp_client.NewProxyOption("http://127.0.0.1:888"),
	// NewProxyOption("socks5://127.0.0.1:8889"),
	// gokhttp_client.NewProxyOption("http://201.91.82.155:3128"),
	// NewJa3SpoofingOptionV2(browser, &tls.Config{InsecureSkipVerify: true}),
	// NewProxyOption("http://proxy:trWK3kn@192.154.251.136:8000"),
	// NewProxyOption("socks5://GmBNx0nh3FzAEN2T:mobile;us;;;@proxy.soax.com:9096"),
	)

	require.NoError(t, err, "NewHTTPClient: errored unexpectedly.")
	doRequest(hClient, "https://api64.ipify.org?format=json", t)
	doRequest(hClient, "https://tls.peet.ws/api/clean", t)
}

func doRequest(hClient *http.Client, urlStr string, t *testing.T) {
	fmt.Println(fmt.Sprintf("%s: %s", time.Now().String(), "start"))
	req, err := gokhttp_requests.MakeGETRequest(context.Background(), urlStr)
	require.NoError(t, err, "requests.MakeGETRequest: errored unexpectedly.")

	req.Header = http.Header{
		oohttp.PHeaderOrderKey: {
			":method",
			":path",
			":authority",
			":scheme",
		},
	}

	fmt.Println(fmt.Sprintf("%s: %s", time.Now().String(), "do"))
	resp, err := hClient.Do(req)
	require.NoError(t, err, "hClient.Do: errored unexpectedly.")

	fmt.Println(fmt.Sprintf("%s: %s", time.Now().String(), "resp"))
	result, err := gokhttp_responses.ResponseText(resp)
	require.NoError(t, err, "gokhttp_responses.ResponseText: errored unexpectedly.")
	fmt.Println(fmt.Sprintf("%s\n\n%s", time.Now().String(), result))
}

func TestHeaderOrder(t *testing.T) {

	hClient := &oohttp.Client{}
	err := NewJa3SpoofingOptionV2(nil, &utls.HelloChrome_Auto).ExecuteV2(hClient)
	if err != nil {
		panic(err)
	}

	err = NewProxyOption("socks5://127.0.0.1:8889").ExecuteV2(hClient)
	if err != nil {
		panic(err)
	}

	req, err := oohttp.NewRequestWithContext(context.Background(), oohttp.MethodGet, "https://tls.peet.ws/api/clean", nil)
	if err != nil {
		panic(err)
	}
	req.Header = oohttp.Header{
		oohttp.PHeaderOrderKey: {
			":method",
			":path",
			":authority",
			":scheme",
		},
	}

	_, err = hClient.Do(req)
	if err != nil {
		panic(err)
	}

}
