package gokhttp_ja3spoof

import (
	"context"
	"crypto/tls"
	"fmt"
	gokhttp "github.com/BRUHItsABunny/gOkHttp"
	gokhttp_requests "github.com/BRUHItsABunny/gOkHttp/requests"
	gokhttp_responses "github.com/BRUHItsABunny/gOkHttp/responses"
	oohttp "github.com/ooni/oohttp"
	utls "github.com/refraction-networking/utls"
	"github.com/stretchr/testify/require"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestClientHelloId(t *testing.T) {
	hClient, err := gokhttp.NewHTTPClient(
		NewJa3SpoofingOptionV2(nil, &utls.HelloChrome_120),
	)
	require.NoError(t, err, "gokhttp.NewHTTPClient: errored unexpectedly.")
	if hClient.Transport.(*oohttp.StdlibTransport).Transport.TLSClientConfig == nil {
		hClient.Transport.(*oohttp.StdlibTransport).Transport.TLSClientConfig = &tls.Config{
			KeyLogWriter: os.Stdout,
		}
	}
	hClient.Transport.(*oohttp.StdlibTransport).Transport.TLSClientConfig.InsecureSkipVerify = true

	// HTTP 2 stuff
	hClient.Transport.(*oohttp.StdlibTransport).Transport.HasCustomInitialSettings = true
	hClient.Transport.(*oohttp.StdlibTransport).Transport.HTTP2SettingsFrameParameters = []int64{
		65536,   // HeaderTableSize
		0,       // EnablePush
		-1,      // MaxConcurrentStreams
		6291456, // InitialWindowSize
		-1,      // MaxFrameSize
		262144,  // MaxHeaderListSize
	}

	hClient.Transport.(*oohttp.StdlibTransport).Transport.HasCustomWindowUpdate = true
	hClient.Transport.(*oohttp.StdlibTransport).Transport.WindowUpdateIncrement = 15663105
	hClient.Transport.(*oohttp.StdlibTransport).Transport.HTTP2PriorityFrameSettings = &oohttp.HTTP2PriorityFrameSettings{
		HeaderFrame: &oohttp.HTTP2Priority{
			StreamDep: 0,
			Exclusive: true,
			Weight:    255,
		},
	}

	// doRequest(hClient, "https://tls.peet.ws/api/all", t)
	doRequest(hClient, "https://google.com/", t)
}

func TestClientHelloSpec(t *testing.T) {
	// Copied from https://github.com/refraction-networking/utls/blob/d2768e4eaac0c6f6e7b9e53ccec6ce8e907addd9/u_parrots.go#L662
	spec := utls.ClientHelloSpec{
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
		Extensions: utls.ShuffleChromeTLSExtensions([]utls.TLSExtension{
			&utls.UtlsGREASEExtension{},
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
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
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
				{Group: utls.X25519},
			}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{
				utls.PskModeDHE,
			}},
			&utls.SupportedVersionsExtension{Versions: []uint16{
				utls.GREASE_PLACEHOLDER,
				utls.VersionTLS13,
				utls.VersionTLS12,
			}},
			&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{
				utls.CertCompressionBrotli,
			}},
			&utls.ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
			utls.BoringGREASEECH(),
			&utls.UtlsGREASEExtension{},
		}),
	}

	hClient, err := gokhttp.NewHTTPClient(
		NewJa3SpoofingOptionV2(&spec, nil),
	)
	require.NoError(t, err, "gokhttp.NewHTTPClient: errored unexpectedly.")
	if hClient.Transport.(*oohttp.StdlibTransport).Transport.TLSClientConfig == nil {
		hClient.Transport.(*oohttp.StdlibTransport).Transport.TLSClientConfig = &tls.Config{
			KeyLogWriter: os.Stdout,
		}
	}
	hClient.Transport.(*oohttp.StdlibTransport).Transport.TLSClientConfig.InsecureSkipVerify = true

	// HTTP 2 stuff
	hClient.Transport.(*oohttp.StdlibTransport).Transport.HasCustomInitialSettings = true
	hClient.Transport.(*oohttp.StdlibTransport).Transport.HTTP2SettingsFrameParameters = []int64{
		65536,   // HeaderTableSize
		0,       // EnablePush
		-1,      // MaxConcurrentStreams
		6291456, // InitialWindowSize
		-1,      // MaxFrameSize
		262144,  // MaxHeaderListSize
	}

	hClient.Transport.(*oohttp.StdlibTransport).Transport.HasCustomWindowUpdate = true
	hClient.Transport.(*oohttp.StdlibTransport).Transport.WindowUpdateIncrement = 15663105
	hClient.Transport.(*oohttp.StdlibTransport).Transport.HTTP2PriorityFrameSettings = &oohttp.HTTP2PriorityFrameSettings{
		HeaderFrame: &oohttp.HTTP2Priority{
			StreamDep: 0,
			Exclusive: true,
			Weight:    255,
		},
	}

	// doRequest(hClient, "https://tls.peet.ws/api/all", t)
	doRequest(hClient, "https://google.com/", t)
}

func TestBaseline(t *testing.T) {
	hClient, err := gokhttp.NewHTTPClient()

	require.NoError(t, err, "NewHTTPClient: errored unexpectedly.")
	// doRequest(hClient, "https://api64.ipify.org?format=json", t)
	doRequest(hClient, "https://tls.peet.ws/api/all", t)
}

func doRequest(hClient *http.Client, urlStr string, t *testing.T) {
	fmt.Println(fmt.Sprintf("%s: %s", time.Now().String(), "start"))
	req, err := gokhttp_requests.MakeGETRequest(context.Background(), urlStr)
	require.NoError(t, err, "requests.MakeGETRequest: errored unexpectedly.")

	req.Header = http.Header{
		"sec-ch-ua":                 []string{"\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Brave\";v=\"120\""},
		"sec-ch-ua-mobile":          []string{"?0"},
		"sec-ch-ua-platform":        []string{"\"Windows\""},
		"upgrade-insecure-requests": []string{"1"},
		"user-agent":                []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
		"accept":                    []string{"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"},
		"sec-gpc":                   []string{"1"},
		"accept-language":           []string{"en-US,en;q=0.7"},
		"sec-fetch-site":            []string{"none"},
		"sec-fetch-mode":            []string{"navigate"},
		"sec-fetch-user":            []string{"?1"},
		"sec-fetch-dest":            []string{"document"},
		"cookie":                    []string{"cf_clearance=rqdbb6v1wCYbEMt6Et4U2m.XUcqh4n6FIV_ex.TId8k-1701720069-0-1-8dcbb9b1.a7e587a8.86d28ea2-160.2.1701720069"},
		oohttp.PHeaderOrderKey: {
			":method",
			":authority",
			":scheme",
			":path",
		},
		oohttp.HeaderOrderKey: {
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"sec-ch-ua-platform",
			"upgrade-insecure-requests",
			"user-agent",
			"accept",
			"sec-gpc",
			"accept-language",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-user",
			"sec-fetch-dest",
			"accept-encoding",
			"cookie",
		},
	}

	fmt.Println(fmt.Sprintf("%s: %s", time.Now().String(), "do"))
	resp, err := hClient.Do(req)
	if err != nil {
		panic(err)
	}
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

	// err = NewProxyOption("socks5://127.0.0.1:8889").ExecuteV2(hClient)
	// if err != nil {
	// 	panic(err)
	// }

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
