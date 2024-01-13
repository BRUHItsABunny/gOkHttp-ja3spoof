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

	// spec, err := CreateSpecWithJA3Str("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,13-43-23-11-17513-10-5-0-51-65281-16-18-65037-27-35-45,29-23-24,0")
	spec, err := CreateSpecWithJA3Str("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,51-45-17513-13-43-0-10-35-18-11-65281-23-5-65037-27-16-21,29-23-24,0")
	require.NoError(t, err, "CreateSpecWithJA3Str: errored unexpectedly.")
	fmt.Println(spew.Sdump(spec))
	hClient, err := gokhttp.NewHTTPClient(
		// gokhttp_client.NewProxyOption("http://127.0.0.1:8888"),
		// gokhttp_client.NewProxyOption("http://201.91.82.155:3128"),
		NewJa3SpoofingOptionV2(&spec, nil),
		// NewJa3SpoofingOptionV2(nil, &utls.HelloChrome_Auto),
		// NewProxyOption("http://127.0.0.1:8888"),
	)
	require.NoError(t, err, "gokhttp.NewHTTPClient: errored unexpectedly.")
	if hClient.Transport.(*oohttp.StdlibTransport).Transport.TLSClientConfig == nil {
		hClient.Transport.(*oohttp.StdlibTransport).Transport.TLSClientConfig = &tls.Config{}
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
		PriorityFrames: []*oohttp.HTTP2Priority{
			// nil,
			// nil, // 1
			// nil, // 2
			// { // 3
			// 	StreamDep: 0,
			// 	Exclusive: false,
			// 	Weight:    200,
			// },
			// nil, // 4
			// { // 5
			// 	StreamDep: 0,
			// 	Exclusive: false,
			// 	Weight:    100,
			// },
			// nil, // 6
			// { // 7
			// 	StreamDep: 0,
			// 	Exclusive: false,
			// 	Weight:    0,
			// },
			// nil, // 8
			// { // 9
			// 	StreamDep: 7,
			// 	Exclusive: false,
			// 	Weight:    200,
			// },
			// nil, // 10
			// { // 11
			// 	StreamDep: 3,
			// 	Exclusive: false,
			// 	Weight:    0,
			// },
			// nil, // 12
			// { // 13
			// 	StreamDep: 0,
			// 	Exclusive: false,
			// 	Weight:    240,
			// },
		},
		HeaderFrame: &oohttp.HTTP2Priority{
			StreamDep: 0,
			Exclusive: true,
			Weight:    255,
		},
	}

	// tr2 := hClient.Transport.(*oohttp.StdlibTransport).Transport.(*oohttp.Transport)
	// require.NoError(t, err, "NewHTTPClient: errored unexpectedly.")
	// doRequest(hClient, "https://api64.ipify.org?format=json", t)
	doRequest(hClient, "https://tls.peet.ws/api/all", t)
}

func TestBaseline(t *testing.T) {
	hClient, err := gokhttp.NewHTTPClient(
	// gokhttp_client.NewProxyOption("http://127.0.0.1:8888"),
	// NewProxyOption("socks5://127.0.0.1:8889"),
	// gokhttp_client.NewProxyOption("http://201.91.82.155:3128"),
	// NewJa3SpoofingOptionV2(browser, &tls.Config{InsecureSkipVerify: true}),
	// NewProxyOption("http://proxy:trWK3kn@192.154.251.136:8000"),
	// NewProxyOption("socks5://GmBNx0nh3FzAEN2T:mobile;us;;;@proxy.soax.com:9096"),
	)

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
