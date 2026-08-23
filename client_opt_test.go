package gokhttp_ja3spoof

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	gokhttp "github.com/BRUHItsABunny/gOkHttp"
	gokhttp_requests "github.com/BRUHItsABunny/gOkHttp/requests"
	gokhttp_responses "github.com/BRUHItsABunny/gOkHttp/responses"
	device_utils "github.com/BRUHItsABunny/go-device-utils"
	oohttp "github.com/BRUHItsABunny/oohttp"
	"github.com/stretchr/testify/require"
)

func TestParseSpec(t *testing.T) {
	rawData, err := os.ReadFile("peet.json")
	if err != nil {
		panic(err)
	}
	peetData := &device_utils.PeetResponse{}
	err = json.Unmarshal(rawData, peetData)
	if err != nil {
		panic(err)
	}
	browser := &device_utils.Browser{}
	err = browser.FromPEET(peetData)
	if err != nil {
		panic(err)
	}
	spec, err := CreateSpecWithTLSFingerprint(browser.TlsFingerprint)
	if err != nil {
		panic(err)
	}
	opt := NewJa3SpoofingOptionV2(&spec, nil)
	hClient, err := gokhttp.NewHTTPClient(
		opt,
		&HTTP2ParametersOption{
			HeaderTableSize:       65536,
			EnablePush:            0,
			MaxConcurrentStreams:  -1,
			InitialWindowSize:     6291456,
			MaxFrameSize:          -1,
			MaxHeaderListSize:     262144,
			WindowUpdateIncrement: 15663105,
			HTTP2PriorityFrameSettings: &oohttp.HTTP2PriorityFrameSettings{
				PriorityFrames: []*oohttp.HTTP2Priority{},
				HeaderFrame: &oohttp.HTTP2Priority{
					StreamDep: 0,
					Exclusive: true,
					Weight:    255,
				},
			},
		},
	)
	require.NoError(t, err, "gokhttp.NewHTTPClient: errored unexpectedly.")

	if hClient.Transport.(*oohttp.StdlibTransport).Transport.TLSClientConfig == nil {
		hClient.Transport.(*oohttp.StdlibTransport).Transport.TLSClientConfig = &tls.Config{}
	}
	hClient.Transport.(*oohttp.StdlibTransport).Transport.TLSClientConfig.InsecureSkipVerify = true
	// hClient.Transport.(*oohttp.StdlibTransport).Transport.TLSClientConfig.NextProtos = []string{
	// 	"http/1.1",
	// }

	// HTTP 2 stuff
	// hClient.Transport.(*oohttp.StdlibTransport).Transport.HasCustomInitialSettings = true
	// hClient.Transport.(*oohttp.StdlibTransport).Transport.HTTP2SettingsFrameParameters = []int64{
	// 	65536,   // HeaderTableSize
	// 	0,       // EnablePush
	// 	-1,      // MaxConcurrentStreams
	// 	6291456, // InitialWindowSize
	// 	-1,      // MaxFrameSize
	// 	262144,  // MaxHeaderListSize
	// }

	// hClient.Transport.(*oohttp.StdlibTransport).Transport.HasCustomWindowUpdate = true
	// hClient.Transport.(*oohttp.StdlibTransport).Transport.WindowUpdateIncrement = 15663105
	// hClient.Transport.(*oohttp.StdlibTransport).Transport.HTTP2PriorityFrameSettings = &oohttp.HTTP2PriorityFrameSettings{
	// 	PriorityFrames: []*oohttp.HTTP2Priority{},
	// 	HeaderFrame: &oohttp.HTTP2Priority{
	// 		StreamDep: 0,
	// 		Exclusive: true,
	// 		Weight:    255,
	// 	},
	// }
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
		"accept-encoding":           []string{"gzip, deflate, br, zstd"},
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
	fmt.Println("content-encoding: ", resp.Header.Get("Content-Encoding"))
}
