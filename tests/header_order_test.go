package tests

import (
	"context"
	"fmt"
	gokhttp "github.com/BRUHItsABunny/gOkHttp"
	gokhttp_ja3spoof "github.com/BRUHItsABunny/gOkHttp-ja3spoof"
	gokhttp_requests "github.com/BRUHItsABunny/gOkHttp/requests"
	gokhttp_responses "github.com/BRUHItsABunny/gOkHttp/responses"
	oohttp "github.com/ooni/oohttp"
	utls "github.com/refraction-networking/utls"
	"github.com/stretchr/testify/assert"
	"net/http"
	"strings"
	"testing"
)

func TestHeaderFingerprintConsistency(t *testing.T) {
	type testCase struct {
		label     string
		in        *gokhttp_ja3spoof.Ja3SpoofingOptionV2
		inHeaders http.Header
		expected  []string
	}

	testCases := []testCase{
		{
			label: "chrome http2",
			in:    gokhttp_ja3spoof.NewJa3SpoofingOptionV2(nil, &utls.HelloChrome_131),
			inHeaders: http.Header{
				"sec-ch-ua":                 {"\"Brave\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\""},
				"sec-ch-ua-mobile":          {"?0"},
				"sec-ch-ua-platform":        {"\"Windows\""},
				"upgrade-insecure-requests": {"1"},
				"user-agent":                {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"},
				"accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"},
				"sec-gpc":                   {"1"},
				"accept-language":           {"en-GB,en;q=0.6"},
				"sec-fetch-site":            {"none"},
				"sec-fetch-mode":            {"navigate"},
				"sec-fetch-user":            {"?1"},
				"sec-fetch-dest":            {"document"},
				"accept-encoding":           {"gzip, deflate, br, zstd"},
				"priority":                  {"u=0, i"},
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
					"priority",
				},
			},
			expected: []string{
				":method: GET",
				":authority: tls.peet.ws",
				":scheme: https",
				":path: /api/all",
				"sec-ch-ua: \\\"Brave\\\";v=\\\"131\\\", \\\"Chromium\\\";v=\\\"131\\\", \\\"Not_A Brand\\\";v=\\\"24\\",
				"sec-ch-ua-mobile: ?0",
				"sec-ch-ua-platform: \\\"Windows\\",
				"upgrade-insecure-requests: 1",
				"user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
				"accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
				"sec-gpc: 1",
				"accept-language: en-GB,en;q=0.6",
				"sec-fetch-site: none",
				"sec-fetch-mode: navigate",
				"sec-fetch-user: ?1",
				"sec-fetch-dest: document",
				"accept-encoding: gzip, deflate, br, zstd",
				"priority: u=0, i",
			},
		},
		{
			label: "chrome http1",
			in:    gokhttp_ja3spoof.NewJa3SpoofingOptionV2(nil, &utls.HelloChrome_131),
			inHeaders: http.Header{
				"Sec-CH-UA":                 []string{"\"Brave\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\""},
				"Sec-CH-UA-Mobile":          []string{"?0"},
				"Sec-CH-UA-Platform":        []string{"\"Windows\""},
				"Upgrade-Insecure-Requests": []string{"1"},
				"User-Agent":                []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"},
				"Accept":                    []string{"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"},
				"Sec-GPC":                   []string{"1"},
				"Accept-Language":           []string{"en-GB,en;q=0.6"},
				"Sec-Fetch-Site":            []string{"none"},
				"Sec-Fetch-Mode":            []string{"navigate"},
				"Sec-Fetch-User":            []string{"?1"},
				"Sec-Fetch-Dest":            []string{"document"},
				"Accept-Encoding":           []string{"gzip, deflate, br, zstd"},
				"Priority":                  []string{"u=0, i"},
				oohttp.HeaderOrderKey: []string{
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
					"priority",
				},
			},
			expected: []string{
				"Sec-CH-UA: \"Brave\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
				"Sec-CH-UA-Mobile: ?0",
				"Sec-CH-UA-Platform: \"Windows\"",
				"Upgrade-Insecure-Requests: 1",
				"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
				"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
				"Sec-GPC: 1",
				"Accept-Language: en-GB,en;q=0.6",
				"Sec-Fetch-Site: none",
				"Sec-Fetch-Mode: navigate",
				"Sec-Fetch-User: ?1",
				"Sec-Fetch-Dest: document",
				"Accept-Encoding: gzip, deflate, br, zstd",
				"Priority: u=0, i",
				"Host: tls.peet.ws",
			},
		},
	}

	for _, testCaseObj := range testCases {
		fmt.Println(fmt.Sprintf("Running test: %s", testCaseObj.label))
		testCaseObj.in.IsHTTP1 = strings.Contains(testCaseObj.label, "http1")
		hClient, err := gokhttp.NewHTTPClient(testCaseObj.in)
		if err != nil {
			t.Error(err)
			continue
		}
		// TODO: This line is needed to pass HTTP 1 tests, but  that's really indicative of a bug because HTTP 2 tests don't need it
		hClient.Transport.(*oohttp.StdlibTransport).Transport.DisableCompression = true

		req, err := gokhttp_requests.MakeGETRequest(
			context.Background(),
			"https://tls.peet.ws/api/all",
			gokhttp_requests.NewHeaderOption(testCaseObj.inHeaders),
		)
		if err != nil {
			t.Error(err)
			continue
		}

		resp, err := hClient.Do(req)
		if err != nil {
			t.Error(err)
			continue
		}

		result := &PeetResponse{}
		err = gokhttp_responses.ResponseJSON(resp, result)
		if err != nil {
			t.Error(err)
			continue
		}

		var got []string
		if result.Http1 != nil {
			got = result.Http1.Headers
		} else {
			for _, frame := range result.Http2.SentFrames {
				if len(frame.Headers) != 0 {
					got = frame.Headers
					break
				}
			}
		}
		assert.EqualValues(t, testCaseObj.expected, got, "Headers should equal")
	}
}
