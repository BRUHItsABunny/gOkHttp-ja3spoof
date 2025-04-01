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
	"testing"
)

func TestTLSFingerprintConsistency(t *testing.T) {
	type testCase struct {
		label    string
		in       *gokhttp_ja3spoof.Ja3SpoofingOptionV2
		expected string
	}

	testCases := []testCase{
		{
			label:    "latest chrome",
			in:       gokhttp_ja3spoof.NewJa3SpoofingOptionV2(nil, &utls.HelloChrome_133),
			expected: "GREASE-772-771|2-1.1|GREASE-4588-29-23-24|1027-2052-1025-1283-2053-1281-2054-1537|1|2|GREASE-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53|0-10-11-13-16-17613-18-23-27-35-43-45-5-51-65037-65281-GREASE-GREASE",
		},
		{
			label:    "chrome 131+",
			in:       gokhttp_ja3spoof.NewJa3SpoofingOptionV2(nil, &utls.HelloChrome_131),
			expected: "GREASE-772-771|2-1.1|GREASE-4588-29-23-24|1027-2052-1025-1283-2053-1281-2054-1537|1|2|GREASE-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53|0-10-11-13-16-17513-18-23-27-35-43-45-5-51-65037-65281-GREASE-GREASE",
		},
		{
			label:    "chrome 120+",
			in:       gokhttp_ja3spoof.NewJa3SpoofingOptionV2(nil, &utls.HelloChrome_120_PQ),
			expected: "GREASE-772-771|2-1.1|GREASE-25497-29-23-24|1027-2052-1025-1283-2053-1281-2054-1537|1|2|GREASE-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53|0-10-11-13-16-17513-18-23-27-35-43-45-5-51-65037-65281-GREASE-GREASE",
		},
		{
			label:    "android",
			in:       gokhttp_ja3spoof.NewJa3SpoofingOptionV2(nil, &utls.HelloAndroid_11_OkHttp),
			expected: "||29-23-24|1027-2052-1025-1283-2053-1281-2054-1537-513|0||49195-49196-52393-49199-49200-52392-49171-49172-156-157-47-53|0-10-11-13-23-5-65281",
		},
		{
			label:    "ios",
			in:       gokhttp_ja3spoof.NewJa3SpoofingOptionV2(nil, &utls.HelloIOS_14),
			expected: "GREASE-772-771-770-769|2-1.1|GREASE-29-23-24-25|1027-2052-1025-1283-515-2053-2053-1281-2054-1537-513|1||GREASE-4865-4866-4867-49196-49195-52393-49200-49199-52392-49188-49187-49162-49161-49192-49191-49172-49171-157-156-61-60-53-47-49160-49170-10|0-10-11-13-16-18-21-23-43-45-5-51-65281-GREASE-GREASE",
		},
	}

	for _, testCaseObj := range testCases {
		fmt.Println(fmt.Sprintf("Running test: %s", testCaseObj.label))
		hClient, err := gokhttp.NewHTTPClient(testCaseObj.in)
		if err != nil {
			t.Error(err)
			continue
		}

		req, err := gokhttp_requests.MakeGETRequest(
			context.Background(),
			"https://tls.peet.ws/api/all",
			gokhttp_requests.NewHeaderOption(http.Header{
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
			}),
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

		assert.Equal(t, testCaseObj.expected, result.TLS.Peetprint, "PEET print should equal")
	}
}
