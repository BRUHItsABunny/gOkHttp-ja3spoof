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

func TestHTTP2FingerprintConsistency(t *testing.T) {
	type testCase struct {
		label                   string
		in                      *gokhttp_ja3spoof.HTTP2ParametersOption
		inPHeaderOrder          []string
		expectedFP              string
		expectedHeadersFlags    []string
		expectedHeadersPriority Priority
		expectedFrameCount      int
	}

	testCases := []testCase{
		{
			label: "chrome",
			in: &gokhttp_ja3spoof.HTTP2ParametersOption{
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
			expectedFP: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
			inPHeaderOrder: []string{
				":method",
				":authority",
				":scheme",
				":path",
			},
			expectedHeadersFlags: []string{
				"EndStream (0x1)",
				"EndHeaders (0x4)",
				"Priority (0x20)",
			},
			expectedHeadersPriority: Priority{
				Weight:    256,
				DependsOn: 0,
				Exclusive: 1,
			},
			expectedFrameCount: 3,
		},
		{
			label: "firefox",
			in: &gokhttp_ja3spoof.HTTP2ParametersOption{
				HeaderTableSize:       65536,
				EnablePush:            0,
				MaxConcurrentStreams:  -1,
				InitialWindowSize:     131072,
				MaxFrameSize:          16384,
				MaxHeaderListSize:     -1,
				WindowUpdateIncrement: 12517377,
				HTTP2PriorityFrameSettings: &oohttp.HTTP2PriorityFrameSettings{
					PriorityFrames: []*oohttp.HTTP2Priority{nil, nil, nil},
					HeaderFrame: &oohttp.HTTP2Priority{
						StreamDep: 0,
						Exclusive: false,
						Weight:    41,
					},
				},
			},
			expectedFP: "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s",
			inPHeaderOrder: []string{
				":method",
				":path",
				":authority",
				":scheme",
			},
			expectedHeadersFlags: []string{
				"EndStream (0x1)",
				"EndHeaders (0x4)",
				"Priority (0x20)",
			},
			expectedHeadersPriority: Priority{
				Weight:    42,
				DependsOn: 0,
				Exclusive: 0,
			},
			expectedFrameCount: 3,
		},
	}

	for _, testCaseObj := range testCases {
		fmt.Println(fmt.Sprintf("Running test: %s", testCaseObj.label))
		hClient, err := gokhttp.NewHTTPClient(gokhttp_ja3spoof.NewJa3SpoofingOptionV2(nil, &utls.HelloChrome_131), testCaseObj.in)
		if err != nil {
			t.Error(err)
			continue
		}

		req, err := gokhttp_requests.MakeGETRequest(
			context.Background(),
			"https://tls.peet.ws/api/all",
			gokhttp_requests.NewHeaderOption(http.Header{
				oohttp.PHeaderOrderKey: testCaseObj.inPHeaderOrder,
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

		assert.Equal(t, testCaseObj.expectedFP, result.Http2.AkamaiFingerprint, "Akamai FP should be the same")
		assert.Equal(t, testCaseObj.expectedFrameCount, len(result.Http2.SentFrames), "The amount of frames emitted should equal")

		for _, frame := range result.Http2.SentFrames {
			if frame.FrameType == "HEADERS" {
				assert.ElementsMatch(t, testCaseObj.expectedHeadersFlags, frame.Flags, "HEADERS frame flags should equal")
				assert.Equal(t, testCaseObj.expectedHeadersPriority, frame.Priority, "HEADERS frame priority should equal")
			}
		}
	}
}
