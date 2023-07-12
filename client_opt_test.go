package gokhttp_ja3spoof

import (
	"context"
	"fmt"
	gokhttp "github.com/BRUHItsABunny/gOkHttp"
	gokhttp_requests "github.com/BRUHItsABunny/gOkHttp/requests"
	gokhttp_responses "github.com/BRUHItsABunny/gOkHttp/responses"
	device_utils "github.com/BRUHItsABunny/go-device-utils"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"
	"time"
)

func TestNewJa3SpoofingOptionV2(t *testing.T) {
	browser := device_utils.AvailableBrowsers["brave"]["1.50.114"]
	fmt.Println(spew.Sdump(browser))

	spec, err := BrowserToClientHelloSpec(browser, DefaultExtensionMapV2)
	require.NoError(t, err, "BrowserToClientHelloSpec: errored unexpectedly.")

	hClient, err := gokhttp.NewHTTPClient(
		// gokhttp_client.NewProxyOption("http://127.0.0.1:8888"),
		// gokhttp_client.NewProxyOption("http://201.91.82.155:3128"),
		NewJa3SpoofingOptionV2(spec, nil),
		// NewProxyOption("http://127.0.0.1:8888"),
		// NewProxyOption("http://201.91.82.155:3128"),
	)

	require.NoError(t, err, "NewHTTPClient: errored unexpectedly.")
	// doRequest(hClient, "https://api64.ipify.org?format=json", t)
	doRequest(hClient, "https://tls.peet.ws/api/clean", t)
}

func TestBaseline(t *testing.T) {
	hClient, err := gokhttp.NewHTTPClient(
	// gokhttp_client.NewProxyOption("http://127.0.0.1:8888"),
	// gokhttp_client.NewProxyOption("http://201.91.82.155:3128"),
	// NewJa3SpoofingOptionV2(browser, &tls.Config{InsecureSkipVerify: true}),
	// NewProxyOption("http://201.91.82.155:3128"),
	)

	require.NoError(t, err, "NewHTTPClient: errored unexpectedly.")
	doRequest(hClient, "https://api64.ipify.org?format=json", t)
	doRequest(hClient, "https://tls.peet.ws/api/clean", t)
}

func doRequest(hClient *http.Client, urlStr string, t *testing.T) {
	fmt.Println(fmt.Sprintf("%s: %s", time.Now().String(), "start"))
	req, err := gokhttp_requests.MakeGETRequest(context.Background(), urlStr)
	require.NoError(t, err, "requests.MakeGETRequest: errored unexpectedly.")

	fmt.Println(fmt.Sprintf("%s: %s", time.Now().String(), "do"))
	resp, err := hClient.Do(req)
	require.NoError(t, err, "hClient.Do: errored unexpectedly.")

	fmt.Println(fmt.Sprintf("%s: %s", time.Now().String(), "resp"))
	result, err := gokhttp_responses.ResponseText(resp)
	require.NoError(t, err, "gokhttp_responses.ResponseText: errored unexpectedly.")
	fmt.Println(fmt.Sprintf("%s\n\n%s", time.Now().String(), result))
}
