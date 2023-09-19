package gokhttp_ja3spoof

import (
	"context"
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

	// spec, err := BrowserToClientHelloSpec(browser, DefaultExtensionMapV2)
	// require.NoError(t, err, "BrowserToClientHelloSpec: errored unexpectedly.")

	hClient, err := gokhttp.NewHTTPClient(
		// gokhttp_client.NewProxyOption("http://127.0.0.1:8888"),
		// gokhttp_client.NewProxyOption("http://201.91.82.155:3128"),
		NewJa3SpoofingOptionV2(nil, &utls.HelloChrome_Auto),
		NewProxyOption("http://127.0.0.1:8888"),
		// NewProxyOption("socks5://127.0.0.1:8889"),
		// NewProxyOption("http://201.91.82.155:3128"),
		// NewProxyOption("http://proxy:trWK3kn@192.154.251.136:8000"),
		// NewProxyOption("socks5://GmBNx0nh3FzAEN2T:mobile;us;;;@proxy.soax.com:9096"),
	)

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
