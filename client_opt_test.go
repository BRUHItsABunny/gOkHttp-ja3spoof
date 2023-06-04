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
	utls "github.com/refraction-networking/utls"
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"
)

func TestNewJa3SpoofingOption(t *testing.T) {
	browser := device_utils.AvailableBrowsers["brave"]["1.50.114"]
	fmt.Println(spew.Sdump(browser))

	hClient, err := gokhttp.NewHTTPClient(
		NewJa3SpoofingOption(browser, &utls.Config{InsecureSkipVerify: true}),
	)
	require.NoError(t, err, "NewHTTPClient: errored unexpectedly.")
	hClient.Transport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	req, err := gokhttp_requests.MakeGETRequest(context.Background(), "https://tls.peet.ws/api/clean")
	require.NoError(t, err, "requests.MakeGETRequest: errored unexpectedly.")

	resp, err := hClient.Do(req)
	require.NoError(t, err, "hClient.Do: errored unexpectedly.")

	result, err := gokhttp_responses.ResponseText(resp)
	require.NoError(t, err, "gokhttp_responses.ResponseText: errored unexpectedly.")

	fmt.Println(result)
}
