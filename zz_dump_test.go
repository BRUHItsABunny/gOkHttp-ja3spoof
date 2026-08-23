package gokhttp_ja3spoof

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	gokhttp "github.com/BRUHItsABunny/gOkHttp"
	gokhttp_requests "github.com/BRUHItsABunny/gOkHttp/requests"
	gokhttp_responses "github.com/BRUHItsABunny/gOkHttp/responses"
	device_utils "github.com/BRUHItsABunny/go-device-utils"
	oohttp "github.com/BRUHItsABunny/oohttp"
	"github.com/stretchr/testify/require"
)

// TestZZGrease builds a spec with the GREASE layout extracted from peet.json and compares the
// fingerprint the server reports back against the one recorded in peet.json.
func TestZZGrease(t *testing.T) {
	rawData, err := os.ReadFile("peet.json")
	require.NoError(t, err)
	peetData := &device_utils.PeetResponse{}
	require.NoError(t, json.Unmarshal(rawData, peetData))

	browser := &device_utils.Browser{}
	require.NoError(t, browser.FromPEET(peetData))

	grease := ExtractGREASEFromPEET(peetData)
	fmt.Printf("extracted GREASE: %+v\n", grease)

	spec, err := CreateSpecWithTLSFingerprintAndGREASE(browser.TlsFingerprint, grease)
	require.NoError(t, err)

	hClient, err := gokhttp.NewHTTPClient(NewJa3SpoofingOptionV2(&spec, nil))
	require.NoError(t, err)
	if hClient.Transport.(*oohttp.StdlibTransport).Transport.TLSClientConfig == nil {
		hClient.Transport.(*oohttp.StdlibTransport).Transport.TLSClientConfig = &tls.Config{}
	}
	hClient.Transport.(*oohttp.StdlibTransport).Transport.TLSClientConfig.InsecureSkipVerify = true

	req, err := gokhttp_requests.MakeGETRequest(context.Background(), "https://tls.peet.ws/api/all")
	require.NoError(t, err)
	resp, err := hClient.Do(req)
	require.NoError(t, err)
	body, err := gokhttp_responses.ResponseText(resp)
	require.NoError(t, err)

	got := &device_utils.PeetResponse{}
	require.NoError(t, json.Unmarshal([]byte(body), got))

	require.Equal(t, peetData.TLS.Ja3, got.TLS.Ja3, "ja3 mismatch")
	require.Equal(t, peetData.TLS.Ja3Hash, got.TLS.Ja3Hash, "ja3_hash mismatch")
	require.Equal(t, peetData.TLS.Peetprint, got.TLS.Peetprint, "peetprint mismatch")
	require.Equal(t, peetData.TLS.PeetprintHash, got.TLS.PeetprintHash, "peetprint_hash mismatch")

	require.Equal(t, peetData.TLS.Ja4, got.TLS.Ja4, "ja4 mismatch")
}
