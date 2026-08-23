package gokhttp_ja3spoof

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	gokhttp "github.com/BRUHItsABunny/gOkHttp"
	"github.com/BRUHItsABunny/gOkHttp-ja3spoof/compat/tls_compat"
	gokhttp_client "github.com/BRUHItsABunny/gOkHttp/client"
	gokhttp_pcap "github.com/BRUHItsABunny/gOkHttp/pcap"
	gokhttp_requests "github.com/BRUHItsABunny/gOkHttp/requests"
	gokhttp_responses "github.com/BRUHItsABunny/gOkHttp/responses"
	device_utils "github.com/BRUHItsABunny/go-device-utils"
	oohttp "github.com/BRUHItsABunny/oohttp"
	"github.com/stretchr/testify/require"
)

// TestPCAPNGOptionOnOOHTTPStack checks that PCAPNGOption produces a decryptable capture when it
// sits on top of the oohttp/uTLS transport rather than a plain *http.Transport.
//
// Two things have to survive that swap for the capture to be usable:
//
//   - the dialer hook has to land on oohttp.Transport, so the bytes are captured on the raw
//     socket underneath the uTLS handshake (encrypted records, not plaintext);
//   - the KeyLogWriter the option installs on the transport tls.Config has to reach the
//     utls.Config our factory builds, otherwise the capture has no secrets to decrypt with.
//
// The structural assertions run everywhere. The decryption is verified with tshark when it is
// on PATH, since that is the only way to prove the two halves line up; set REQUIRE_TSHARK to
// make a missing tshark a failure rather than a silent skip (CI does).
func TestPCAPNGOptionOnOOHTTPStack(t *testing.T) {
	rawData, err := os.ReadFile("peet.json")
	require.NoError(t, err)
	peetData := &device_utils.PeetResponse{}
	require.NoError(t, json.Unmarshal(rawData, peetData))
	browser := &device_utils.Browser{}
	require.NoError(t, browser.FromPEET(peetData))

	spec, err := CreateSpecWithTLSFingerprintAndGREASE(browser.TlsFingerprint, ExtractGREASEFromPEET(peetData))
	require.NoError(t, err)

	capturePath := filepath.Join(t.TempDir(), "capture.pcapng")
	pcapOpt, err := gokhttp_client.NewPCAPNGOptionToFile(capturePath)
	require.NoError(t, err, "NewPCAPNGOptionToFile: errored unexpectedly.")

	// Order matters: the spoofing option replaces the transport, the capture option hooks the
	// transport that is left behind, so the capture has to be applied second.
	hClient, err := gokhttp.NewHTTPClient(NewJa3SpoofingOptionV2(&spec, nil), pcapOpt)
	require.NoError(t, err, "gokhttp.NewHTTPClient: errored unexpectedly.")

	transport, ok := hClient.Transport.(*oohttp.StdlibTransport)
	require.True(t, ok, "expected the oohttp transport to still be in place after the capture option")
	require.NotNil(t, transport.Transport.TLSClientConfig, "capture option should have allocated a TLS config")
	require.NotNil(t, transport.Transport.TLSClientConfig.KeyLogWriter, "capture option should have installed a KeyLogWriter")
	require.NotNil(t, transport.Transport.DialContext, "capture option should have taken over dialing")
	transport.Transport.TLSClientConfig.InsecureSkipVerify = true

	req, err := gokhttp_requests.MakeGETRequest(context.Background(), "https://tls.peet.ws/api/all")
	require.NoError(t, err)
	resp, err := hClient.Do(req)
	require.NoError(t, err, "hClient.Do: errored unexpectedly.")
	body, err := gokhttp_responses.ResponseText(resp)
	require.NoError(t, err)
	require.Contains(t, body, "\"ja3\"", "expected a peet response through the captured connection")

	// The request has to have gone out over the spoofed hello, not a fallback: a capture of the
	// wrong handshake would still decrypt and tell us nothing.
	got := &device_utils.PeetResponse{}
	require.NoError(t, json.Unmarshal([]byte(body), got))
	require.Equal(t, peetData.TLS.Ja3Hash, got.TLS.Ja3Hash, "capture changed the ClientHello")

	hClient.CloseIdleConnections()
	require.NoError(t, pcapOpt.Close(), "pcapOpt.Close: errored unexpectedly.")

	captured, err := os.ReadFile(capturePath)
	require.NoError(t, err)
	require.NotEmpty(t, captured, "capture file is empty")

	packets, secrets := countBlocks(t, captured)
	require.Greater(t, packets, 0, "capture contains no packet blocks")
	require.Greater(t, secrets, 0, "capture contains no decryption secrets blocks")

	// The secrets have to be the TLS 1.3 traffic secrets, a capture carrying only a client
	// random line would pass a naive "is there a DSB" check and still not decrypt.
	require.Contains(t, string(captured), "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
		"expected TLS 1.3 key material in the capture")

	// The capture has to sit under the TLS handshake: the SNI of the ClientHello is on the wire
	// in the clear, while anything from the encrypted response body is not. Checking both pins
	// the capture point down - only a socket-level capture satisfies both at once.
	require.Contains(t, string(captured), "tls.peet.ws",
		"ClientHello SNI missing, the capture did not record the handshake")
	require.NotContains(t, string(captured), "ja3_hash",
		"response body is in cleartext, the capture is above TLS instead of below it")

	assertDecryptsWithTshark(t, capturePath)
}

// countBlocks walks the pcapng block chain and counts enhanced packet blocks and decryption
// secrets blocks. Walking it also proves the block lengths are self-consistent, which is what a
// reader needs to parse the file at all.
func countBlocks(t *testing.T, capture []byte) (packets, secrets int) {
	t.Helper()

	const (
		blockTypeEPB = uint32(0x00000006)
		blockTypeDSB = uint32(0x0000000A)
	)

	for offset := 0; offset+12 <= len(capture); {
		blockType := binary.LittleEndian.Uint32(capture[offset:])
		blockLen := int(binary.LittleEndian.Uint32(capture[offset+4:]))
		require.GreaterOrEqual(t, blockLen, 12, "malformed block length at offset %d", offset)
		require.LessOrEqual(t, offset+blockLen, len(capture), "block at offset %d runs past EOF", offset)

		trailer := binary.LittleEndian.Uint32(capture[offset+blockLen-4:])
		require.Equal(t, uint32(blockLen), trailer, "block at offset %d has mismatched trailer", offset)

		switch blockType {
		case blockTypeEPB:
			packets++
		case blockTypeDSB:
			secrets++
		}
		offset += blockLen
	}
	return packets, secrets
}

// assertDecryptsWithTshark proves the captured records and the embedded secrets belong to each
// other, by asking tshark to dissect the TLS payload. Skipped when tshark is not installed.
func assertDecryptsWithTshark(t *testing.T, capturePath string) {
	t.Helper()

	tshark, err := exec.LookPath("tshark")
	if err != nil {
		// Skipping quietly is fine on a dev box, but in CI it would turn the only assertion
		// that actually proves decryption into a no-op and still report green.
		if os.Getenv("REQUIRE_TSHARK") != "" {
			t.Fatal("REQUIRE_TSHARK is set but tshark is not on PATH")
		}
		t.Log("tshark not on PATH, skipping the decryption check (set REQUIRE_TSHARK to enforce)")
		return
	}

	// -Y http2 only matches if the TLS records were decrypted using the DSB secrets.
	out, err := exec.Command(tshark, "-r", capturePath, "-Y", "http2", "-T", "fields",
		"-e", "http2.header.value").CombinedOutput()
	require.NoError(t, err, "tshark: %s", string(out))

	decoded := string(out)
	require.NotEmpty(t, strings.TrimSpace(decoded),
		"tshark decoded no HTTP/2 from the capture, the embedded secrets do not decrypt it")
	require.Contains(t, decoded, "tls.peet.ws",
		"expected the decrypted HTTP/2 headers to carry the request authority")
}

// TestPCAPNGOptionKeyLogReachesUTLSConfig is the narrow regression test for the wiring the
// capture depends on: a KeyLogWriter set on the stdlib config has to survive the conversion
// into the utls.Config the spoofing factory hands to uTLS.
func TestPCAPNGOptionKeyLogReachesUTLSConfig(t *testing.T) {
	var sink bytes.Buffer
	writer, err := gokhttp_pcap.NewWriter(&sink)
	require.NoError(t, err)
	t.Cleanup(func() { _ = writer.Close() })

	stdConfig := &tls.Config{KeyLogWriter: writer.KeyLogWriter()}
	uConfig := tls_compat.STDConfigToConfig(stdConfig)
	require.NotNil(t, uConfig.KeyLogWriter, "KeyLogWriter was dropped converting to utls.Config")
}
