package tests

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	gokhttp "github.com/BRUHItsABunny/gOkHttp"
	gokhttp_ja3spoof "github.com/BRUHItsABunny/gOkHttp-ja3spoof"
	gokhttp_client "github.com/BRUHItsABunny/gOkHttp/client"
	gokhttp_requests "github.com/BRUHItsABunny/gOkHttp/requests"
	gokhttp_responses "github.com/BRUHItsABunny/gOkHttp/responses"
	utls "github.com/refraction-networking/utls"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const proxyTestBody = "hello through the tunnel"

// connectProxy is a minimal HTTP CONNECT proxy that records every host it tunnels to,
// so a test can prove traffic actually traversed the proxy instead of going direct.
type connectProxy struct {
	ln net.Listener

	mu      sync.Mutex
	targets []string
}

func startConnectProxy(t *testing.T) *connectProxy {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "net.Listen: errored unexpectedly.")

	p := &connectProxy{ln: ln}
	go p.serve()
	t.Cleanup(func() { _ = ln.Close() })

	return p
}

// URL is what you hand to a ProxyOption.
func (p *connectProxy) URL() string {
	return "http://" + p.ln.Addr().String()
}

// Targets returns the hosts this proxy was asked to CONNECT to.
func (p *connectProxy) Targets() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string{}, p.targets...)
}

func (p *connectProxy) serve() {
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.handle(conn)
	}
}

func (p *connectProxy) handle(clientConn net.Conn) {
	defer func() { _ = clientConn.Close() }()

	// bufio may over-read past the CONNECT line, so the tunnel has to copy from the reader.
	br := bufio.NewReader(clientConn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method != http.MethodConnect {
		_, _ = clientConn.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
		return
	}

	upstream, err := net.Dial("tcp", req.Host)
	if err != nil {
		_, _ = clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer func() { _ = upstream.Close() }()

	p.mu.Lock()
	p.targets = append(p.targets, req.Host)
	p.mu.Unlock()

	if _, err = clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		return
	}

	go func() {
		defer func() { _ = upstream.Close() }()
		_, _ = io.Copy(upstream, br)
	}()
	_, _ = io.Copy(clientConn, upstream)
}

// startTLSBackend serves proxyTestBody over HTTPS with a self-signed cert.
func startTLSBackend(t *testing.T) *httptest.Server {
	t.Helper()

	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(proxyTestBody))
	}))
	t.Cleanup(backend.Close)

	return backend
}

func newProxyTestSpoofOption() *gokhttp_ja3spoof.Ja3SpoofingOptionV2 {
	opt := gokhttp_ja3spoof.NewJa3SpoofingOptionV2(nil, &utls.HelloChrome_131)
	// The backend is self-signed.
	opt.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	return opt
}

func doProxyTestRequest(t *testing.T, hClient *http.Client, urlStr string) {
	t.Helper()

	req, err := gokhttp_requests.MakeGETRequest(context.Background(), urlStr)
	require.NoError(t, err, "requests.MakeGETRequest: errored unexpectedly.")

	resp, err := hClient.Do(req)
	require.NoError(t, err, "hClient.Do: errored unexpectedly.")

	body, err := gokhttp_responses.ResponseText(resp)
	require.NoError(t, err, "gokhttp_responses.ResponseText: errored unexpectedly.")
	require.Equal(t, proxyTestBody, body, "Body should equal")
}

// TestProxyRoutesTraffic proves that a configured proxy is actually used: the spoofed
// client's request has to show up as a CONNECT on the local proxy.
func TestProxyRoutesTraffic(t *testing.T) {
	testCases := []struct {
		label string
		opt   func(proxyURL string) gokhttp_client.Option
	}{
		{
			label: "gOkHttp-ja3spoof.ProxyOption",
			opt:   func(proxyURL string) gokhttp_client.Option { return gokhttp_ja3spoof.NewProxyOption(proxyURL) },
		},
		{
			label: "gOkHttp/client.ProxyOption",
			opt:   func(proxyURL string) gokhttp_client.Option { return gokhttp_client.NewProxyOption(proxyURL) },
		},
	}

	for _, testCaseObj := range testCases {
		t.Run(testCaseObj.label, func(t *testing.T) {
			backend := startTLSBackend(t)
			proxy := startConnectProxy(t)

			// The proxy option MUST come after the spoofing option: Ja3SpoofingOptionV2
			// replaces client.Transport wholesale, which would drop an earlier proxy.
			hClient, err := gokhttp.NewHTTPClient(newProxyTestSpoofOption(), testCaseObj.opt(proxy.URL()))
			require.NoError(t, err, "gokhttp.NewHTTPClient: errored unexpectedly.")

			doProxyTestRequest(t, hClient, backend.URL)

			assert.EqualValues(t, []string{backend.Listener.Addr().String()}, proxy.Targets(), "Proxy should have tunneled the request")
		})
	}
}

// TestProxyNotConfigured is the control: without a proxy option nothing reaches the proxy.
func TestProxyNotConfigured(t *testing.T) {
	backend := startTLSBackend(t)
	proxy := startConnectProxy(t)

	hClient, err := gokhttp.NewHTTPClient(newProxyTestSpoofOption())
	require.NoError(t, err, "gokhttp.NewHTTPClient: errored unexpectedly.")

	doProxyTestRequest(t, hClient, backend.URL)

	assert.Empty(t, proxy.Targets(), "Proxy should not have been used")
}

// TestProxyOptionOrderMatters pins down the footgun: a proxy option placed BEFORE the
// spoofing option is silently discarded, because Ja3SpoofingOptionV2.Execute overwrites
// client.Transport. The request then goes out direct instead of erroring.
func TestProxyOptionOrderMatters(t *testing.T) {
	backend := startTLSBackend(t)
	proxy := startConnectProxy(t)

	hClient, err := gokhttp.NewHTTPClient(gokhttp_ja3spoof.NewProxyOption(proxy.URL()), newProxyTestSpoofOption())
	require.NoError(t, err, "gokhttp.NewHTTPClient: errored unexpectedly.")

	doProxyTestRequest(t, hClient, backend.URL)

	assert.Empty(t, proxy.Targets(), "Proxy set before the spoofing option is expected to be dropped")
}
