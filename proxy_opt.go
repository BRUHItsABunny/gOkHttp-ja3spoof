package gokhttp_ja3spoof

import (
	"fmt"
	oohttp "github.com/ooni/oohttp"
	"net/http"
	"net/url"
)

// ProxyOption sets a proxy on your HTTP transport, supports http, https, socks4 and socks5.
//
// Deprecated: This option was needed to handle oohttp Transports in the past, reflection now handles both in one function. Use github.com/BRUHItsABunny/gOkHttp/client instead.
type ProxyOption struct {
	ProxyURL string
}

// NewProxyOption Creates an ProxyOption that sets a proxy on your HTTP transport, supports http, https, socks4 and socks5.
//
// Deprecated: This option was needed to handle oohttp Transports in the past, reflection now handles both in one function. Use github.com/BRUHItsABunny/gOkHttp/client instead.
func NewProxyOption(proxyURL string) *ProxyOption {
	return &ProxyOption{ProxyURL: proxyURL}
}

func (o *ProxyOption) Execute(client *http.Client) error {
	puo, err := url.Parse(o.ProxyURL)
	if err != nil {
		return fmt.Errorf("ProxyOption: url.Parse: %w", err)
	}

	switch puo.Scheme {
	case "socks":
		fallthrough
	case "socks4":
		fallthrough
	case "socks5":
		fallthrough
	default:
		_, ok := client.Transport.(*http.Transport)
		if ok {
			client.Transport.(*http.Transport).Proxy = http.ProxyURL(puo)
		}

		_, ok = client.Transport.(*oohttp.StdlibTransport)
		if ok {
			client.Transport.(*oohttp.StdlibTransport).Transport.Proxy = oohttp.ProxyURL(puo)
		}
		break
	}
	return nil
}

func (o *ProxyOption) ExecuteV2(client *oohttp.Client) error {
	puo, err := url.Parse(o.ProxyURL)
	if err != nil {
		return fmt.Errorf("ProxyOption: url.Parse: %w", err)
	}

	switch puo.Scheme {
	case "socks":
		fallthrough
	case "socks4":
		fallthrough
	case "socks5":
		fallthrough
	default:
		_, ok := client.Transport.(*oohttp.Transport)
		if ok {
			client.Transport.(*oohttp.Transport).Proxy = oohttp.ProxyURL(puo)
		}
		break
	}
	return nil
}
