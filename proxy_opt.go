package gokhttp_ja3spoof

import (
	"fmt"
	oohttp "github.com/ooni/oohttp"
	"net/http"
	"net/url"
)

type ProxyOption struct {
	ProxyURL string
}

func NewProxyOption(proxyURL string) *ProxyOption {
	return &ProxyOption{ProxyURL: proxyURL}
}

// TODO: Allow for other types of proxies outside of stdlib too?

func (o *ProxyOption) Execute(client *http.Client) error {
	puo, err := url.Parse(o.ProxyURL)
	if err != nil {
		return fmt.Errorf("ProxyOption: url.Parse: %w", err)
	}

	_, ok := client.Transport.(*http.Transport)
	if ok {
		client.Transport.(*http.Transport).Proxy = http.ProxyURL(puo)
	}

	_, ok = client.Transport.(*oohttp.StdlibTransport)
	if ok {
		client.Transport.(*oohttp.StdlibTransport).Transport.Proxy = oohttp.ProxyURL(puo)
	}

	return nil
}
