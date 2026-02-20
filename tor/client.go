package tor

import (
	"net/http"
	"time"

	"golang.org/x/net/proxy"
)

// NewHTTPClient cria um cliente HTTP que roteia todo tráfego
// pelo SOCKS5 do Tor — permitindo resolver endereços .onion
func NewHTTPClient(socksAddr string) (*http.Client, error) {
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		Dial:                  dialer.Dial,
		DisableKeepAlives:     false,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		// Tor over SOCKS doesn't support HTTP/2 well; prefer HTTP/1.x
		ForceAttemptHTTP2: false,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   120 * time.Second,
		// não seguir redirects automaticamente — deixar o cliente decidir
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}
