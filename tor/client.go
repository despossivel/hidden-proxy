package tor

import (
	"net/http"
	"time"

	"golang.org/x/net/proxy"
)

// NewHTTPClient creates an HTTP client that routes all traffic
// through Tor's SOCKS5 — enabling .onion address resolution
func NewHTTPClient(socksAddr string) (*http.Client, error) {
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}

	// Pool sizes tuned for low-memory devices (RPi 4).
	// 20 idle conns uses ~2 MB vs 100 → ~10 MB.
	transport := &http.Transport{
		Dial:                  dialer.Dial,
		DisableKeepAlives:     false,
		MaxIdleConns:          20,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       120 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		WriteBufferSize:       4096, // 4 KB (default 4 KB) — keep small
		ReadBufferSize:        8192, // 8 KB — enough for headers
		ForceAttemptHTTP2:     false,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   120 * time.Second,
		// do not follow redirects automatically — let the client decide
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}
