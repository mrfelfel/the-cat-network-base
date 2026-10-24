package catnet

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"
)

// StaticHostSource fetches https://host/path by connecting to a hard-coded IP
// and using host only for SNI and certificate validation.
//
// This is layer one: it resolves nothing, so a poisoned or dead DNS cannot stop
// it. The certificate must still be valid for host, so a middlebox cannot
// impersonate the endpoint — it can only block it.
type StaticHostSource struct {
	// IP is the address to dial, without a port.
	IP string
	// Host is the name used for SNI and the Host header, e.g.
	// "raw.githubusercontent.com".
	Host string
	// Path is the request path, usually the repo document path. It must begin
	// with "/".
	Path string
	// Timeout bounds the whole request. Default 3s.
	Timeout time.Duration
}

func (s StaticHostSource) Name() string {
	return "static:" + s.IP + "→" + s.Host
}

func (s StaticHostSource) Fetch(ctx context.Context) ([]byte, error) {
	if net.ParseIP(s.IP) == nil {
		return nil, fmt.Errorf("static: %q is not an IP", s.IP)
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ip := s.IP
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			// The requested port comes from the URL; the host is replaced.
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				port = "443"
			}
			return d.DialContext(ctx, network, net.JoinHostPort(ip, port))
		},
		TLSClientConfig:       &tls.Config{ServerName: s.Host, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   2 * time.Second,
		ResponseHeaderTimeout: 3 * time.Second,
	}
	defer tr.CloseIdleConnections()

	url := "https://" + s.Host + freshPath(s.Path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "catnet/1")
	req.Host = s.Host
	resp, err := (&http.Client{Transport: tr, Timeout: timeout}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return readLimited(resp, s.Name())
}
