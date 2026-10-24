package catnet

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Source produces the published document bytes. Implementations must not
// interpret the content; ParseEnvelope is the only thing that decides whether
// bytes are valid, so every source is equally untrusted.
type Source interface {
	// Name is used in diagnostics, never in decisions.
	Name() string
	// Fetch returns the document. Implementations must honour ctx.
	Fetch(ctx context.Context) ([]byte, error)
}

// HTTPMirror fetches the document from a URL over HTTPS (or HTTP when the
// caller explicitly opts in, e.g. for a LAN bootstrap server).
type HTTPMirror struct {
	// URL is the full document URL, e.g.
	// "https://raw.githubusercontent.com/mrfelfel/the-cat-network-base/main/servers.json".
	URL string
	// CacheBust appends ?t=<unix> so CDN edges do not serve a stale revision.
	CacheBust bool
	// Client is optional; a sane default is used when nil.
	Client *http.Client
}

func (m HTTPMirror) Name() string { return "http:" + hostOf(m.URL) }

func (m HTTPMirror) Fetch(ctx context.Context) ([]byte, error) {
	url := m.URL
	if m.CacheBust {
		sep := "?"
		if strings.ContainsRune(url, '?') {
			sep = "&"
		}
		url += fmt.Sprintf("%st=%d", sep, nowUnix())
	}
	client := m.Client
	if client == nil {
		client = defaultHTTPClient()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "catnet/1")
	// Some mirrors and captive portals return 200 with an HTML login page;
	// the size cap plus signature check rejects those downstream.
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: status %d", m.Name(), resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxEnvelope+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxEnvelope {
		return nil, fmt.Errorf("%s: response too large", m.Name())
	}
	return body, nil
}

// DNSTXTSource reads the document from a TXT record. The record holds the JSON
// document split into <=255-byte base64 chunks, each in its own quoted string;
// the resolver concatenates them in order. Used when HTTPS is filtered but DNS
// still resolves.
type DNSTXTSource struct {
	Name_  string // record name, e.g. "_catnet.catgram.example"
	Server string // optional resolver "host:port"; empty uses the system one
	Net    string // "udp", "tcp", "tcp-tls"; empty uses "udp"
}

func (d DNSTXTSource) Name() string {
	if d.Name_ == "" {
		return "dns:txt"
	}
	return "dns:" + d.Name_
}

func (d DNSTXTSource) Fetch(ctx context.Context) ([]byte, error) {
	r := &net.Resolver{}
	if d.Server != "" {
		server := d.Server
		r.PreferGo = true
		r.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			var dd net.Dialer
			return dd.DialContext(ctx, network, server)
		}
	}
	records, err := r.LookupTXT(ctx, d.Name_)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("%s: no TXT records", d.Name())
	}
	joined := strings.Join(records, "")
	raw, err := base64.StdEncoding.DecodeString(joined)
	if err != nil {
		// Records published as raw JSON are accepted too, which makes the
		// record human-readable in `dig`.
		if strings.HasPrefix(strings.TrimSpace(joined), "{") {
			return []byte(joined), nil
		}
		return nil, fmt.Errorf("%s: %v", d.Name(), err)
	}
	return raw, nil
}

// SeedSource asks a hard-coded ip:port to serve the document over plain HTTP.
// This is the last line of defence: it needs neither DNS nor TLS, only that
// the seed host is reachable. Path is fixed so the server side is one static
// route.
type SeedSource struct {
	Host string
	Port int
	// Path defaults to "/owpengram/net".
	Path string
}

func (s SeedSource) Name() string { return "seed:" + s.Host }

func (s SeedSource) Fetch(ctx context.Context) ([]byte, error) {
	path := s.Path
	if path == "" {
		path = "/owpengram/net"
	}
	url := "http://" + net.JoinHostPort(s.Host, fmt.Sprint(s.Port)) + path
	return HTTPMirror{URL: url, Client: seedHTTPClient(), CacheBust: true}.Fetch(ctx)
}

func defaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			ForceAttemptHTTP2:     true,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 6 * time.Second,
		},
	}
}

// seedHTTPClient talks to a bare IP, so hostname verification cannot apply.
// The document's signature is what authenticates the content; TLS would only
// hide the transport, which is not the threat model for a seed.
func seedHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy:               nil,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			TLSHandshakeTimeout: 4 * time.Second,
		},
	}
}

func hostOf(url string) string {
	url = strings.TrimPrefix(strings.TrimPrefix(url, "https://"), "http://")
	if i := strings.IndexAny(url, "/?"); i >= 0 {
		url = url[:i]
	}
	return url
}

// readLimited reads a response body with the envelope size cap, so a hostile or
// broken endpoint cannot make the client allocate unbounded memory.
func readLimited(resp *http.Response, name string) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxEnvelope+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxEnvelope {
		return nil, fmt.Errorf("%s: response too large", name)
	}
	return body, nil
}

// Addr is the seed's host:port dial string.
func (s SeedSource) Addr() string { return net.JoinHostPort(s.Host, fmt.Sprint(s.Port)) }
