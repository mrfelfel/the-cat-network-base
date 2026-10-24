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

// DNSTXTSource is layer 4: a signed, compact address list in one TXT record.
//
// It is a bootstrap, not the full document. Its job is to answer "which
// address do I connect to first" in a single DNS query, when HTTPS is filtered
// and even encrypted DNS is blocked. The registry (mirrors, resolvers, relay)
// is not here — it is fetched from the other layers once the client is
// connected, at which point everything is finalised.
//
// The record is encrypted and Ed25519-signed in the CNB2 format, so a poisoned
// DNS can withhold the answer but cannot substitute an address.
type DNSTXTSource struct {
	// Record is the TXT record name, e.g. "_gameserver.bizibazi.ir".
	Record string
	// Server is an optional resolver "ip:port"; empty uses the system one.
	Server string
	// Timeout bounds the lookup. Default 700ms — the record is one string.
	Timeout time.Duration
}

func (d DNSTXTSource) Name() string {
	if d.Record == "" {
		return "dns-txt"
	}
	return "dns-txt:" + d.Record
}

// Lookup returns the signed bootstrap addresses.
func (d DNSTXTSource) Lookup(ctx context.Context) ([]Server, error) {
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 700 * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	r := net.DefaultResolver
	if d.Server != "" {
		server := d.Server
		r = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var dd net.Dialer
			return dd.DialContext(ctx, network, server)
		}}
	}
	records, err := r.LookupTXT(ctx, d.Record)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("%s: no TXT records", d.Name())
	}
	// One record is the normal case; joining also tolerates a provider that
	// split the value.
	return ParseBootstrap(strings.Join(records, ""), Descriptor(), Keys)
}

func (d DNSTXTSource) Fetch(context.Context) ([]byte, error) {
	return nil, fmt.Errorf("%s: bootstrap carries addresses, not a document", d.Name())
}

// decodeTXTDocument tries the base64 encodings a TXT record may use: standard,
// raw (no padding), and URL-safe, in that order.
func decodeTXTDocument(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil && len(b) > 0 {
			return b, nil
		}
	}
	return nil, fmt.Errorf("not base64")
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
