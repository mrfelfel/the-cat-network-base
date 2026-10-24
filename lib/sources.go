package catnet

import (
	"context"
	"crypto/tls"
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

// NamesTXTResolver reads server addresses directly from a TXT record.
//
// Unlike every other layer, this one does not fetch a document: the record
// *is* the answer. It exists for the case where HTTPS is filtered but DNS
// still resolves, and it costs one DNS query. The record carries addresses
// only, so it needs no signature — but that also means it is unverified, so
// the caller must own the name and the results are treated as lower-trust
// than a signed document (see TrustedByDNS).
//
// Expected record value, one address per record or space/comma separated:
//
//	"62.220.127.238:30001"
//	"62.220.127.238:30001, 203.0.113.7:30001"
type NamesTXTResolver struct {
	// Record is the TXT record name, e.g. "_gameserver.bizibazi.ir".
	Record string
	// Server is an optional resolver "ip:port"; empty uses the system one.
	Server string
	// Timeout bounds the lookup. Default 800ms.
	Timeout time.Duration
}

func (d NamesTXTResolver) Name() string {
	if d.Record == "" {
		return "names-txt"
	}
	return "names-txt:" + d.Record
}

// Lookup returns the addresses in the record, in record order.
func (d NamesTXTResolver) Lookup(ctx context.Context) ([]Server, error) {
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 800 * time.Millisecond
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
	var out []Server
	for _, rec := range records {
		for _, tok := range splitAddresses(rec) {
			host, port, err := splitHostPort(tok)
			if err != nil {
				continue
			}
			if net.ParseIP(host) == nil {
				continue
			}
			out = append(out, Server{Host: host, Port: port, Tag: "dns-txt"})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no usable addresses in TXT", d.Name())
	}
	return out, nil
}

func (d NamesTXTResolver) Fetch(context.Context) ([]byte, error) {
	return nil, errNotADocument
}

// splitAddresses splits a record on commas and whitespace, dropping empties.
func splitAddresses(rec string) []string {
	fields := strings.FieldsFunc(rec, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	out := fields[:0]
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

var errNotADocument = fmt.Errorf("names-txt carries addresses, not a document")

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
