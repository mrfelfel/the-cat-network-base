package catnet

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sort"
	"time"
)

// Payload is the decrypted JSON document.
//
// It is both the answer ("connect here") and the registry ("this is how you
// find the next revision"): the file carries the addresses, the resolvers, the
// mirrors and the relay URL, so the library learns every layer's inputs from
// the document itself and does not depend on a shipped constant going stale.
type Payload struct {
	Version       int       `json:"version"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	MinLibVersion int       `json:"min_lib_version,omitempty"`

	// Servers are the addresses to connect to.
	Servers []Server `json:"servers"`

	// Registry — inputs for the next lookup. Every field is optional; a
	// missing one means "keep the built-in default".

	// GitHubIPs are literal addresses for raw.githubusercontent.com, tried
	// before any DNS lookup.
	GitHubIPs []string `json:"github_ips,omitempty"`
	// GoProxies are Go module proxies that carry the whole repository as a
	// zip. Iranian filtering leaves these up because Go developers need them.
	GoProxies []string `json:"go_proxies,omitempty"`
	// Mirrors are internal mirrors addressed by IP.
	Mirrors []MirrorHost `json:"mirrors,omitempty"`
	// Resolvers are DNS resolvers in the layer syntax: "ip:53",
	// "dot:ip[:port]", "doh:https://ip/query". Listed before the built-ins.
	Resolvers []string `json:"resolvers,omitempty"`
	// ServerName is the DNS name whose TXT record holds the address(es).
	// Layer 4 reads it; it does NOT carry the document, only addresses.
	ServerName string `json:"server_name,omitempty"`
	// AppsScript is the last-resort relay URL.
	AppsScript string `json:"apps_script,omitempty"`
}

// MirrorHost is a mirror addressed by IP. Declared here because it travels in
// the payload as well as in Options.
type MirrorHost struct {
	IP   string `json:"ip"`
	Host string `json:"host"`
	Path string `json:"path,omitempty"`
	// PlainHTTP disables TLS for mirrors that only serve HTTP.
	PlainHTTP bool `json:"plain_http,omitempty"`
}

// Server is one address the client may connect to.
type Server struct {
	// Host is a dotted-quad IPv4 or a bare DNS name.
	Host string `json:"host"`
	Port int    `json:"port"`
	// Tag is free-form: "primary", "backup", "cdn", "relay". Clients may
	// display it or sort by it.
	Tag string `json:"tag,omitempty"`
	// Weight is 0..100; higher is preferred.
	Weight int `json:"weight,omitempty"`
}

// Addr returns the host:port pair, bracketing IPv6 literals.
func (s Server) Addr() string {
	return net.JoinHostPort(s.Host, fmt.Sprint(s.Port))
}

// Expired reports whether p was still valid at t.
func (p Payload) Expired(t time.Time) bool {
	return !p.ExpiresAt.IsZero() && !t.Before(p.ExpiresAt)
}

// Sorted returns the servers by descending weight, stable on input order.
func (p Payload) Sorted() []Server {
	out := append([]Server(nil), p.Servers...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Weight > out[j].Weight })
	return out
}

// decodePayload parses a decrypted document.
//
// Unknown fields are IGNORED rather than rejected, and that is a deliberate
// reversal. With DisallowUnknownFields, publishing any new field broke every
// client already in the field: the whole document failed to parse, catnet fell
// back to the seed, and the fleet lost address discovery for a change it never
// needed to understand. Compatibility has to be forward-only, not exact.
//
// The guard that DisallowUnknownFields used to provide — "this document is not
// one I understand, do not silently read zeros" — is kept in two explicit
// checks below, so tolerance does not become a hole:
//
//  1. Version must match exactly. A future document that changed meaning, not
//     just vocabulary, bumps it and is rejected here as before.
//  2. At least one field this build knows must be present. An empty object, a
//     wrong document, or JSON that parsed into nothing passes neither.
//
// Together those mean a document carrying only fields we do not know is still
// rejected, while one carrying new fields alongside the ones we do know reads
// cleanly.
func decodePayload(plain []byte) (Payload, error) {
	var p Payload
	dec := json.NewDecoder(bytes.NewReader(plain))
	if err := dec.Decode(&p); err != nil {
		return Payload{}, fmt.Errorf("%w: payload is not valid JSON: %v", ErrFormat, err)
	}
	if !knownFieldsPresent(plain) {
		return Payload{}, fmt.Errorf("%w: payload has no fields this build understands", ErrFormat)
	}
	if err := p.validate(); err != nil {
		return Payload{}, err
	}
	return p, nil
}

// knownFieldsPresent reports whether the document carried at least one field
// this build understands. It is the replacement for the "unknown field" guard:
// with unknown fields tolerated, an object made entirely of them would decode
// to an all-zero Payload and pass a naive validate.
func knownFieldsPresent(plain []byte) bool {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(plain, &probe); err != nil {
		return false
	}
	for _, k := range []string{
		"servers", "version", "issued_at", "expires_at", "min_lib_version",
		"github_ips", "go_proxies", "mirrors", "resolvers", "server_name", "apps_script",
	} {
		if _, ok := probe[k]; ok {
			return true
		}
	}
	return false
}

func (p Payload) validate() error {
	// A future version is rejected rather than best-effort read. Tolerance for
	// unknown FIELDS is what keeps this build working across additive changes;
	// a version bump is the signal that a change was not additive, so reading
	// it with this build's meaning would be guessing.
	if p.Version > ProtocolVersion {
		return fmt.Errorf("%w: payload version %d is newer than this client supports (%d)", ErrFormat, p.Version, ProtocolVersion)
	}
	if p.Version != ProtocolVersion {
		return fmt.Errorf("%w: payload version %d", ErrFormat, p.Version)
	}
	if len(p.Servers) == 0 {
		return fmt.Errorf("%w: no servers", ErrFormat)
	}
	for i, s := range p.Servers {
		if err := s.validate(); err != nil {
			return fmt.Errorf("%w: server[%d]: %v", ErrFormat, i, err)
		}
	}
	return nil
}

func (s Server) validate() error {
	if s.Host == "" {
		return fmt.Errorf("empty host")
	}
	if ip := net.ParseIP(s.Host); ip == nil {
		// Not an IP: require a plain DNS label sequence, no scheme/path/space.
		if len(s.Host) > 253 {
			return fmt.Errorf("hostname too long")
		}
		for _, c := range s.Host {
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '-', c == '_':
			default:
				return fmt.Errorf("invalid character %q in host %q", c, s.Host)
			}
		}
	}
	if s.Port < 1 || s.Port > 65535 {
		return fmt.Errorf("port %d out of range", s.Port)
	}
	if s.Weight < 0 || s.Weight > 100 {
		return fmt.Errorf("weight %d out of 0..100", s.Weight)
	}
	return nil
}

// trimReader strips a UTF-8 BOM and surrounding whitespace so that editors
// which add either do not break parsing. It reads from b lazily so we do not
// allocate a copy of the whole document.
type trimReader struct{ r io.Reader }

func newTrimReader(b []byte) io.Reader {
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	b = bytes.TrimSpace(b)
	return &trimReader{bytes.NewReader(b)}
}

func (t *trimReader) Read(p []byte) (int, error) { return t.r.Read(p) }
