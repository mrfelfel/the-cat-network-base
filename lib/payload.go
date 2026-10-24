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
type Payload struct {
	Version       int       `json:"version"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	MinLibVersion int       `json:"min_lib_version,omitempty"`
	Servers       []Server  `json:"servers"`
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

func decodePayload(plain []byte) (Payload, error) {
	var p Payload
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Payload{}, fmt.Errorf("%w: payload is not valid JSON: %v", ErrFormat, err)
	}
	if err := p.validate(); err != nil {
		return Payload{}, err
	}
	return p, nil
}

func (p Payload) validate() error {
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
