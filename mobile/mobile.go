// Package mobile is the gomobile-bindable surface of the address finder.
//
// Only string/[]byte/bool/int and error cross the gomobile boundary, so this
// package is deliberately thin: it formats results as JSON and forwards to lib.
//
//	gomobile bind -target=android ./mobile
package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	catnet "github.com/mrfelfel/the-cat-network-base/lib"
)

// Client is the object Android/iOS hold on to. Create it once at startup.
type Client struct {
	r *catnet.Resolver
}

// New creates a client.
//
//	cacheDir  — app-private directory for the document cache (e.g.
//	            context.getCacheDir().getAbsolutePath() on Android). May be empty.
//	seeds     — comma-separated ip:port fallbacks ("" for none).
//	timeoutMs — the overall deadline; 0 uses 12000.
func New(cacheDir string, seeds string, timeoutMs int) (*Client, error) {
	return NewForFile(cacheDir, seeds, timeoutMs, "")
}

// NewForFile is New with an explicit document path inside the repo.
//
// The path is a parameter rather than a constant so a client can move to a
// document layout that older clients cannot read — new fields, a new cache
// name, a different shape — without breaking the ones already installed. An
// empty file keeps the historical "servers.json" and its cache name, so a
// caller that does not care about any of this behaves exactly as before.
//
// The cache filename is derived from the document path on purpose: two
// documents must never share a cache entry, or a client pointing at the new
// layout could be served the old document from disk.
func NewForFile(cacheDir string, seeds string, timeoutMs int, file string) (*Client, error) {
	cachePath := ""
	if cacheDir != "" {
		name := "catnet-servers.json"
		if file != "" {
			name = "catnet-" + strings.NewReplacer("/", "_", "\\", "_").Replace(file) + ".cache"
		}
		cachePath = cacheDir + "/" + name
	}
	opts := catnet.Options{
		Repo:      "mrfelfel/the-cat-network-base",
		Branch:    "main",
		File:      file,
		CachePath: cachePath,
		Seeds:     parseSeeds(seeds),
	}
	return &Client{r: catnet.Build(opts)}, nil
}

// ResolveJSON returns a JSON object:
//
//	{"addrs":["1.2.3.4:30001"],"source":"http:...","stale":false,
//	 "cached":false,"servers":[{"host":..,"port":..,"tag":..,"weight":..}]}
//
// The first element of addrs is the preferred address. On total failure the
// returned string is `{"error":"..."}` and err is non-nil, so a caller that
// only inspects the string still gets valid JSON.
func (c *Client) ResolveJSON(timeoutMs int) (string, error) {
	if timeoutMs <= 0 {
		timeoutMs = 12000
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
	defer cancel()

	res, err := c.r.Resolve(ctx)
	if err != nil {
		b, _ := json.Marshal(map[string]string{"error": err.Error()})
		return string(b), err
	}
	return encode(res), nil
}

// ConfigJSON returns the document's runtime configuration as JSON, or "" when
// the document carried none. It never fails on a missing config: an app must
// keep its compiled-in defaults, not show empty fields.
//
// Payment decisions are answered here rather than in Kotlin because the
// document is the source of truth and only the Go side sees it: a client that
// mirrored the rules would have to be updated in step with every rule change,
// which defeats the purpose of putting them in the document.
//
// build is the distribution name ("play", "standalone", "bazaar"). An unknown
// build is answered with payments disabled — a new distribution must never
// inherit a purchase path because nobody listed it.
func (c *Client) ConfigJSON(build string) string {
	cfg := c.r.Config()
	if cfg == nil {
		return ""
	}
	out := map[string]any{}
	if cfg.Payments != nil {
		out["payments"] = map[string]any{
			"direct_enabled": c.PaymentsEnabled(build),
		}
	}
	if cfg.Support != nil {
		out["support"] = cfg.Support
	}
	if cfg.URLs != nil {
		out["urls"] = cfg.URLs
	}
	b, _ := json.Marshal(out)
	return string(b)
}

// PaymentsEnabled resolves the document's payment switch for one build.
//
// Order of precedence, and why it is this order:
//
//  1. An explicit per-build entry always wins. An operator listing "play":
//     false means play, whatever the master switch says.
//  2. Otherwise the master switch decides.
//  3. If neither is present, payments are allowed subject to whatever the app
//     itself requires — the document says nothing, so it imposes nothing.
//
// A build this document names with no value, or does not name at all, follows
// (2) and (3). What it must NOT do is invent permission: when the document
// carries a Builds map and the build is absent from it, the operator was
// enumerating exceptions and did not include this one.
func (c *Client) PaymentsEnabled(build string) bool {
	cfg := c.r.Config()
	if cfg == nil || cfg.Payments == nil {
		return true
	}
	p := cfg.Payments
	if p.Builds != nil {
		if v, ok := p.Builds[build]; ok {
			return v
		}
		if p.DirectEnabled == nil {
			// The operator enumerated builds and this one was not among them.
			return false
		}
	}
	if p.DirectEnabled != nil {
		return *p.DirectEnabled
	}
	return true
}

// FirstAddr is the convenience call most apps want: just the preferred
// address, or "" and an error.
func (c *Client) FirstAddr(timeoutMs int) (string, error) {
	if timeoutMs <= 0 {
		timeoutMs = 12000
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
	defer cancel()
	res, err := c.r.Resolve(ctx)
	if err != nil {
		return "", err
	}
	if len(res.Addrs) == 0 {
		return "", errors.New("catnet: no addresses")
	}
	return res.Addrs[0], nil
}

// Close releases nothing today; it exists so the bound API can evolve without
// changing call sites.
func (c *Client) Close() {}

// Version is the library build the app is running, for logs and support.
func Version() string { return "1.0.0" }

type mobileServer struct {
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Tag    string `json:"tag,omitempty"`
	Weight int    `json:"weight,omitempty"`
}

func encode(res *catnet.Result) string {
	srvs := make([]mobileServer, len(res.Servers))
	for i, s := range res.Servers {
		srvs[i] = mobileServer{Host: s.Host, Port: s.Port, Tag: s.Tag, Weight: s.Weight}
	}
	b, _ := json.Marshal(map[string]any{
		"addrs":   res.Addrs,
		"servers": srvs,
		"source":  res.Source,
		"stale":   res.Stale,
		"layer":   res.Layer,
		"cached":  res.Cached,
		"expires": res.ExpiresAt.UTC().Format(time.RFC3339),
	})
	return string(b)
}

func parseSeeds(s string) []catnet.SeedSource {
	var out []catnet.SeedSource
	for _, hp := range splitComma(s) {
		if s, ok := parseSeed(hp); ok {
			out = append(out, s)
		}
	}
	return out
}
