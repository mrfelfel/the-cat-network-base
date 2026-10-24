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
	cachePath := ""
	if cacheDir != "" {
		cachePath = cacheDir + "/catnet-servers.json"
	}
	opts := catnet.Options{
		Repo:      "mrfelfel/the-cat-network-base",
		Branch:    "main",
		File:      "servers.json",
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
