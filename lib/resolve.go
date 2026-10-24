package catnet

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Result is what a successful Resolve returns.
type Result struct {
	// Addrs are the resolved addresses, most preferred first.
	Addrs []string
	// Servers is the full decrypted record, including tags and weights.
	Servers []Server
	// Source names the layer that produced the document.
	Source string
	// Layer is the numeric position of Source in the chain, for diagnostics.
	Layer int
	// FetchedAt is when this process obtained the document.
	FetchedAt time.Time
	// IssuedAt/ExpiresAt come from the signed payload.
	IssuedAt  time.Time
	ExpiresAt time.Time
	// Probed lists seed addresses that answered a TCP connect, fastest first.
	// Non-empty means the app can skip document fetching entirely on a later
	// run and go straight to a known-good address.
	Probed []ProbeResult
	// Cached is true when the document came from disk, not the network.
	Cached bool
	// Stale is true when the payload's expires_at has passed.
	Stale bool
	// Attempts lists every layer tried, in order, with its outcome.
	Attempts []Attempt
}

// Attempt records one layer's outcome.
type Attempt struct {
	Layer  int
	Source string
	Err    error
}

// Resolver is a configured, reusable address finder. Safe for concurrent use.
type Resolver struct {
	layers []Source
	cache  *cache
	seeds  []SeedSource
	// ProbeTimeout bounds layer zero. Zero uses 500ms.
	ProbeTimeout time.Duration
	// Now is injectable for tests.
	Now func() time.Time
}

// Options configures Build.
type Options struct {
	// Repo is "owner/name".
	Repo string
	// Branch is the branch or tag holding servers.json. Default "main".
	Branch string
	// File is the document path inside the repo. Default "servers.json".
	File string
	// GitHubIPs are literal GitHub/CDN addresses used before any DNS lookup.
	// Empty uses a built-in set.
	GitHubIPs []string
	// Mirrors are internal mirrors addressed by static IP, e.g. the Liara
	// packages and the operator's own mirror. They are tried before DNS.
	Mirrors []MirrorHost
	// DNSHosts are hostnames resolved by the DNS layer. Empty uses a built-in
	// set matching GitHubIPs.
	DNSHosts []HostPath
	// Resolvers are explicit DNS resolvers, "ip:53" / "dot:ip" / "doh:https://ip/query".
	Resolvers []string
	// DNSName is an optional TXT record, "_catnet.example.com".
	DNSName string
	// AppsScript is the last-resort relay URL.
	AppsScript string
	// AppsScriptToken is the optional shared secret for that relay.
	AppsScriptToken string
	// Seeds are hard-coded server addresses probed at layer zero.
	Seeds []SeedSource
	// CachePath is the document cache file. Empty disables caching.
	CachePath string
}

// MirrorHost is an internal or vendor mirror addressed by IP.
type MirrorHost struct {
	// IP is the literal address to dial.
	IP string
	// Host is the TLS name and Host header, e.g. "package-mirror.liara.ir".
	Host string
	// Path is the document URL path on that host.
	Path string
	// PlainHTTP disables TLS for mirrors that only serve HTTP (some internal
	// package mirrors on port 80).
	PlainHTTP bool
}

// defaultGitHubIPs are the addresses raw.githubusercontent.com and
// github.com have answered with for long periods. They are not guaranteed and
// are refreshed by the published document's `mirror_ips` on each successful
// fetch, so a stale entry costs one timeout, not correctness.
var defaultGitHubIPs = []string{
	"185.199.108.133",
	"185.199.109.133",
	"185.199.110.133",
	"185.199.111.133",
}

// defaultDNSHosts are the names the DNS layer resolves when no static IP
// worked. The paths are filled in by Build.
var defaultDNSHosts = []string{
	"raw.githubusercontent.com",
	"cdn.jsdelivr.net",
}

// Build assembles the layer chain in the order the client must use.
func Build(o Options) *Resolver {
	if o.Branch == "" {
		o.Branch = "main"
	}
	if o.File == "" {
		o.File = "servers.json"
	}
	docPath := "/" + o.Repo + "/" + o.Branch + "/" + o.File
	if o.Repo == "" {
		docPath = "/" + o.File
	}

	ips := o.GitHubIPs
	if len(ips) == 0 {
		ips = defaultGitHubIPs
	}

	var layers []Source

	// Layer 1 — static IP, no DNS: GitHub's raw host, then each internal
	// mirror. A blocked or poisoned DNS cannot stop any of these.
	for _, ip := range ips {
		layers = append(layers, StaticHostSource{IP: ip, Host: "raw.githubusercontent.com", Path: docPath})
	}
	for _, m := range o.Mirrors {
		layers = append(layers, mirrorSource(m, docPath))
	}

	// Layer 2 — light DNS, but reject filtered answers.
	hosts := o.DNSHosts
	if len(hosts) == 0 {
		for _, h := range defaultDNSHosts {
			hosts = append(hosts, HostPath{Host: h, Path: docPath})
		}
	}
	resolvers := o.Resolvers
	if len(resolvers) == 0 {
		resolvers = []string{"dot:8.8.8.8", "dot:1.1.1.1", "doh:https://8.8.8.8/dns-query"}
	}
	layers = append(layers, DNSLayer{Hosts: hosts, Resolvers: resolvers})

	// Layer 3 — DNS TXT on our own domain.
	if o.DNSName != "" {
		layers = append(layers, DNSTXTSource{Name_: o.DNSName})
	}

	// Layer 4 — last resort: the Google Apps Script relay.
	if o.AppsScript != "" {
		layers = append(layers, AppsScriptSource{URL: o.AppsScript, Token: o.AppsScriptToken})
	}

	return &Resolver{
		layers: layers,
		cache:  newCache(o.CachePath),
		seeds:  o.Seeds,
	}
}

func mirrorSource(m MirrorHost, docPath string) Source {
	if m.Path == "" {
		m.Path = docPath
	}
	if m.PlainHTTP {
		return HTTPMirror{URL: "http://" + m.IP + m.Path, CacheBust: true}
	}
	return StaticHostSource{IP: m.IP, Host: m.Host, Path: m.Path}
}

// Sources returns the layer names in order.
func (r *Resolver) Sources() []string {
	out := make([]string, len(r.layers))
	for i, s := range r.layers {
		out[i] = s.Name()
	}
	return out
}

// Resolve finds the address list.
//
// Order: fresh cache → layer 0 probe of seeds → layers 1..N in order → stale
// cache. It returns an error only when nothing at all succeeded.
func (r *Resolver) Resolve(ctx context.Context) (*Result, error) {
	now := r.Now
	if now == nil {
		now = time.Now
	}
	res := &Result{FetchedAt: now(), Attempts: []Attempt{}}

	var staleFallback []byte
	if raw := r.cache.load(); raw != nil {
		env, err := ParseEnvelope(raw, Descriptor(), Keys)
		if err != nil {
			res.Attempts = append(res.Attempts, Attempt{Layer: -1, Source: "cache", Err: err})
			r.cache.discard()
		} else {
			res.Attempts = append(res.Attempts, Attempt{Layer: -1, Source: "cache"})
			res.fill(env, "cache", -1)
			res.Cached = true
			if !env.Payload.Expired(now()) {
				return res, nil
			}
			res.Stale = true
			staleFallback = raw
		}
	}

	// Layer 0 — is a seed already reachable? A TCP connect is the cheapest
	// possible proof and needs no document at all.
	if probed := r.probeSeeds(ctx); len(probed) > 0 {
		res.Probed = probed
		// Seed reachability is not the same as a verified document, so only
		// short-circuit when the cached document is at least decryptable.
		// When there is no cache, the seed address itself is still the best
		// answer we have, and it costs nothing to return it now.
		if !res.Cached {
			addrs := make([]string, len(probed))
			for i, p := range probed {
				addrs[i] = p.Addr
			}
			res.Addrs = addrs
			res.Servers = serversFromSeeds(probed)
			res.Source = "probe"
			res.Layer = 0
			return res, nil
		}
	} else {
		res.Attempts = append(res.Attempts, Attempt{Layer: 0, Source: "probe", Err: errors.New("no seed reachable")})
	}

	// Layers 1..N, strictly in order: the first that verifies wins.
	for i, layer := range r.layers {
		n := i + 1
		raw, err := layer.Fetch(ctx)
		if err != nil {
			res.Attempts = append(res.Attempts, Attempt{Layer: n, Source: layer.Name(), Err: err})
			continue
		}
		env, err := ParseEnvelope(raw, Descriptor(), Keys)
		if err != nil {
			res.Attempts = append(res.Attempts, Attempt{Layer: n, Source: layer.Name(), Err: err})
			continue
		}
		res.Attempts = append(res.Attempts, Attempt{Layer: n, Source: layer.Name()})
		r.cache.store(env.Raw)
		probed := res.Probed
		res.fill(env, layer.Name(), n)
		res.Probed = probed
		res.Cached = false
		res.Stale = env.Payload.Expired(now())
		return res, nil
	}

	if staleFallback != nil {
		return res, nil
	}
	return nil, fmt.Errorf("catnet: no layer produced a valid document: %w", joinAttempts(res.Attempts))
}

func (r *Resolver) probeSeeds(ctx context.Context) []ProbeResult {
	if len(r.seeds) == 0 {
		return nil
	}
	addrs := make([]string, len(r.seeds))
	for i, s := range r.seeds {
		addrs[i] = s.Addr()
	}
	return ProbeAll(ctx, addrs, r.ProbeTimeout)
}

func serversFromSeeds(p []ProbeResult) []Server {
	out := make([]Server, 0, len(p))
	for _, s := range p {
		host, port, err := splitHostPort(s.Addr)
		if err != nil {
			continue
		}
		out = append(out, Server{Host: host, Port: port, Tag: "seed"})
	}
	return out
}

// Payload returns the decrypted record backing the result.
func (r *Result) Payload() Payload {
	return Payload{IssuedAt: r.IssuedAt, ExpiresAt: r.ExpiresAt, Servers: r.Servers}
}

func (r *Result) fill(env *Envelope, source string, layer int) {
	p := env.Payload
	r.Servers = p.Sorted()
	r.Addrs = make([]string, len(r.Servers))
	for i, s := range r.Servers {
		r.Addrs[i] = s.Addr()
	}
	r.Source = source
	r.Layer = layer
	r.IssuedAt = p.IssuedAt
	r.ExpiresAt = p.ExpiresAt
}

// ProbeSeeds exposes layer zero to callers that want to skip document fetching
// entirely on a warm start.
func (r *Resolver) ProbeSeeds(ctx context.Context) []ProbeResult { return r.probeSeeds(ctx) }

func joinAttempts(as []Attempt) error {
	var parts []string
	for _, a := range as {
		if a.Err != nil {
			parts = append(parts, fmt.Sprintf("L%d %s: %v", a.Layer, a.Source, a.Err))
		}
	}
	if len(parts) == 0 {
		return errors.New("no layers configured")
	}
	return errors.New(strings.Join(parts, "; "))
}
