package catnet

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"
)

// Result is what a successful Resolve returns.
type Result struct {
	// Addrs are the resolved addresses, most preferred first.
	Addrs []string
	// Servers is the full decrypted record, including tags and weights.
	Servers []Server
	// Source names the channel that produced the document, e.g. "http:raw.githubusercontent.com".
	Source string
	// FetchedAt is when this process obtained the document.
	FetchedAt time.Time
	// IssuedAt/ExpiresAt come from the signed payload.
	IssuedAt  time.Time
	ExpiresAt time.Time
	// Cached is true when the document came from disk, not the network.
	Cached bool
	// Stale is true when the payload's expires_at has passed. The addresses
	// are still returned: a stale address is usually better than none.
	Stale bool
	// Attempts lists every source tried, in order, with its outcome. It is
	// diagnostic only.
	Attempts []Attempt
}

// Attempt records one source's outcome.
type Attempt struct {
	Source  string
	Err     error
	Skipped bool
}

// Resolver is a configured, reusable address finder. It is safe for concurrent
// use.
type Resolver struct {
	sources []Source
	cache   *cache
	// Concurrency is how many sources are tried at once when the cache misses.
	// Zero means len(sources), capped at 4.
	Concurrency int
	// Now is injectable for tests.
	Now func() time.Time
}

// Options configures Build.
type Options struct {
	// Repo is "owner/name"; used to build the canonical GitHub and mirror URLs.
	Repo string
	// Branch is the branch or tag that holds servers.json. Default "main".
	Branch string
	// File is the document path inside the repo. Default "servers.json".
	File string
	// Mirrors are extra URLs tried before the seed addresses.
	Mirrors []string
	// DNSName is the TXT record name, e.g. "_catnet.catgram.ir". Optional.
	DNSName string
	// Seeds are hard-coded ip:port pairs tried last.
	Seeds []SeedSource
	// CachePath is the document cache file. Empty disables caching.
	CachePath string
}

// Build assembles the default source list: GitHub raw, the operator mirror,
// public CDN mirrors, DNS TXT, then the seeds. Order matters only for
// diagnostics; Resolve races them.
func Build(o Options) *Resolver {
	if o.Branch == "" {
		o.Branch = "main"
	}
	if o.File == "" {
		o.File = "servers.json"
	}
	var srcs []Source
	if o.Repo != "" {
		branch, file := o.Branch, o.File
		srcs = append(srcs,
			HTTPMirror{URL: fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s", o.Repo, branch, file), CacheBust: true},
			HTTPMirror{URL: fmt.Sprintf("https://scorpian.ir/repos/%s/%s/%s", o.Repo, branch, file), CacheBust: true},
			HTTPMirror{URL: fmt.Sprintf("https://cdn.jsdelivr.net/gh/%s@%s/%s", o.Repo, branch, file), CacheBust: true},
			HTTPMirror{URL: fmt.Sprintf("https://ghproxy.net/https://raw.githubusercontent.com/%s/%s/%s", o.Repo, branch, file), CacheBust: true},
			HTTPMirror{URL: fmt.Sprintf("https://raw.githack.com/%s/%s/%s", o.Repo, branch, file), CacheBust: true},
		)
	}
	for _, u := range o.Mirrors {
		srcs = append(srcs, HTTPMirror{URL: u, CacheBust: true})
	}
	if o.DNSName != "" {
		srcs = append(srcs, DNSTXTSource{Name_: o.DNSName})
	}
	for _, s := range o.Seeds {
		srcs = append(srcs, s)
	}
	return &Resolver{sources: srcs, cache: newCache(o.CachePath)}
}

// Sources returns the configured source names, in order.
func (r *Resolver) Sources() []string {
	out := make([]string, len(r.sources))
	for i, s := range r.sources {
		out[i] = s.Name()
	}
	return out
}

// Resolve finds the address list. It returns an error only when no source
// produced a valid document and the cache was empty.
func (r *Resolver) Resolve(ctx context.Context) (*Result, error) {
	now := r.Now
	if now == nil {
		now = time.Now
	}
	res := &Result{FetchedAt: now(), Attempts: []Attempt{}}

	// 1. Cache first: instant, and authoritative enough when fresh.
	if raw := r.cache.load(); raw != nil {
		env, err := ParseEnvelope(raw, Descriptor(), Keys)
		if err != nil {
			res.Attempts = append(res.Attempts, Attempt{Source: "cache", Err: err})
			r.cache.discard()
		} else {
			res.Attempts = append(res.Attempts, Attempt{Source: "cache"})
			res.fill(env, "cache")
			res.Cached = true
			if !res.Payload().Expired(now()) {
				return res, nil
			}
			// Expired cache: keep it as the fallback while we try the network.
			res.Stale = true
		}
	}

	// 2. Race the network sources. First verified document wins.
	fresh, err := r.fetchFirst(ctx, now)
	if err != nil {
		if res.Cached {
			return res, nil
		}
		return nil, fmt.Errorf("catnet: no source produced a valid document: %w", err)
	}
	res.fill(fresh.env, fresh.source)
	res.Cached = false
	res.Stale = fresh.env.Payload.Expired(now())
	r.cache.store(fresh.env.Raw)
	return res, nil
}

// Payload returns the decrypted record backing the result.
func (r *Result) Payload() Payload {
	return Payload{IssuedAt: r.IssuedAt, ExpiresAt: r.ExpiresAt, Servers: r.Servers}
}

func (r *Result) fill(env *Envelope, source string) {
	p := env.Payload
	r.Servers = p.Sorted()
	r.Addrs = make([]string, len(r.Servers))
	for i, s := range r.Servers {
		r.Addrs[i] = s.Addr()
	}
	r.Source = source
	r.IssuedAt = p.IssuedAt
	r.ExpiresAt = p.ExpiresAt
}

type fetchResult struct {
	env    *Envelope
	source string
}

// fetchFirst tries sources concurrently and returns the first verified
// document. Remaining sources are cancelled. The error joins every failure so
// diagnostics name the actual cause (blocked? 404? DNS?).
func (r *Resolver) fetchFirst(ctx context.Context, now func() time.Time) (fetchResult, error) {
	n := len(r.sources)
	if n == 0 {
		return fetchResult{}, errors.New("no sources configured")
	}
	limit := r.Concurrency
	if limit <= 0 || limit > 4 {
		limit = min(4, n)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type out struct {
		i   int
		raw []byte
		err error
	}
	ch := make(chan out, n)
	sem := make(chan struct{}, limit)
	var done atomic.Bool

	for i, s := range r.sources {
		i, s := i, s
		go func() {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				ch <- out{i: i, err: ctx.Err()}
				return
			}
			defer func() { <-sem }()
			if done.Load() {
				ch <- out{i: i, err: errSuperseded}
				return
			}
			raw, err := s.Fetch(ctx)
			ch <- out{i: i, raw: raw, err: err}
		}()
	}

	var errs []error
	for got := 0; got < n; got++ {
		o := <-ch
		if o.err != nil || o.raw == nil {
			if o.err != nil && !errors.Is(o.err, errSuperseded) && !errors.Is(o.err, context.Canceled) {
				errs = append(errs, fmt.Errorf("%s: %w", r.sources[o.i].Name(), o.err))
			} else if o.err == nil {
				errs = append(errs, fmt.Errorf("%s: empty response", r.sources[o.i].Name()))
			}
			continue
		}
		env, err := ParseEnvelope(o.raw, Descriptor(), Keys)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", r.sources[o.i].Name(), err))
			continue
		}
		done.Store(true)
		cancel()
		return fetchResult{env: env, source: r.sources[o.i].Name()}, nil
	}
	if len(errs) == 0 {
		return fetchResult{}, errors.New("all sources were cancelled")
	}
	return fetchResult{}, errors.Join(errs...)
}

var errSuperseded = errors.New("superseded by another source")
