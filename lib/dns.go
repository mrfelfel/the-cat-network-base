package catnet

import (
	"context"
	"fmt"
	"net"
	"sort"
	"time"
)

// DNSLayer resolves hostnames then fetches from whichever IPs answered.
//
// Between the static-IP layer and the CDN layer: a "light DNS" step. Its job
// is not only to get an address but to *reject* obviously-filtered answers
// before they cost a connection attempt. Iranian filtering commonly answers
// with an internal or black-hole address (10.x, 127.x, 0.0.0.0) or a country
// address that is not where the service lives; connecting to those burns a
// timeout and never works.
type DNSLayer struct {
	// Hosts are the hostnames to resolve and fetch, e.g.
	// raw.githubusercontent.com.
	Hosts []HostPath
	// Resolvers are tried in order until one yields a plausible answer. Entries
	// are "ip:53", "dot:ip:853" or "doh:https://ip/dns-query". Empty means the
	// system resolver only.
	Resolvers []string
	// Timeout bounds one resolution attempt. Default 800ms.
	Timeout time.Duration
}

// HostPath binds a hostname to the request path served on it.
type HostPath struct {
	Host string
	Path string
}

func (d DNSLayer) Name() string { return "dns" }

func (d DNSLayer) Fetch(ctx context.Context) ([]byte, error) {
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 800 * time.Millisecond
	}
	var lastErr error
	for _, hp := range d.Hosts {
		ips, err := resolvePlausible(ctx, hp.Host, d.Resolvers, timeout)
		if err != nil {
			lastErr = err
			continue
		}
		for _, ip := range ips {
			src := StaticHostSource{IP: ip, Host: hp.Host, Path: hp.Path}
			b, err := src.Fetch(ctx)
			if err == nil {
				return b, nil
			}
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("dns: no hosts configured")
	}
	return nil, lastErr
}

// resolvePlausible returns IPs for host, preferring resolver answers that are
// not obviously filtered. A system-resolver answer is accepted only if it is
// plausible; otherwise the explicit resolvers (8.8.8.8, 1.1.1.1 over DoT/DoH)
// are consulted.
func resolvePlausible(ctx context.Context, host string, resolvers []string, timeout time.Duration) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ips, sysErr := lookupHost(ctx, host, nil)
	if len(plausible(ips)) > 0 {
		return rank(plausible(ips)), nil
	}
	var errs []error
	if sysErr != nil {
		errs = append(errs, fmt.Errorf("system: %w", sysErr))
	} else if len(ips) > 0 {
		errs = append(errs, fmt.Errorf("system returned filtered answer %v", ips))
	}
	for _, r := range resolvers {
		ips, err := lookupVia(ctx, host, r)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", r, err))
			continue
		}
		if good := plausible(ips); len(good) > 0 {
			return rank(good), nil
		}
		errs = append(errs, fmt.Errorf("%s returned filtered answer %v", r, ips))
	}
	return nil, fmt.Errorf("dns %s: %v", host, joinErrs(errs))
}

func lookupHost(ctx context.Context, host string, r *net.Resolver) ([]string, error) {
	if r == nil {
		r = net.DefaultResolver
	}
	return r.LookupHost(ctx, host)
}

// lookupVia resolves through one explicit resolver. "ip:53" uses plain UDP;
// "dot:ip[:port]" uses DNS-over-TLS; "doh:https://..." uses DoH. All forms
// address the resolver by IP so bootstrapping the resolver does not itself
// depend on the resolver.
func lookupVia(ctx context.Context, host, spec string) ([]string, error) {
	switch {
	case hasPrefixFold(spec, "doh:"):
		return lookupDoH(ctx, host, spec[len("doh:"):])
	case hasPrefixFold(spec, "dot:"):
		server := spec[len("dot:"):]
		if _, _, err := net.SplitHostPort(server); err != nil {
			server = net.JoinHostPort(server, "853")
		}
		r := dotResolver(server)
		return lookupHost(ctx, host, r)
	default:
		server := spec
		if _, _, err := net.SplitHostPort(server); err != nil {
			server = net.JoinHostPort(server, "53")
		}
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, server)
		}}
		return lookupHost(ctx, host, r)
	}
}

// plausible rejects answers that are private, loopback, link-local,
// unspecified or multicast. A real public service never answers with these;
// filtering middleboxes almost always do.
func plausible(ips []string) []string {
	var out []string
	for _, s := range ips {
		ip := net.ParseIP(s)
		if ip == nil {
			continue
		}
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
			ip.IsUnspecified() || ip.IsMulticast() {
			continue
		}
		out = append(out, s)
	}
	return out
}

// rank puts IPv4 first: Iranian mobile networks frequently have broken IPv6
// routes, so an IPv6 attempt costs a full timeout for nothing.
func rank(ips []string) []string {
	sort.SliceStable(ips, func(i, j int) bool {
		return net.ParseIP(ips[i]).To4() != nil && net.ParseIP(ips[j]).To4() == nil
	})
	return ips
}

func joinErrs(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	msg := errs[0].Error()
	for _, e := range errs[1:] {
		msg += "; " + e.Error()
	}
	return fmt.Errorf("%s", msg)
}

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && equalFold(s[:len(prefix)], prefix)
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}
