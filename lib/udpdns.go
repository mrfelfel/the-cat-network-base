package catnet

import (
	"context"
	"fmt"
	"net"
	"time"
)

// UDPDNSSource resolves with plain DNS over UDP to explicit servers, then
// fetches the document from the resulting addresses.
//
// Why this exists separately from DNSLayer: DoT and DoH can be blocked by port
// or by SNI, and when they are, an Iranian carrier's own resolver — or any
// national resolver on port 53 — is often still reachable. It is the
// lowest-common-denominator DNS channel, so it sits between the encrypted
// resolvers and the TXT layer.
//
// Plain UDP DNS is not authenticated: a middlebox can answer it. That is
// handled in two ways. First, `plausible` rejects the block-page answers that
// filtering actually returns. Second, and decisively, the fetched document
// must still pass signature verification, so a spoofed DNS answer can at worst
// point at an address that serves nothing, which costs one timeout — it cannot
// substitute a server address.
type UDPDNSSource struct {
	// Hosts are the names to resolve and fetch.
	Hosts []HostPath
	// Servers are DNS servers as "ip" or "ip:port". Default port 53.
	Servers []string
	// Timeout bounds one resolve+fetch attempt. Default 1s.
	Timeout time.Duration
}

func (u UDPDNSSource) Name() string { return "udp-dns" }

func (u UDPDNSSource) Fetch(ctx context.Context) ([]byte, error) {
	timeout := u.Timeout
	if timeout <= 0 {
		timeout = time.Second
	}
	servers := u.Servers
	if len(servers) == 0 {
		// The system resolver is also a UDP resolver, and on a censored
		// network it is frequently the only one that answers at all.
		servers = []string{""}
	}
	var lastErr error
	for _, hp := range u.Hosts {
		for _, srv := range servers {
			ctx1, cancel := context.WithTimeout(ctx, timeout)
			ips, err := resolveUDP(ctx1, hp.Host, srv)
			cancel()
			if err != nil {
				lastErr = err
				continue
			}
			good := rank(plausible(ips))
			if len(good) == 0 {
				lastErr = fmt.Errorf("udp-dns %s via %s: filtered answer %v", hp.Host, srvLabel(srv), ips)
				continue
			}
			for _, ip := range good {
				src := StaticHostSource{IP: ip, Host: hp.Host, Path: hp.Path}
				b, err := src.Fetch(ctx)
				if err == nil {
					return b, nil
				}
				lastErr = err
			}
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("udp-dns: nothing to resolve")
	}
	return nil, lastErr
}

// resolveUDP queries one server over UDP. An empty server uses the system
// resolver, which is itself normally a plain-UDP query to the carrier's DNS.
func resolveUDP(ctx context.Context, host, server string) ([]string, error) {
	if server == "" {
		return lookupHost(ctx, host, nil)
	}
	addr := server
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "53")
	}
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", addr)
		},
	}
	return lookupHost(ctx, host, r)
}

func srvLabel(s string) string {
	if s == "" {
		return "system"
	}
	return s
}
