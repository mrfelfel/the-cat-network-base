package catnet

import (
	"context"
	"crypto/tls"
	"net"
)

// DoT resolver IPs are also valid certificate names (the IP is in the SAN list
// of the provider's certificate), so ServerName is set from the IP and normal
// verification still applies — no InsecureSkipVerify.
var dotServerNames = map[string]string{
	"1.1.1.1":         "one.one.one.one",
	"1.0.0.1":         "one.one.one.one",
	"8.8.8.8":         "dns.google",
	"8.8.4.4":         "dns.google",
	"9.9.9.9":         "dns.quad9.net",
	"149.112.112.112": "dns.quad9.net",
}

// dotResolver returns a Resolver that speaks DNS-over-TLS to server, "ip:port".
// A filtering middlebox can inject plain UDP answers, but cannot forge the
// resolver's certificate.
func dotResolver(server string) *net.Resolver {
	host, _, _ := net.SplitHostPort(server)
	name := dotServerNames[host]
	if name == "" {
		name = host
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			conn, err := d.DialContext(ctx, "tcp", server)
			if err != nil {
				return nil, err
			}
			tc := tls.Client(conn, &tls.Config{ServerName: name, MinVersion: tls.VersionTLS12})
			if err := tc.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, err
			}
			return tc, nil
		},
	}
}
