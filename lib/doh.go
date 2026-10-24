package catnet

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// lookupDoH performs a DNS-over-HTTPS A query. endpoint is like
// "https://1.1.1.1/dns-query": it must carry an IP literal so that resolving
// the resolver does not depend on the resolver.
func lookupDoH(ctx context.Context, host, endpoint string) ([]string, error) {
	msg, id, err := buildAQuery(host)
	if err != nil {
		return nil, err
	}
	hostPart := splitHost(endpoint)
	ip := net.ParseIP(hostPart)
	if ip == nil {
		return nil, fmt.Errorf("doh endpoint %q must be an IP", endpoint)
	}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				port = "443"
			}
			return d.DialContext(ctx, network, net.JoinHostPort(hostPart, port))
		},
		// Certificate validation stays on: the DoH endpoint must prove it is
		// the resolver it claims to be.
		TLSClientConfig: &tls.Config{ServerName: hostPart, MinVersion: tls.VersionTLS12},
	}
	defer tr.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(msg))
	if err != nil {
		return nil, err
	}
	req.Host = hostPart
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := (&http.Client{Transport: tr, Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, err
	}
	return parseAAnswer(body, id, host)
}

// buildAQuery constructs a minimal DNS query for an A record, returning the
// wire bytes and the transaction id used.
func buildAQuery(host string) ([]byte, uint16, error) {
	if len(host) == 0 || len(host) > 253 {
		return nil, 0, fmt.Errorf("bad host %q", host)
	}
	id := uint16(nowUnix() & 0xffff)
	buf := make([]byte, 0, 12+len(host)+6)
	var hdr [12]byte
	binary.BigEndian.PutUint16(hdr[0:], id)
	binary.BigEndian.PutUint16(hdr[4:], 1) // QDCOUNT
	buf = append(buf, hdr[:]...)
	for _, label := range splitLabels(host) {
		if len(label) == 0 || len(label) > 63 {
			return nil, 0, fmt.Errorf("bad label in %q", host)
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0)    // root
	buf = append(buf, 0, 1) // QTYPE A
	buf = append(buf, 0, 1) // QCLASS IN
	return buf, id, nil
}

func parseAAnswer(msg []byte, wantID uint16, host string) ([]string, error) {
	if len(msg) < 12 {
		return nil, fmt.Errorf("dns: short answer")
	}
	if binary.BigEndian.Uint16(msg[0:]) != wantID {
		return nil, fmt.Errorf("dns: transaction id mismatch")
	}
	ancount := int(binary.BigEndian.Uint16(msg[6:]))
	qd := int(binary.BigEndian.Uint16(msg[4:]))
	off := 12
	for i := 0; i < qd; i++ {
		var err error
		off, err = skipName(msg, off)
		if err != nil {
			return nil, err
		}
		off += 4
	}
	var out []string
	for i := 0; i < ancount; i++ {
		var err error
		off, err = skipName(msg, off)
		if err != nil {
			return nil, err
		}
		if off+10 > len(msg) {
			break
		}
		typ := binary.BigEndian.Uint16(msg[off:])
		class := binary.BigEndian.Uint16(msg[off+2:])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8:]))
		off += 10
		if off+rdlen > len(msg) {
			break
		}
		if typ == 1 && class == 1 && rdlen == 4 {
			out = append(out, net.IP(msg[off:off+4]).String())
		}
		off += rdlen
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("dns: no A records for %s", host)
	}
	return out, nil
}

func skipName(msg []byte, off int) (int, error) {
	for {
		if off >= len(msg) {
			return 0, fmt.Errorf("dns: truncated name")
		}
		l := int(msg[off])
		switch {
		case l == 0:
			return off + 1, nil
		case l&0xc0 == 0xc0:
			return off + 2, nil
		default:
			off += 1 + l
		}
	}
}

func splitLabels(host string) []string {
	var out []string
	start := 0
	for i := 0; i < len(host); i++ {
		if host[i] == '.' {
			out = append(out, host[start:i])
			start = i + 1
		}
	}
	return append(out, host[start:])
}

// splitHost returns the authority part of a URL, dropping the scheme.
func splitHost(u string) string {
	hp := u
	hp = strings.TrimPrefix(hp, "https://")
	hp = strings.TrimPrefix(hp, "http://")
	if i := strings.IndexByte(hp, '/'); i >= 0 {
		hp = hp[:i]
	}
	return hp
}
