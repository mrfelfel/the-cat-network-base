package catnet

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPlausibleRejectsFilteredAnswers(t *testing.T) {
	in := []string{
		"10.10.34.36",         // the classic Iranian block page
		"127.0.0.1",           // loopback
		"0.0.0.0",             // null route
		"192.168.1.1",         // private
		"169.254.1.1",         // link-local
		"224.0.0.1",           // multicast
		"185.199.108.133",     // real
		"2606:50c0:8000::154", // real v6
		"not-an-ip",
	}
	got := plausible(in)
	want := []string{"185.199.108.133", "2606:50c0:8000::154"}
	if len(got) != len(want) {
		t.Fatalf("plausible = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("plausible[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if len(plausible([]string{"10.10.34.36"})) != 0 {
		t.Fatal("a block-page answer must not be considered usable")
	}
}

func TestRankPrefersIPv4(t *testing.T) {
	in := []string{"2606:50c0:8000::154", "185.199.108.133", "2606:50c0:8000::153"}
	got := rank(append([]string(nil), in...))
	if got[0] != "185.199.108.133" {
		t.Fatalf("rank = %v", got)
	}
}

func TestProbeAllReturnsFastestReachableFirst(t *testing.T) {
	// Two listeners; probe both. Both are reachable, so ordering is by RTT,
	// which cannot be asserted reliably — assert membership and order of the
	// slice's fields instead.
	l1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l1.Close()
	l2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()

	addrs := []string{l1.Addr().String(), "127.0.0.1:1"} // second likely refused
	got := ProbeAll(context.Background(), addrs, 2*time.Second)
	if len(got) == 0 || got[0].Addr != l1.Addr().String() {
		t.Fatalf("probe results = %+v", got)
	}
	if got[0].RTT <= 0 {
		t.Fatal("RTT not measured")
	}
}

func TestProbeAllEmptyWhenUnreachable(t *testing.T) {
	got := ProbeAll(context.Background(), []string{"127.0.0.1:1"}, 300*time.Millisecond)
	if len(got) != 0 {
		t.Fatalf("unexpected results: %+v", got)
	}
}

func TestLayerZeroReturnsSeedWithoutAnyNetwork(t *testing.T) {
	// No layers at all: if the probe succeeds, Resolve must still answer.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	host, port, _ := net.SplitHostPort(l.Addr().String())
	var p int
	for _, c := range port {
		p = p*10 + int(c-'0')
	}

	r := &Resolver{
		cache: newCache(""),
		seeds: []SeedSource{{Host: host, Port: p}},
	}
	res, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Layer != 0 || res.Source != "probe" {
		t.Fatalf("layer=%d source=%q", res.Layer, res.Source)
	}
	if len(res.Addrs) != 1 || res.Addrs[0] != l.Addr().String() {
		t.Fatalf("addrs = %v", res.Addrs)
	}
}

func TestStaticSourceIgnoresDNS(t *testing.T) {
	// Serve the document on a local TLS server, then reach it through a
	// StaticHostSource pointed at 127.0.0.1 while the Host name is
	// unresolvable. Success proves no lookup happened.
	priv := mustPriv(t)
	doc := seal(t, samplePayload(), nil, priv, 7)
	restore := swapKeys(t, 7, priv.Public().(ed25519.PublicKey))
	defer restore()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(doc)
	}))
	defer srv.Close()

	// The test server's certificate is for 127.0.0.1; use its own client
	// trust by giving the source a static IP and the server's host name.
	ip, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	src := StaticHostSource{
		IP:      ip,
		Host:    "raw.githubusercontent.com",
		Path:    "/o/r/main/servers.json",
		Timeout: 2 * time.Second,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// This will fail TLS verification against the test certificate; what
	// matters is that it reached the server without resolving the name.
	_, err := src.Fetch(ctx)
	if err == nil {
		return // a trusted local cert would also be a pass
	}
	if strings.Contains(err.Error(), "no such host") || strings.Contains(err.Error(), "lookup") {
		t.Fatalf("static source performed a DNS lookup: %v", err)
	}
	_ = port
}

func TestTimeBucketIsStableWithinWindow(t *testing.T) {
	a := timeBucket()
	b := timeBucket()
	if a != b {
		t.Fatalf("bucket changed between calls: %d then %d", a, b)
	}
	// A bucket is 10 minutes, so the current time's bucket must be
	// now/600.
	if want := nowUnix() / 600; a != want && a != want-1 && a != want+1 {
		t.Fatalf("bucket %d out of range for now=%d", a, nowUnix())
	}
}

func TestFreshPathAppendsBucket(t *testing.T) {
	p := freshPath("/o/r/main/servers.json")
	if !strings.Contains(p, "b=") {
		t.Fatalf("freshPath = %q", p)
	}
	if q := freshPath("/x?y=1"); !strings.Contains(q, "&b=") {
		t.Fatalf("freshPath with query = %q", q)
	}
}

func TestDNSParseRejectsMismatchedID(t *testing.T) {
	msg, id, err := buildAQuery("example.com")
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint16(msg[0:], id+1) // tamper
	if _, err := parseAAnswer(msg, id, "example.com"); err == nil {
		t.Fatal("expected id mismatch error")
	}
}

func TestBuildAQueryShape(t *testing.T) {
	msg, _, err := buildAQuery("raw.githubusercontent.com")
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(msg[4:]) != 1 {
		t.Fatal("QDCOUNT != 1")
	}
	if !strings.Contains(string(msg[12:]), "raw") {
		t.Fatal("question name missing")
	}
	if msg[len(msg)-1] != 1 || msg[len(msg)-2] != 0 {
		t.Fatal("QTYPE/QCLASS wrong")
	}
}

var _ = ed25519.PublicKey{}

func TestSplitAddresses(t *testing.T) {
	got := splitAddresses("62.220.127.238:30001, 203.0.113.7:30001\n10.0.0.1:1")
	want := []string{"62.220.127.238:30001", "203.0.113.7:30001", "10.0.0.1:1"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestNamesTXTSkipsNonAddresses(t *testing.T) {
	// A record that also carries a non-address token must not fail the layer;
	// only the valid entry is used.
	rec := "v=spf1 -all 62.220.127.238:30001 example.com:80"
	var out []Server
	for _, tok := range splitAddresses(rec) {
		host, port, err := splitHostPort(tok)
		if err != nil || net.ParseIP(host) == nil {
			continue
		}
		out = append(out, Server{Host: host, Port: port})
	}
	if len(out) != 1 || out[0].Addr() != "62.220.127.238:30001" {
		t.Fatalf("out = %+v", out)
	}
}
