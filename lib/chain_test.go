package catnet

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The tests here pin the *ordering contract* of the chain: which layer answers
// first, which layers are never touched after a winner, and what state the
// result carries. They use fake sources so they are hermetic.

func TestChainStopsAtTheFirstWorkingLayer(t *testing.T) {
	priv := mustPriv(t)
	restore := swapKeys(t, 7, priv.Public().(ed25519.PublicKey))
	defer restore()

	doc := seal(t, samplePayload(), nil, priv, 7)
	doc2 := seal(t, samplePayload(), nil, priv, 7)

	l1 := &fakeSource{name: "L1", err: errors.New("blocked")}
	l2 := &fakeSource{name: "L2", raw: doc}
	l3 := &fakeSource{name: "L3", raw: doc2}
	r := &Resolver{layers: []Source{l1, l2, l3}, cache: newCache("")}

	res, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Layer != 2 || res.Source != "L2" {
		t.Fatalf("layer=%d source=%q", res.Layer, res.Source)
	}
	if l1.calls.Load() != 1 {
		t.Fatalf("failed layer calls = %d, want 1", l1.calls.Load())
	}
	if l3.calls.Load() != 0 {
		t.Fatal("a layer after the winner was still called")
	}
}

func TestChainRecordsEveryAttempt(t *testing.T) {
	priv := mustPriv(t)
	restore := swapKeys(t, 7, priv.Public().(ed25519.PublicKey))
	defer restore()
	doc := seal(t, samplePayload(), nil, priv, 7)

	r := &Resolver{layers: []Source{
		&fakeSource{name: "bad-html", raw: []byte("<html>login</html>")},
		&fakeSource{name: "wrong-signature", raw: []byte(`{"v":1,"kid":7,"n":"AAAAAAAAAAAAAAAA","ct":"AAAAAAAAAAAAAAAAAAAAAA==","sig":"AAAA"}`)},
		&fakeSource{name: "good", raw: doc},
	}, cache: newCache("")}

	res, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, a := range res.Attempts {
		names = append(names, a.Source)
		if a.Source != "good" && a.Err == nil {
			t.Fatalf("%s should have failed", a.Source)
		}
	}
	// Layer 0 always records an attempt (there are no seeds here), so the
	// document layers follow it.
	if !strings.HasSuffix(strings.Join(names, ","), "bad-html,wrong-signature,good") {
		t.Fatalf("attempts = %v", names)
	}
	if res.Source != "good" {
		t.Fatalf("source = %q", res.Source)
	}
}

func TestChainBootstrapWinsWithoutFetchingADocument(t *testing.T) {
	priv := mustPriv(t)
	restore := swapKeys(t, 7, priv.Public().(ed25519.PublicKey))
	defer restore()

	record := sealBoot(t, []Server{{Host: "62.220.127.238", Port: 30001}}, priv)
	after := &fakeSource{name: "after", raw: []byte("never")}

	r := &Resolver{
		layers: []Source{
			DNSTXTSource{Record: "_gameserver.test", lookupTXT: fixedTXT(record)},
			after,
		},
		cache: newCache(""),
	}
	res, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Addrs[0] != "62.220.127.238:30001" || res.Layer != 1 {
		t.Fatalf("layer=%d addrs=%v", res.Layer, res.Addrs)
	}
	if after.calls.Load() != 0 {
		t.Fatal("a document layer ran after the bootstrap won")
	}
	var last Attempt
	for _, a := range res.Attempts {
		if a.Layer == 1 {
			last = a
		}
	}
	if last.Err != nil {
		t.Fatalf("bootstrap attempt failed: %v", last.Err)
	}
}

func TestChainBootstrapBadSignatureFallsThrough(t *testing.T) {
	priv := mustPriv(t)
	restore := swapKeys(t, 7, priv.Public().(ed25519.PublicKey))
	defer restore()

	// A valid record from a different key: signature must fail.
	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	foreign := sealBoot(t, []Server{{Host: "6.6.6.6", Port: 1}}, otherPriv)
	doc := seal(t, samplePayload(), nil, priv, 7)

	r := &Resolver{
		layers: []Source{
			DNSTXTSource{Record: "_gameserver.test", lookupTXT: fixedTXT(foreign)},
			&fakeSource{name: "after", raw: doc},
		},
		cache: newCache(""),
	}
	res, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != "after" {
		t.Fatalf("forged bootstrap was used: source=%q addrs=%v", res.Source, res.Addrs)
	}
}

func fixedTXT(values ...string) func(context.Context, *net.Resolver, string) ([]string, error) {
	return func(context.Context, *net.Resolver, string) ([]string, error) { return values, nil }
}

func TestChainBootstrapFailureFallsThrough(t *testing.T) {
	priv := mustPriv(t)
	restore := swapKeys(t, 7, priv.Public().(ed25519.PublicKey))
	defer restore()
	doc := seal(t, samplePayload(), nil, priv, 7)

	// A malformed record must not abort the chain; the next layer answers.
	bad := DNSTXTSource{Record: "not a record name", Timeout: time.Millisecond}
	r := &Resolver{
		layers: []Source{bad, &fakeSource{name: "after", raw: doc}},
		cache:  newCache(""),
	}
	res, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != "after" {
		t.Fatalf("source = %q", res.Source)
	}
}

func TestChainFreshCacheShortCircuitsEverything(t *testing.T) {
	priv := mustPriv(t)
	restore := swapKeys(t, 7, priv.Public().(ed25519.PublicKey))
	defer restore()

	path := t.TempDir() + "/servers.json"
	newCache(path).store(seal(t, samplePayload(), nil, priv, 7))

	probeSeed := mustListen(t)
	layer := &fakeSource{name: "L1", raw: []byte("never")}
	r := &Resolver{
		layers: []Source{layer},
		cache:  newCache(path),
		seeds:  []SeedSource{probeSeed},
	}
	res, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Cached || res.Layer != -1 {
		t.Fatalf("cached=%v layer=%d", res.Cached, res.Layer)
	}
	if layer.calls.Load() != 0 {
		t.Fatal("a layer ran despite a fresh cache")
	}
}

func TestChainExpiredCacheIsFallbackOnly(t *testing.T) {
	priv := mustPriv(t)
	restore := swapKeys(t, 7, priv.Public().(ed25519.PublicKey))
	defer restore()

	old := samplePayload()
	old.ExpiresAt = time.Now().Add(-time.Hour)
	old.Servers = []Server{{Host: "10.1.1.1", Port: 1}}

	path := t.TempDir() + "/servers.json"
	newCache(path).store(seal(t, old, nil, priv, 7))

	fresh := samplePayload()
	fresh.Servers = []Server{{Host: "10.9.9.9", Port: 2}}

	// With a working layer, the fresh document wins over the expired cache.
	r := &Resolver{
		layers: []Source{&fakeSource{name: "L1", raw: seal(t, fresh, nil, priv, 7)}},
		cache:  newCache(path),
	}
	res, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Cached || res.Stale || res.Addrs[0] != "10.9.9.9:2" {
		t.Fatalf("cached=%v stale=%v addrs=%v", res.Cached, res.Stale, res.Addrs)
	}

	// With every layer down, the expired cache is still better than nothing.
	r2 := &Resolver{
		layers: []Source{&fakeSource{name: "L1", err: errors.New("offline")}},
		cache:  newCache(path),
	}
	res2, err := r2.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !res2.Cached {
		t.Fatal("expired cache was not used as a fallback")
	}
}

func TestChainAllLayersFailNamesEachCause(t *testing.T) {
	r := &Resolver{layers: []Source{
		&fakeSource{name: "github", err: errors.New("dial tcp: timeout")},
		&fakeSource{name: "mirror", err: errors.New("status 503")},
	}, cache: newCache("")}

	_, err := r.Resolve(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"github", "timeout", "mirror", "status 503"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error lost %q: %v", want, err)
		}
	}
}

// Layer 1 — static IP: the request must reach the given IP with the given Host
// and SNI, with no DNS lookup for that name.
func TestLayer1StaticIPIgnoresDNS(t *testing.T) {
	priv := mustPriv(t)
	doc := seal(t, samplePayload(), nil, priv, 7)
	restore := swapKeys(t, 7, priv.Public().(ed25519.PublicKey))
	defer restore()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "raw.githubusercontent.com" {
			t.Errorf("Host = %q, want the real hostname", r.Host)
		}
		if !strings.HasPrefix(r.URL.Path, "/o/r/main/") {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write(doc)
	}))
	defer srv.Close()

	ip, _, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	if net.ParseIP(ip) == nil {
		t.Fatalf("test server URL is not an IP literal: %v", srv.URL)
	}
	// The test certificate is for 127.0.0.1, so the handshake fails; the point
	// is that no DNS lookup for "raw.githubusercontent.com" happened.
	src := StaticHostSource{IP: ip, Host: "raw.githubusercontent.com", Path: "/o/r/main/servers.json", Timeout: 2 * time.Second}
	_, err := src.Fetch(context.Background())
	if err != nil && (strings.Contains(err.Error(), "no such host") || strings.Contains(err.Error(), "lookup")) {
		t.Fatalf("static layer performed a DNS lookup: %v", err)
	}
}

func TestLayer1RejectsNonIP(t *testing.T) {
	src := StaticHostSource{IP: "raw.githubusercontent.com", Host: "raw.githubusercontent.com", Path: "/x"}
	if _, err := src.Fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "not an IP") {
		t.Fatalf("err = %v", err)
	}
}

// Layer 2/3 — filtered answers must never be connected to.
func TestFilteredDNSAnswerIsNotUsed(t *testing.T) {
	for _, bad := range []string{"10.10.34.36", "127.0.0.1", "0.0.0.0", "192.168.0.1"} {
		if len(plausible([]string{bad})) != 0 {
			t.Fatalf("%s was accepted as a real answer", bad)
		}
	}
	good := plausible([]string{"10.10.34.36", "185.199.108.133"})
	if len(good) != 1 || good[0] != "185.199.108.133" {
		t.Fatalf("mixed answer = %v", good)
	}
}

// Layer 4 — the record must fit one DNS string.
func TestLayer4FitsOneRecord(t *testing.T) {
	priv := mustPriv(t)
	for _, n := range []int{1, 2, 3} {
		srvs := make([]Server, n)
		for i := range srvs {
			srvs[i] = Server{Host: "62.220.127.2" + strconv.Itoa(i), Port: 30001}
		}
		rec := sealBoot(t, srvs, priv)
		if len(rec) > 255 {
			t.Fatalf("%d servers = %d chars, will not fit one TXT string", n, len(rec))
		}
	}
}

// Layer 4 — the bootstrap is signed, so a poisoned DNS cannot swap an address.
func TestLayer4TamperedRecordIsRejected(t *testing.T) {
	priv := mustPriv(t)
	restore := swapKeys(t, 7, priv.Public().(ed25519.PublicKey))
	defer restore()

	rec := sealBoot(t, []Server{{Host: "62.220.127.238", Port: 30001}}, priv)
	raw, err := decodeTXTDocument(rec)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a ciphertext byte; the signature must reject it before decryption.
	raw[len(raw)/2] ^= 0x01
	if _, err := ParseBootstrap(base64.RawURLEncoding.EncodeToString(raw), Descriptor(), Keys); !errors.Is(err, ErrSignature) {
		t.Fatalf("err = %v, want ErrSignature", err)
	}
}

// Layer 5 — the relay answer is unwrapped from its JSON envelope.
func TestLayer5UnwrapsRelayEnvelope(t *testing.T) {
	priv := mustPriv(t)
	doc := seal(t, samplePayload(), nil, priv, 7)
	restore := swapKeys(t, 7, priv.Public().(ed25519.PublicKey))
	defer restore()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		env, err := json.Marshal(map[string]string{"d": string(doc)})
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = w.Write(env)
	}))
	defer srv.Close()

	src := AppsScriptSource{URL: srv.URL + "/exec", Timeout: 2 * time.Second}
	body, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseEnvelope(body, Descriptor(), Keys); err != nil {
		t.Fatalf("unwrapped body is not a valid document: %v", err)
	}
}

func mustListen(t *testing.T) SeedSource {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	host, port, _ := net.SplitHostPort(l.Addr().String())
	p, _ := strconv.Atoi(port)
	return SeedSource{Host: host, Port: p}
}
