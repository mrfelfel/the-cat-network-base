package catnet

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeSource returns fixed bytes, an error, or blocks until ctx is done.
type fakeSource struct {
	name  string
	raw   []byte
	err   error
	block bool
	calls atomic.Int32
}

func (f *fakeSource) Name() string { return f.name }
func (f *fakeSource) Fetch(ctx context.Context) ([]byte, error) {
	f.calls.Add(1)
	if f.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return f.raw, f.err
}

func resolverWith(t *testing.T, srcs ...Source) (*Resolver, SigningKeys, ed25519.PrivateKey) {
	t.Helper()
	keys, priv := testKeys(t)
	return &Resolver{sources: srcs, cache: newCache("")}, keys, priv
}

func TestResolveFirstValidSourceWins(t *testing.T) {
	priv := mustPriv(t)
	good := seal(t, samplePayload(), nil, priv, 7)
	r, _, _ := resolverWith(t)
	// ParseEnvelope uses the package Keys, so the resolver must too; swap in
	// the test key set for the duration of this test.
	restore := swapKeys(t, 7, priv.Public().(ed25519.PublicKey))

	r.sources = []Source{
		&fakeSource{name: "broken-html", raw: []byte("<html>")},
		&fakeSource{name: "blocked", err: errors.New("connection reset")},
		&fakeSource{name: "good", raw: good},
	}
	res, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer restore()
	if res.Source != "good" {
		t.Fatalf("source = %q", res.Source)
	}
	if len(res.Addrs) != 2 || res.Addrs[0] != "10.0.0.1:30001" {
		t.Fatalf("addrs = %v", res.Addrs)
	}
	if res.Stale {
		t.Fatal("unexpected stale")
	}
}

func mustPriv(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func swapKeys(t *testing.T, kid uint16, pub ed25519.PublicKey) func() {
	t.Helper()
	old := Keys
	Keys = SigningKeys{kid: pub}
	return func() { Keys = old }
}

func TestResolveCancelsSlowSources(t *testing.T) {
	priv := mustPriv(t)
	good := seal(t, samplePayload(), nil, priv, 7)
	restore := swapKeys(t, 7, priv.Public().(ed25519.PublicKey))
	defer restore()

	slow := &fakeSource{name: "slow", block: true}
	fast := &fakeSource{name: "fast", raw: good}
	r := &Resolver{sources: []Source{slow, fast}, cache: newCache("")}
	start := time.Now()
	res, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != "fast" {
		t.Fatalf("source = %q", res.Source)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("resolution waited for the slow source: %v", elapsed)
	}
}

func TestResolveAllFailNoCache(t *testing.T) {
	priv := mustPriv(t)
	restore := swapKeys(t, 7, priv.Public().(ed25519.PublicKey))
	defer restore()
	r := &Resolver{sources: []Source{
		&fakeSource{name: "a", err: errors.New("dial tcp: timeout")},
		&fakeSource{name: "b", raw: []byte("{}")},
	}, cache: newCache("")}
	if _, err := r.Resolve(context.Background()); err == nil {
		t.Fatal("expected error")
	} else if !strings.Contains(err.Error(), "dial tcp: timeout") {
		t.Fatalf("error lost the underlying cause: %v", err)
	}
}

func TestResolveFallsBackToExpiredCache(t *testing.T) {
	priv := mustPriv(t)
	restore := swapKeys(t, 7, priv.Public().(ed25519.PublicKey))
	defer restore()

	expired := samplePayload()
	expired.ExpiresAt = time.Now().Add(-time.Hour)
	doc := seal(t, expired, nil, priv, 7)

	path := filepath.Join(t.TempDir(), "servers.json")
	c := newCache(path)
	c.store(doc)

	r := &Resolver{sources: []Source{&fakeSource{name: "down", err: errors.New("offline")}}, cache: c}
	res, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Stale || !res.Cached {
		t.Fatalf("stale=%v cached=%v", res.Stale, res.Cached)
	}
	if res.Addrs[0] != "10.0.0.1:30001" {
		t.Fatalf("addrs = %v", res.Addrs)
	}
}

func TestResolvePrefersNetworkOverExpiredCache(t *testing.T) {
	priv := mustPriv(t)
	restore := swapKeys(t, 7, priv.Public().(ed25519.PublicKey))
	defer restore()

	old := samplePayload()
	old.ExpiresAt = time.Now().Add(-time.Hour)
	path := filepath.Join(t.TempDir(), "servers.json")
	c := newCache(path)
	c.store(seal(t, old, nil, priv, 7))

	fresh := samplePayload()
	fresh.Servers = []Server{{Host: "10.9.9.9", Port: 1}}
	freshDoc := seal(t, fresh, nil, priv, 7)

	r := &Resolver{sources: []Source{&fakeSource{name: "live", raw: freshDoc}}, cache: c}
	res, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Cached || res.Stale || res.Addrs[0] != "10.9.9.9:1" {
		t.Fatalf("cached=%v stale=%v addrs=%v", res.Cached, res.Stale, res.Addrs)
	}
	// The fresh document replaced the expired cache.
	if got := newCache(path).load(); string(got) != string(freshDoc) {
		t.Fatal("cache was not refreshed")
	}
}

func TestResolveCorruptCacheIsDiscarded(t *testing.T) {
	priv := mustPriv(t)
	restore := swapKeys(t, 7, priv.Public().(ed25519.PublicKey))
	defer restore()

	path := filepath.Join(t.TempDir(), "servers.json")
	if err := os.WriteFile(path, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	good := seal(t, samplePayload(), nil, priv, 7)
	r := &Resolver{sources: []Source{&fakeSource{name: "live", raw: good}}, cache: newCache(path)}
	if _, err := r.Resolve(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := newCache(path).load(); string(got) != string(good) {
		t.Fatal("corrupt cache was not replaced")
	}
}

func TestResolveDoesNotPoisonCacheFromFailedSource(t *testing.T) {
	priv := mustPriv(t)
	restore := swapKeys(t, 7, priv.Public().(ed25519.PublicKey))
	defer restore()
	path := filepath.Join(t.TempDir(), "servers.json")
	r := &Resolver{sources: []Source{&fakeSource{name: "evil", raw: []byte(`{"v":1}`)}}, cache: newCache(path)}
	if _, err := r.Resolve(context.Background()); err == nil {
		t.Fatal("expected error")
	}
	if got := newCache(path).load(); got != nil {
		t.Fatal("failed resolution wrote the cache")
	}
}

func TestHTTPMirrorFetchesAndRejectsStatus(t *testing.T) {
	priv := mustPriv(t)
	restore := swapKeys(t, 7, priv.Public().(ed25519.PublicKey))
	defer restore()
	doc := seal(t, samplePayload(), nil, priv, 7)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/servers.json" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("t") == "" {
			t.Error("CacheBust did not add ?t=")
		}
		w.Write(doc)
	}))
	defer srv.Close()

	r := &Resolver{sources: []Source{HTTPMirror{URL: srv.URL + "/servers.json", CacheBust: true}}, cache: newCache("")}
	res, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Source == "" || len(res.Addrs) != 2 {
		t.Fatalf("unexpected result: %+v", res)
	}

	r2 := &Resolver{sources: []Source{HTTPMirror{URL: srv.URL + "/missing.json"}}, cache: newCache("")}
	if _, err := r2.Resolve(context.Background()); err == nil {
		t.Fatal("expected 404 to fail")
	}
}

func TestBuildSourceOrder(t *testing.T) {
	r := Build(Options{
		Repo:    "o/r",
		DNSName: "_catnet.example",
		Seeds:   []SeedSource{{Host: "1.2.3.4", Port: 30001}},
	})
	got := r.Sources()
	want := []string{
		"http:raw.githubusercontent.com",
		"http:scorpian.ir",
		"http:cdn.jsdelivr.net",
		"http:ghproxy.net",
		"http:raw.githack.com",
		"dns:_catnet.example",
		"seed:1.2.3.4",
	}
	if len(got) != len(want) {
		t.Fatalf("sources = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("source[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
