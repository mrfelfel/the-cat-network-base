package catnet

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func registryPayload() Payload {
	p := samplePayload()
	p.GitHubIPs = []string{"203.0.113.50"}
	p.Mirrors = []MirrorHost{{IP: "203.0.113.51", Host: "mirror.example", Path: "/s.json"}}
	p.Resolvers = []string{"10.202.10.202:53", "dot:1.1.1.1"}
	p.DNSTXT = "_catnet.example"
	p.AppsScript = "https://script.google.com/macros/s/x/exec"
	return p
}

func TestLearnPersistsAndRebuildsLayers(t *testing.T) {
	priv := mustPriv(t)
	restore := swapKeys(t, 7, priv.Public().(ed25519.PublicKey))
	defer restore()

	dir := t.TempDir()
	cachePath := filepath.Join(dir, "servers.json")
	doc := seal(t, registryPayload(), nil, priv, 7)

	r := Build(Options{Repo: "o/r", CachePath: cachePath})
	r.layers = []Source{&fakeSource{name: "only", raw: doc}}
	// Clear the learned file so Build's own load does not interfere.
	if _, err := r.Resolve(context.Background()); err != nil {
		t.Fatal(err)
	}

	regPath := cachePath + ".registry.json"
	b, err := os.ReadFile(regPath)
	if err != nil {
		t.Fatalf("registry not written: %v", err)
	}
	var lr learnedRegistry
	if err := json.Unmarshal(b, &lr); err != nil {
		t.Fatal(err)
	}
	if len(lr.GitHubIPs) != 1 || lr.GitHubIPs[0] != "203.0.113.50" {
		t.Fatalf("learned github ips = %v", lr.GitHubIPs)
	}
	if lr.AppsScript == "" || lr.DNSTXT != "_catnet.example" {
		t.Fatalf("learned registry incomplete: %+v", lr)
	}
	if fi, err := os.Stat(regPath); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("registry perms: %v %v", fi, err)
	}

	// A fresh resolver must build its chain from the learned values.
	r2 := Build(Options{Repo: "o/r", CachePath: cachePath})
	names := strings.Join(r2.Sources(), " ")
	if !strings.Contains(names, "static:203.0.113.50") {
		t.Fatalf("learned github IP not used: %s", names)
	}
	if !strings.Contains(names, "static:203.0.113.51→mirror.example") {
		t.Fatalf("learned mirror not used: %s", names)
	}
	if !strings.Contains(names, "dns:_catnet.example") {
		t.Fatalf("learned TXT not used: %s", names)
	}
	if !strings.Contains(names, "apps-script:") {
		t.Fatalf("learned relay not used: %s", names)
	}
}

func TestCorruptRegistryIsIgnored(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "servers.json")
	if err := os.WriteFile(cachePath+".registry.json", []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := Build(Options{Repo: "o/r", CachePath: cachePath})
	if r.learned != nil {
		t.Fatal("corrupt registry was loaded")
	}
	// Falls back to the built-in defaults.
	if !strings.Contains(strings.Join(r.Sources(), " "), "static:185.199.108.133") {
		t.Fatal("defaults not used")
	}
}

func TestLearnSkipsPayloadWithoutRegistry(t *testing.T) {
	priv := mustPriv(t)
	restore := swapKeys(t, 7, priv.Public().(ed25519.PublicKey))
	defer restore()
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "servers.json")
	r := Build(Options{Repo: "o/r", CachePath: cachePath})
	r.layers = []Source{&fakeSource{name: "only", raw: seal(t, samplePayload(), nil, priv, 7)}}
	if _, err := r.Resolve(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cachePath + ".registry.json"); !os.IsNotExist(err) {
		t.Fatal("registry written for a payload with no registry fields")
	}
}

func TestRefreshBypassesFreshCache(t *testing.T) {
	priv := mustPriv(t)
	restore := swapKeys(t, 7, priv.Public().(ed25519.PublicKey))
	defer restore()

	dir := t.TempDir()
	cachePath := filepath.Join(dir, "servers.json")
	first := seal(t, samplePayload(), nil, priv, 7)

	r := Build(Options{Repo: "o/r", CachePath: cachePath})
	r.cache.store(first)

	// Without force, the fresh cache answers and the layer is untouched.
	layer := &fakeSource{name: "L1", err: errTestNoNetwork}
	r.layers = []Source{layer}
	res, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Cached || layer.calls.Load() != 0 {
		t.Fatalf("fresh cache was not used: cached=%v calls=%d", res.Cached, layer.calls.Load())
	}

	// Forced, the layer is tried even though the cache is fresh.
	updated := samplePayload()
	updated.Servers = []Server{{Host: "10.5.5.5", Port: 1}}
	layer.err = nil
	layer.raw = seal(t, updated, nil, priv, 7)
	res, err = r.refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Cached || res.Addrs[0] != "10.5.5.5:1" {
		t.Fatalf("refresh did not reach upstream: cached=%v addrs=%v", res.Cached, res.Addrs)
	}
}

func TestRefreshKeepsCacheOnFailure(t *testing.T) {
	priv := mustPriv(t)
	restore := swapKeys(t, 7, priv.Public().(ed25519.PublicKey))
	defer restore()

	dir := t.TempDir()
	cachePath := filepath.Join(dir, "servers.json")
	good := seal(t, samplePayload(), nil, priv, 7)
	r := Build(Options{Repo: "o/r", CachePath: cachePath})
	r.cache.store(good)
	r.layers = []Source{&fakeSource{name: "down", err: errTestNoNetwork}}

	// refresh with everything down still answers from the cache.
	res, err := r.refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Addrs[0] != "10.0.0.1:30001" {
		t.Fatalf("addrs = %v", res.Addrs)
	}
	if got := newCache(cachePath).load(); string(got) != string(good) {
		t.Fatal("cache was damaged by a failed refresh")
	}
}

func TestRefresherCallsBack(t *testing.T) {
	priv := mustPriv(t)
	restore := swapKeys(t, 7, priv.Public().(ed25519.PublicKey))
	defer restore()

	r := Build(Options{Repo: "o/r"})
	r.layers = []Source{&fakeSource{name: "L1", raw: seal(t, samplePayload(), nil, priv, 7)}}

	got := make(chan error, 1)
	f := &Refresher{Resolver: r, Interval: 20 * time.Millisecond, OnResult: func(_ *Result, err error) { got <- err }}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.Run(ctx); close(done) }()
	select {
	case err := <-got:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("refresher never fired")
	}
	cancel()
	<-done
}

var errTestNoNetwork = &testErr{"no network"}

type testErr struct{ s string }

func (e *testErr) Error() string { return e.s }
