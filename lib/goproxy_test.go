package catnet

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func zipWith(t *testing.T, prefix string, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(prefix + "/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func proxyServer(t *testing.T, module string, z []byte, version string) *httptest.Server {
	t.Helper()
	esc := escapeModule(module)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/" + esc + "/@latest":
			_ = json.NewEncoder(w).Encode(map[string]string{"Version": version})
		case "/" + esc + "/@v/" + version + ".zip":
			_, _ = w.Write(z)
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestGoProxyExtractsTheDocument(t *testing.T) {
	priv := mustPriv(t)
	restore := swapKeys(t, 7, priv.Public().(ed25519.PublicKey))
	defer restore()

	doc := seal(t, samplePayload(), nil, priv, 7)
	module := "github.com/Example/the-cat-network-base"
	z := zipWith(t, module+"@v1.0.0", map[string][]byte{
		"go.mod":       []byte("module " + module),
		"servers.json": doc,
		"README.md":    []byte("readme"),
	})
	srv := proxyServer(t, module, z, "v1.0.0")
	defer srv.Close()

	src := GoProxySource{Base: srv.URL, Module: module, Timeout: 5 * time.Second}
	body, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != string(doc) {
		t.Fatalf("extracted %d bytes, want %d", len(body), len(doc))
	}
	if _, err := ParseEnvelope(body, Descriptor(), Keys); err != nil {
		t.Fatalf("extracted document does not verify: %v", err)
	}
}

func TestGoProxyEscapesUppercaseModule(t *testing.T) {
	// Go's proxy spec escapes uppercase as "!lower"; the server above only
	// answers the escaped path, so a failure here means the escaping is wrong.
	cases := map[string]string{
		"github.com/mrfelfel/the-cat-network-base": "github.com/mrfelfel/the-cat-network-base",
		"github.com/Example/Repo":                  "github.com/!example/!repo",
		"github.com/a/B/c/D":                       "github.com/a/!b/c/!d",
	}
	for in, want := range cases {
		if got := escapeModule(in); got != want {
			t.Fatalf("%s -> %s, want %s", in, got, want)
		}
	}
}

func TestGoProxyMissingFileFails(t *testing.T) {
	z := zipWith(t, "m@v1", map[string][]byte{"go.mod": []byte("x")})
	srv := proxyServer(t, "m", z, "v1")
	defer srv.Close()

	src := GoProxySource{Base: srv.URL, Module: "m", File: "servers.json", Timeout: 5 * time.Second}
	if _, err := src.Fetch(context.Background()); err == nil {
		t.Fatal("expected an error for a missing member")
	}
}

func TestGoProxyRejectsHugeMember(t *testing.T) {
	big := bytes.Repeat([]byte("A"), maxMember+1)
	z := zipWith(t, "m@v1", map[string][]byte{"servers.json": big})
	srv := proxyServer(t, "m", z, "v1")
	defer srv.Close()

	src := GoProxySource{Base: srv.URL, Module: "m", Timeout: 5 * time.Second}
	if _, err := src.Fetch(context.Background()); err == nil {
		t.Fatal("expected an error for an oversized member")
	}
}

func TestGoProxyPinnedVersionSkipsLatest(t *testing.T) {
	doc := []byte(`{"pinned":true}`)
	z := zipWith(t, "m@v2.0.0", map[string][]byte{"servers.json": doc})
	var latestHit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/m/@latest" {
			latestHit = true
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(z)
	}))
	defer srv.Close()

	src := GoProxySource{Base: srv.URL, Module: "m", Version: "v2.0.0", Timeout: 5 * time.Second}
	body, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if latestHit {
		t.Fatal("@latest was queried despite a pinned version")
	}
	if string(body) != string(doc) {
		t.Fatalf("body = %q", body)
	}
}

func TestGoProxyLayerSitsAfterStaticIP(t *testing.T) {
	r := Build(Options{
		Repo:      "o/r",
		GoProxies: []string{"https://package-mirror.liara.ir/repository/go"},
	})
	names := r.Sources()
	var staticIdx, proxyIdx, dnsIdx = -1, -1, -1
	for i, n := range names {
		switch {
		case staticIdx < 0 && len(n) > 7 && n[:7] == "static:":
			staticIdx = i
		case proxyIdx < 0 && len(n) > 8 && n[:8] == "goproxy:":
			proxyIdx = i
		case dnsIdx < 0 && n == "dns":
			dnsIdx = i
		}
	}
	if staticIdx < 0 || proxyIdx < 0 || dnsIdx < 0 {
		t.Fatalf("missing layers: %v", names)
	}
	if !(staticIdx < proxyIdx && proxyIdx < dnsIdx) {
		t.Fatalf("goproxy must sit between static IP and DNS: %v", names)
	}
}
