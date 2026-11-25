package main

import (
	"encoding/json"
	"path/filepath"
	"testing"

	catnet "github.com/mrfelfel/the-cat-network-base/lib"
)

// The desktop parses this JSON in C++ with no schema, so the field names are
// the contract. Renaming one silently breaks address discovery in a build
// nobody thought to re-test, so pin them here.

func TestParseSeeds(t *testing.T) {
	got := parseSeeds("62.220.127.238:30001, 10.0.0.1:443 ,bad,,host:notaport,1.2.3.4:70000")
	if len(got) != 2 {
		t.Fatalf("want 2 valid seeds, got %d: %v", len(got), got)
	}
	if got[0].Host != "62.220.127.238" || got[0].Port != 30001 {
		t.Errorf("seed 0 = %+v", got[0])
	}
	if got[1].Host != "10.0.0.1" || got[1].Port != 443 {
		t.Errorf("seed 1 = %+v", got[1])
	}
}

func TestParseSeedsEmpty(t *testing.T) {
	if got := parseSeeds(""); len(got) != 0 {
		t.Errorf("want no seeds, got %v", got)
	}
}

func TestCachePathSeparatesDocuments(t *testing.T) {
	a := cachePathFor("/tmp/c", "servers.json")
	b := cachePathFor("/tmp/c", "servers-v2.json")
	if a == b {
		t.Fatalf("two documents share a cache path: %q", a)
	}
	if filepath.Dir(a) != "/tmp/c" || filepath.Dir(b) != "/tmp/c" {
		t.Errorf("cache path left the given directory: %q %q", a, b)
	}
	if got := cachePathFor("", "servers.json"); got != "" {
		t.Errorf("empty dir should disable the cache, got %q", got)
	}
}

func TestEncodeConfigFieldNames(t *testing.T) {
	direct := true
	cfg := &catnet.Config{
		Payments: &catnet.PaymentsConfig{
			Mode_:         catnet.ModeConfig,
			DirectEnabled: &direct,
		},
		Support: &catnet.SupportConfig{Phone: "+982187210128"},
		URLs: &catnet.URLsConfig{
			Base:          "https://catroom.ir",
			UpdateChannel: "https://cr0.ir/news",
			CheckoutHost:  "cr0.ir",
		},
	}

	b, err := json.Marshal(encodeConfig(cfg, "standalone"))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}

	urls, ok := got["urls"].(map[string]any)
	if !ok {
		t.Fatalf("config lost its urls object: %s", b)
	}
	for _, k := range []string{"base", "update_channel", "checkout_host"} {
		if _, ok := urls[k]; !ok {
			t.Errorf("urls.%s missing from %s", k, b)
		}
	}
	pay, ok := got["payments"].(map[string]any)
	if !ok {
		t.Fatalf("config lost its payments object: %s", b)
	}
	if pay["mode"] != catnet.ModeConfig {
		t.Errorf("payments.mode = %v", pay["mode"])
	}
	if pay["direct_enabled"] != true {
		t.Errorf("payments.direct_enabled = %v", pay["direct_enabled"])
	}
}

// A document with no config must report nothing at all, so the caller keeps its
// compiled-in defaults instead of reading empty strings as real values.
func TestEncodeConfigNilWhenAbsent(t *testing.T) {
	if got := encodeConfig(nil, "standalone"); got != nil {
		t.Errorf("nil config encoded as %v", got)
	}
	if got := encodeConfig(&catnet.Config{}, "standalone"); got != nil {
		t.Errorf("empty config encoded as %v", got)
	}
}

func TestEncodeServersKeepsAddressFields(t *testing.T) {
	got := encodeServers([]catnet.Server{{Host: "1.2.3.4", Port: 30001, Tag: "primary", Weight: 100}})
	if len(got) != 1 {
		t.Fatalf("want 1 server, got %d", len(got))
	}
	if got[0].Host != "1.2.3.4" || got[0].Port != 30001 {
		t.Errorf("server = %+v", got[0])
	}
}
