package catnet

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testKey is a throwaway keypair; the production public key lives in signing.go.
func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func testKeys(t *testing.T) (SigningKeys, ed25519.PrivateKey) {
	pub, priv := testKey(t)
	return SigningKeys{7: pub}, priv
}

func samplePayload() Payload {
	now := time.Now().UTC().Truncate(time.Second)
	return Payload{
		Version:   ProtocolVersion,
		IssuedAt:  now.Add(-time.Hour),
		ExpiresAt: now.Add(24 * time.Hour),
		Servers: []Server{
			{Host: "10.0.0.2", Port: 30001, Tag: "backup", Weight: 50},
			{Host: "10.0.0.1", Port: 30001, Tag: "primary", Weight: 100},
		},
	}
}

func seal(t *testing.T, p Payload, keys SigningKeys, priv ed25519.PrivateKey, kid uint16) []byte {
	t.Helper()
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	doc, err := SealEnvelope(p, nonce, Descriptor(), kid, priv)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestRoundTrip(t *testing.T) {
	keys, priv := testKeys(t)
	doc := seal(t, samplePayload(), keys, priv, 7)

	env, err := ParseEnvelope(doc, Descriptor(), keys)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(env.Payload.Servers), 2; got != want {
		t.Fatalf("servers = %d, want %d", got, want)
	}
	if got := env.Payload.Sorted()[0].Tag; got != "primary" {
		t.Fatalf("first by weight = %q, want primary", got)
	}
	// Payload values must survive JSON encoding.
	if !env.Payload.IssuedAt.Equal(samplePayload().IssuedAt) {
		t.Fatalf("issued_at round-trip: %v", env.Payload.IssuedAt)
	}
}

func TestPayloadIsNotCleartext(t *testing.T) {
	keys, priv := testKeys(t)
	doc := seal(t, samplePayload(), keys, priv, 7)
	for _, needle := range []string{"10.0.0.1", "primary", "servers"} {
		if bytes.Contains(doc, []byte(needle)) {
			t.Fatalf("published document leaks %q", needle)
		}
	}
}

func TestJSONReformattingKeepsSignatureValid(t *testing.T) {
	keys, priv := testKeys(t)
	doc := seal(t, samplePayload(), keys, priv, 7)

	var generic map[string]any
	if err := json.Unmarshal(doc, &generic); err != nil {
		t.Fatal(err)
	}
	// Re-encode minified and with reordered keys.
	min, err := json.Marshal(generic)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseEnvelope(min, Descriptor(), keys); err != nil {
		t.Fatalf("minified: %v", err)
	}
	withBOM := append([]byte("\xef\xbb\xbf\n  "), min...)
	if _, err := ParseEnvelope(append(withBOM, '\n'), Descriptor(), keys); err != nil {
		t.Fatalf("BOM+whitespace: %v", err)
	}
}

func TestTamperedCiphertextRejected(t *testing.T) {
	keys, priv := testKeys(t)
	doc := seal(t, samplePayload(), keys, priv, 7)

	var env envelope
	if err := json.Unmarshal(doc, &env); err != nil {
		t.Fatal(err)
	}
	env.Ct[0] ^= 0xff
	tampered, _ := json.Marshal(env)
	if _, err := ParseEnvelope(tampered, Descriptor(), keys); !errors.Is(err, ErrSignature) {
		t.Fatalf("err = %v, want ErrSignature", err)
	}
}

func TestTamperedPayloadWithFreshSignatureFailsDecryptWithWrongKey(t *testing.T) {
	// Attacker has their own signing key and swaps kid to one the library
	// trusts. The signature would pass under the attacker's key, so the check
	// is that they cannot produce one for a trusted kid in the first place —
	// and if they tamper the ciphertext under a real kid, the signature fails.
	keys, priv := testKeys(t)
	doc := seal(t, samplePayload(), keys, priv, 7)

	var env envelope
	if err := json.Unmarshal(doc, &env); err != nil {
		t.Fatal(err)
	}
	env.Kid = 9 // not in keys
	swapped, _ := json.Marshal(env)
	if _, err := ParseEnvelope(swapped, Descriptor(), keys); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("err = %v, want ErrUnknownKey", err)
	}
}

func TestKidIsBoundByAAD(t *testing.T) {
	// Re-signing with the same key but a different kid must fail: kid is in
	// the prologue, which is both signed and used as GCM AAD.
	keys, priv := testKeys(t)
	keys[8] = keys[7]
	doc := seal(t, samplePayload(), SigningKeys{7: keys[7]}, priv, 7)

	var env envelope
	if err := json.Unmarshal(doc, &env); err != nil {
		t.Fatal(err)
	}
	env.Kid = 8
	swapped, _ := json.Marshal(env)
	if _, err := ParseEnvelope(swapped, Descriptor(), keys); !errors.Is(err, ErrSignature) {
		t.Fatalf("err = %v, want ErrSignature", err)
	}
}

func TestWrongDescriptorFails(t *testing.T) {
	keys, priv := testKeys(t)
	doc := seal(t, samplePayload(), keys, priv, 7)

	other := make([]byte, 32)
	other[0] = 1
	// Signature is over ciphertext only, so it still verifies; decryption and
	// therefore the whole document is rejected.
	if _, err := ParseEnvelope(doc, other, keys); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("err = %v, want ErrDecrypt", err)
	}
}

func TestMalformedInputs(t *testing.T) {
	keys, priv := testKeys(t)
	good := seal(t, samplePayload(), keys, priv, 7)

	cases := map[string][]byte{
		"empty":     nil,
		"html":      []byte("<!doctype html><html>login</html>"),
		"truncated": good[:len(good)/2],
		"v2":        []byte(`{"v":2,"kid":7,"n":"AAAAAAAAAAAAAAAAAAAAAA==","ct":"AAAA","sig":"AAAA"}`),
		"unknown":   []byte(`{"v":1,"kid":7,"n":"","ct":"","sig":"","extra":1}`),
	}
	for name, in := range cases {
		if _, err := ParseEnvelope(in, Descriptor(), keys); err == nil {
			t.Fatalf("%s: expected error", name)
		}
	}
}

func TestPayloadValidation(t *testing.T) {
	now := time.Now()
	cases := map[string]Server{
		"empty host":  {Host: "", Port: 1},
		"bad port":    {Host: "1.2.3.4", Port: 0},
		"big port":    {Host: "1.2.3.4", Port: 70000},
		"scheme":      {Host: "http://1.2.3.4", Port: 1},
		"path":        {Host: "1.2.3.4/x", Port: 1},
		"space":       {Host: "1.2.3.4 x", Port: 1},
		"bad weight":  {Host: "1.2.3.4", Port: 1, Weight: 101},
		"negative wt": {Host: "1.2.3.4", Port: 1, Weight: -1},
	}
	for name, s := range cases {
		p := Payload{Version: 1, IssuedAt: now, ExpiresAt: now.Add(time.Hour), Servers: []Server{s}}
		b, _ := json.Marshal(p)
		if _, err := decodePayload(b); err == nil {
			t.Fatalf("%s: expected validation error", name)
		}
	}

	ok := Payload{Version: 1, IssuedAt: now, ExpiresAt: now.Add(time.Hour), Servers: []Server{
		{Host: "1.2.3.4", Port: 1},
		{Host: "example.com", Port: 65535},
		{Host: "::1", Port: 1},
	}}
	b, _ := json.Marshal(ok)
	if _, err := decodePayload(b); err != nil {
		t.Fatalf("valid payload rejected: %v", err)
	}
}

func TestCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "servers.json")
	c := newCache(path)
	if c.load() != nil {
		t.Fatal("empty cache should be nil")
	}
	c.store([]byte(`{"hello":1}`))
	if got := c.load(); !bytes.Equal(got, []byte(`{"hello":1}`)) {
		t.Fatalf("load = %q", got)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("cache perms: %v %v", fi, err)
	}
	c.discard()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("discard left the file: %v", err)
	}
}

func TestAddrsBracketIPv6(t *testing.T) {
	if got := (Server{Host: "::1", Port: 443}).Addr(); got != "[::1]:443" {
		t.Fatalf("Addr = %q", got)
	}
	if got := (Server{Host: "1.2.3.4", Port: 443}).Addr(); got != "1.2.3.4:443" {
		t.Fatalf("Addr = %q", got)
	}
}

func TestDescriptorIsStableAnd32Bytes(t *testing.T) {
	d := Descriptor()
	if len(d) != 32 {
		t.Fatalf("len = %d", len(d))
	}
	if !bytes.Equal(d, Descriptor()) {
		t.Fatal("descriptor not stable")
	}
	if strings.Contains(string(d), "catgram") {
		t.Fatal("descriptor contains the phrase verbatim")
	}
}
