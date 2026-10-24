package catnet

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func sealBoot(t *testing.T, srvs []Server, priv ed25519.PrivateKey) string {
	t.Helper()
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	s, err := SealBootstrap(srvs, nonce, Descriptor(), 7, priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestBootstrapRoundTrip(t *testing.T) {
	priv := mustPriv(t)
	restore := swapKeys(t, 7, priv.Public().(ed25519.PublicKey))
	defer restore()

	srvs := []Server{
		{Host: "62.220.127.238", Port: 30001, Tag: "primary", Weight: 100},
		{Host: "203.0.113.7", Port: 30001, Tag: "backup", Weight: 50},
	}
	rec := sealBoot(t, srvs, priv)
	if len(rec) > 255 {
		t.Fatalf("bootstrap is %d chars, will not fit one TXT string", len(rec))
	}
	got, err := ParseBootstrap(rec, Descriptor(), Keys)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Addr() != "62.220.127.238:30001" {
		t.Fatalf("got %+v", got)
	}
}

func TestBootstrapIsOpaque(t *testing.T) {
	priv := mustPriv(t)
	rec := sealBoot(t, []Server{{Host: "62.220.127.238", Port: 30001}}, priv)
	for _, needle := range []string{"62.220.127.238", "30001"} {
		if strings.Contains(rec, needle) {
			t.Fatalf("record leaks %q", needle)
		}
	}
	raw, err := base64.RawURLEncoding.DecodeString(rec)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "62.220") {
		t.Fatal("decoded record leaks the address")
	}
}

func TestBootstrapTamperRejected(t *testing.T) {
	priv := mustPriv(t)
	restore := swapKeys(t, 7, priv.Public().(ed25519.PublicKey))
	defer restore()
	rec := sealBoot(t, []Server{{Host: "62.220.127.238", Port: 30001}}, priv)

	raw, _ := base64.RawURLEncoding.DecodeString(rec)
	raw[len(raw)/2] ^= 0xff
	tampered := base64.RawURLEncoding.EncodeToString(raw)
	if _, err := ParseBootstrap(tampered, Descriptor(), Keys); err == nil {
		t.Fatal("tampered bootstrap accepted")
	}
}

func TestBootstrapWrongDescriptorRejected(t *testing.T) {
	priv := mustPriv(t)
	restore := swapKeys(t, 7, priv.Public().(ed25519.PublicKey))
	defer restore()
	rec := sealBoot(t, []Server{{Host: "1.2.3.4", Port: 1}}, priv)
	other := make([]byte, 32)
	other[0] = 9
	if _, err := ParseBootstrap(rec, other, Keys); err == nil {
		t.Fatal("bootstrap decrypted with the wrong descriptor")
	}
}

func TestBootstrapRejectsPlainAddressList(t *testing.T) {
	// The old unsigned format must not be accepted: that is the whole point.
	if _, err := ParseBootstrap("62.220.127.238:30001", Descriptor(), Keys); err == nil {
		t.Fatal("plain address list accepted as a bootstrap")
	}
}

func TestBootstrapRejectsUnknownKid(t *testing.T) {
	priv := mustPriv(t)
	rec := sealBoot(t, []Server{{Host: "1.2.3.4", Port: 1}}, priv)
	// Signing with kid 7 but verifying against an empty trust set.
	if _, err := ParseBootstrap(rec, Descriptor(), SigningKeys{}); err == nil {
		t.Fatal("unknown kid accepted")
	}
}
