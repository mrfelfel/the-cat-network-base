package catnet

import (
	"encoding/json"
	"strings"
	"testing"
)

// These tests pin the compatibility contract of the published document, because
// getting it wrong is unrecoverable: a client that cannot parse the document
// falls back to the seed and loses address discovery, and there is no way to
// reach it to fix that.

// A document that carries fields this build has never heard of must still be
// readable. This is the whole reason unknown fields are tolerated: the fleet is
// updated on its own schedule, so new configuration has to be publishable
// before every client knows about it.
func TestNewFieldsAreIgnored(t *testing.T) {
	doc := []byte(`{
		"version": 1,
		"servers": [{"host": "1.2.3.4", "port": 30001}],
		"payments": {"direct_enabled": true},
		"support": {"phone": "+982112345678"},
		"a_field_from_the_future": [1, 2, 3]
	}`)
	var p Payload
	if err := json.Unmarshal(doc, &p); err != nil {
		t.Fatalf("unknown fields must not fail the parse: %v", err)
	}
	if len(p.Servers) != 1 || p.Servers[0].Host != "1.2.3.4" {
		t.Fatalf("known fields must still be read, got %+v", p.Servers)
	}
}

// The tolerance must not extend to documents this build cannot understand at
// all: an object made entirely of unknown fields, or an empty one, would
// otherwise decode to an all-zero Payload that looks valid.
func TestDocumentWithNoKnownFieldsIsRejected(t *testing.T) {
	for name, doc := range map[string][]byte{
		"empty object":   []byte(`{}`),
		"only unknown":   []byte(`{"future_thing": 1}`),
		"not an object":  []byte(`[1,2,3]`),
	} {
		t.Run(name, func(t *testing.T) {
			if knownFieldsPresent(doc) {
				t.Fatalf("%s must not count as a known document", name)
			}
		})
	}
}

// Version is the one signal that a change was NOT additive. A newer document
// must be refused rather than best-effort read, or a future meaning would be
// interpreted with this build's assumptions.
func TestNewerVersionIsRejected(t *testing.T) {
	p := Payload{Version: ProtocolVersion + 1, Servers: []Server{{Host: "1.2.3.4", Port: 1}}}
	err := p.validate()
	if err == nil {
		t.Fatal("a newer payload version must be rejected")
	}
	if !strings.Contains(err.Error(), "newer than this client") {
		t.Fatalf("the error should say the document is too new, got: %v", err)
	}
}

// The ordinary case: the document this build publishes today must keep parsing
// exactly as before.
func TestCurrentDocumentStillParses(t *testing.T) {
	p := Payload{Version: ProtocolVersion, Servers: []Server{{Host: "1.2.3.4", Port: 30001, Tag: "primary", Weight: 100}}}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if !knownFieldsPresent(raw) {
		t.Fatal("a document this build produced must be recognised")
	}
	got, err := decodePayload(raw)
	if err != nil {
		t.Fatalf("current document must parse: %v", err)
	}
	if len(got.Servers) != 1 || got.Servers[0].Addr() != "1.2.3.4:30001" {
		t.Fatalf("unexpected round trip: %+v", got.Servers)
	}
}
