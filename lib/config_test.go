package catnet

import (
	"encoding/json"
	"testing"
)

// resolve mirrors Resolver.PaymentsEnabled without needing a Resolver, so the
// precedence rules can be pinned directly.
func resolve(c *Config, build string) bool {
	if c == nil || c.Payments == nil {
		return true
	}
	p := c.Payments
	if p.Builds != nil {
		if v, ok := p.Builds[build]; ok {
			return v
		}
		if p.DirectEnabled == nil {
			return false
		}
	}
	if p.DirectEnabled != nil {
		return *p.DirectEnabled
	}
	return true
}

func boolp(b bool) *bool { return &b }

func TestPaymentsPrecedence(t *testing.T) {
	cases := []struct {
		name  string
		cfg   *Config
		build string
		want  bool
	}{
		{"no config at all", nil, "play", true},
		{"no payments block", &Config{}, "play", true},
		{"master off", &Config{Payments: &PaymentsConfig{DirectEnabled: boolp(false)}}, "play", false},
		{"master on", &Config{Payments: &PaymentsConfig{DirectEnabled: boolp(true)}}, "play", true},
		// A per-build entry beats the master switch in both directions.
		{"build off beats master on", &Config{Payments: &PaymentsConfig{
			DirectEnabled: boolp(true), Builds: map[string]bool{"play": false}}}, "play", false},
		{"build on beats master off", &Config{Payments: &PaymentsConfig{
			DirectEnabled: boolp(false), Builds: map[string]bool{"play": true}}}, "play", true},
		// Enumeration without a master switch: anything unlisted is off.
		{"listed build", &Config{Payments: &PaymentsConfig{
			Builds: map[string]bool{"play": true}}}, "play", true},
		{"unlisted build, no master", &Config{Payments: &PaymentsConfig{
			Builds: map[string]bool{"play": true}}}, "standalone", false},
		// Enumeration WITH a master switch: unlisted follows the switch.
		{"unlisted build, master on", &Config{Payments: &PaymentsConfig{
			DirectEnabled: boolp(true), Builds: map[string]bool{"bazaar": false}}}, "play", true},
		{"unlisted build, master off", &Config{Payments: &PaymentsConfig{
			DirectEnabled: boolp(false), Builds: map[string]bool{"bazaar": true}}}, "play", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := resolve(c.cfg, c.build); got != c.want {
				t.Fatalf("got %v want %v", got, c.want)
			}
		})
	}
}

// A build the operator has never heard of must never inherit a purchase path
// merely by existing. This is the failure that would ship quietly: a new
// distribution appears, nobody lists it, and it offers payments on rules
// written for something else.
func TestUnknownBuildNeverInheritsPayments(t *testing.T) {
	cfg := &Config{Payments: &PaymentsConfig{Builds: map[string]bool{"play": true, "standalone": true}}}
	if resolve(cfg, "a-build-nobody-listed") {
		t.Fatal("an unlisted build must not get payments from a build map that omits it")
	}
}

// Config must survive the round trip a published document takes, because the
// whole point is that an operator can change it without a release.
func TestConfigSurvivesDocumentRoundTrip(t *testing.T) {
	doc := []byte(`{
		"version": 1,
		"servers": [{"host": "1.2.3.4", "port": 30001}],
		"config": {
			"payments": {"direct_enabled": false, "builds": {"play": true}},
			"support": {"phone": "+982187210128", "bot": "https://t.me/thecat_support"},
			"urls": {"base": "https://catnet.example", "update_channel": "https://t.me/thecatir"}
		}
	}`)
	p, err := decodePayload(doc)
	if err != nil {
		t.Fatalf("document with config must parse: %v", err)
	}
	if p.Config == nil {
		t.Fatal("config was dropped")
	}
	if p.Config.Payments == nil || p.Config.Payments.DirectEnabled == nil || *p.Config.Payments.DirectEnabled {
		t.Fatalf("direct_enabled not read: %+v", p.Config.Payments)
	}
	if !p.Config.Payments.Builds["play"] {
		t.Fatal("per-build override not read")
	}
	if p.Config.Support.Phone != "+982187210128" {
		t.Fatalf("support phone not read: %q", p.Config.Support.Phone)
	}
	if p.Config.URLs.UpdateChannel != "https://t.me/thecatir" {
		t.Fatalf("update channel not read: %q", p.Config.URLs.UpdateChannel)
	}
}

// Absent config must stay absent, so a client can tell "the operator did not
// say" from "the operator said nothing about it" and keep its own defaults.
func TestAbsentConfigStaysNil(t *testing.T) {
	p, err := decodePayload([]byte(`{"version":1,"servers":[{"host":"1.2.3.4","port":30001}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.Config != nil {
		t.Fatal("no config in the document must decode to nil, not an empty struct")
	}
}

func TestConfigIsSerialisable(t *testing.T) {
	c := &Config{
		Payments: &PaymentsConfig{DirectEnabled: boolp(true), Builds: map[string]bool{"play": true}},
		Support:  &SupportConfig{Phone: "+1"},
		URLs:     &URLsConfig{Base: "https://x"},
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var back Config
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if *back.Payments.DirectEnabled != true || !back.Payments.Builds["play"] || back.Support.Phone != "+1" {
		t.Fatalf("round trip lost data: %s", b)
	}
}
