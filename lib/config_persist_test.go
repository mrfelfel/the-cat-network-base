package catnet

import (
	"os"
	"path/filepath"
	"testing"
)

// A kill switch has to survive a restart with no network, so the config must
// come back from the learned file rather than only from a live resolve.
func TestConfigSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catnet.cache")

	b := false
	p := Payload{
		Version: ProtocolVersion,
		Config:  &Config{Payments: &PaymentsConfig{DirectEnabled: &b}},
	}
	storeLearned(path, p)

	back := loadLearned(path)
	if back == nil {
		t.Fatal("learned file did not load")
	}
	if back.Config == nil || back.Config.Payments == nil || back.Config.Payments.DirectEnabled == nil {
		t.Fatalf("config lost across restart: %+v", back.Config)
	}
	if *back.Config.Payments.DirectEnabled {
		t.Fatal("kill switch came back enabled")
	}
}

// A document that carries ONLY config must still be persisted: the kill switch
// has nothing to do with address discovery.
func TestConfigOnlyPayloadIsPersisted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catnet.cache")
	b := false
	storeLearned(path, Payload{Version: ProtocolVersion, Config: &Config{Payments: &PaymentsConfig{DirectEnabled: &b}}})
	if _, err := os.Stat(path); err != nil {
		t.Fatal("registry file was not written for a config-only payload")
	}
	if loadLearned(path).Config == nil {
		t.Fatal("config not persisted")
	}
}
