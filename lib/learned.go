package catnet

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// learnedRegistry is what the client remembers from the last verified payload:
// the addresses that worked, so the next run — including an offline one —
// starts from the operator's newest knowledge instead of the binary's baked-in
// constants.
//
// It is advisory only. Every value here is unsigned and untrusted; it shifts
// which endpoint is tried first, and a wrong entry costs a timeout, never a
// wrong answer, because the document itself is what carries the addresses and
// it is always signature-checked. A poisoned registry therefore cannot redirect
// the client — it can only make one layer fail, which is the same outcome as
// that layer being blocked.
type learnedRegistry struct {
	IssuedAt   string       `json:"issued_at"`
	GitHubIPs  []string     `json:"github_ips,omitempty"`
	Mirrors    []MirrorHost `json:"mirrors,omitempty"`
	Resolvers  []string     `json:"resolvers,omitempty"`
	ServerName string       `json:"server_name,omitempty"`
	AppsScript string       `json:"apps_script,omitempty"`
}

func loadLearned(path string) *Payload {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var lr learnedRegistry
	if err := json.Unmarshal(b, &lr); err != nil {
		return nil
	}
	return &Payload{
		Version:    ProtocolVersion,
		GitHubIPs:  lr.GitHubIPs,
		Mirrors:    lr.Mirrors,
		Resolvers:  lr.Resolvers,
		ServerName: lr.ServerName,
		AppsScript: lr.AppsScript,
	}
}

func storeLearned(path string, p Payload) {
	if path == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	b, err := json.MarshalIndent(learnedRegistry{
		IssuedAt:   p.IssuedAt.UTC().Format("2006-01-02T15:04:05Z"),
		GitHubIPs:  p.GitHubIPs,
		Mirrors:    p.Mirrors,
		Resolvers:  p.Resolvers,
		ServerName: p.ServerName,
		AppsScript: p.AppsScript,
	}, "", "  ")
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".catnet-*")
	if err != nil {
		return
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return
	}
	if err := tmp.Close(); err != nil {
		return
	}
	_ = os.Chmod(name, 0o600)
	_ = os.Rename(name, path)
}
