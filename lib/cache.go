package catnet

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// cache stores the last verified document plus where it came from. The cache
// is the first source tried, so an offline start resolves instantly and an
// online start can skip the network when the cached document is fresh.
type cache struct {
	path  string
	clock func() int64 // unix seconds; injectable for tests
}

func newCache(path string) *cache {
	return &cache{path: path, clock: func() int64 { return nowUnix() }}
}

// load returns the cached raw document, or nil if there is none or it is
// unreadable. A corrupt cache is deleted so the next run starts clean rather
// than repeatedly failing on it.
func (c *cache) load() []byte {
	if c == nil || c.path == "" {
		return nil
	}
	b, err := os.ReadFile(c.path)
	if err != nil {
		return nil
	}
	return b
}

// store atomically replaces the cache file. A failure here is not fatal: the
// caller already has the payload in memory.
func (c *cache) store(raw []byte) {
	if c == nil || c.path == "" {
		return
	}
	dir := filepath.Dir(c.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	tmp, err := os.CreateTemp(dir, ".catnet-*")
	if err != nil {
		return
	}
	name := tmp.Name()
	defer os.Remove(name) // no-op once renamed
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return
	}
	if err := tmp.Close(); err != nil {
		return
	}
	_ = os.Chmod(name, 0o600)
	_ = os.Rename(name, c.path)
}

// discard removes a cache file that failed verification.
func (c *cache) discard() {
	if c == nil || c.path == "" {
		return
	}
	err := os.Remove(c.path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return
	}
}
