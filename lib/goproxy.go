package catnet

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// GoProxySource fetches the document out of a Go module proxy.
//
// Iranian filtering blocks GitHub and many CDNs, but the national Go module
// mirrors (Liara's `repository/go`, goproxy.cn, goproxy.ir) stay reachable
// because every Iranian Go developer needs them. The proxy serves our whole
// repository as a module zip, and servers.json is inside it.
//
// The cost is the zip, not the file: about 67 KiB for this repo, downloaded
// whole and then filtered down to one entry. That is affordable once, but not
// something to try before the cheap layers — hence its position after the
// direct static-IP fetch and before DNS.
//
// Proxy protocol, per Go's module proxy spec:
//
//	GET <proxy>/<module>/@latest  → {"Version":"..."}
//	GET <proxy>/<module>/@v/<ver>.zip
//
// Module paths are lowercased with uppercase letters escaped as !x.
type GoProxySource struct {
	// Base is the proxy root, e.g.
	// "https://package-mirror.liara.ir/repository/go".
	Base string
	// Module is the module path, e.g.
	// "github.com/mrfelfel/the-cat-network-base".
	Module string
	// File is the entry inside the module zip. Default "servers.json".
	File string
	// Version pins a version; empty asks the proxy for @latest.
	Version string
	// Timeout bounds the whole fetch. Default 20s — the zip is ~70 KiB.
	Timeout time.Duration
}

func (g GoProxySource) Name() string { return "goproxy:" + hostOf(g.Base) }

func (g GoProxySource) Fetch(ctx context.Context) ([]byte, error) {
	if g.Base == "" || g.Module == "" {
		return nil, fmt.Errorf("goproxy: base and module are required")
	}
	timeout := g.Timeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	client := &http.Client{Timeout: timeout}
	base := strings.TrimSuffix(g.Base, "/") + "/" + escapeModule(g.Module)

	version := g.Version
	if version == "" {
		var err error
		version, err = latestVersion(ctx, client, base)
		if err != nil {
			return nil, err
		}
	}

	zipURL := base + "/@v/" + version + ".zip"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, zipURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "catnet/1")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("goproxy: zip status %d", resp.StatusCode)
	}
	// Bound the download: a module zip is small, and an unbounded read here
	// would let a hostile proxy exhaust memory.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxModuleZip))
	if err != nil {
		return nil, err
	}
	if len(body) >= maxModuleZip {
		return nil, fmt.Errorf("goproxy: zip too large")
	}
	return extractMember(body, g.FileOrDefault())
}

// maxModuleZip bounds the whole module archive. 8 MiB is far above this repo
// and far below anything that would hurt a phone.
const maxModuleZip = 8 << 20

// maxMember bounds the entry we extract from it.
const maxMember = 32 << 10

func (g GoProxySource) FileOrDefault() string {
	if g.File == "" {
		return "servers.json"
	}
	return g.File
}

func latestVersion(ctx context.Context, client *http.Client, base string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/@latest", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "catnet/1")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("goproxy: @latest status %d", resp.StatusCode)
	}
	var v struct {
		Version string `json:"Version"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&v); err != nil {
		return "", fmt.Errorf("goproxy: @latest: %v", err)
	}
	if v.Version == "" {
		return "", fmt.Errorf("goproxy: @latest returned no version")
	}
	return v.Version, nil
}

// extractMember returns the named file from a module zip. Module zips prefix
// every entry with "<module>@<version>/", so the match is on the suffix.
func extractMember(zipBytes []byte, name string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		return nil, fmt.Errorf("goproxy: %v", err)
	}
	suffix := "/" + name
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, suffix) {
			continue
		}
		if f.UncompressedSize64 > maxMember {
			return nil, fmt.Errorf("goproxy: %s is too large", name)
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		b, err := io.ReadAll(io.LimitReader(rc, maxMember+1))
		if err != nil {
			return nil, err
		}
		if len(b) > maxMember {
			return nil, fmt.Errorf("goproxy: %s is too large", name)
		}
		return b, nil
	}
	return nil, fmt.Errorf("goproxy: %s not found in module zip", name)
}

// escapeModule applies the module-proxy case encoding: an uppercase letter is
// replaced by "!" followed by its lowercase form.
func escapeModule(path string) string {
	var b strings.Builder
	b.Grow(len(path))
	for _, r := range path {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('!')
			b.WriteRune(r + ('a' - 'A'))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
