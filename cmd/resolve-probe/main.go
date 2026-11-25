// resolve-probe is the desktop client's view of catnet.
//
// tdesktop builds without cgo, so it cannot link this library; it runs this
// helper as a short-lived process at startup instead and reads the JSON it
// prints. That is why the output is always JSON — on success and on failure —
// and why nothing is written to stdout that is not part of it: the caller must
// not have to tell a valid answer from a Go panic trace.
//
//	resolve-probe [flags] <cache-dir>
//
// The cache directory is positional because that is how the caller's guide
// documents it; everything else is optional.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	catnet "github.com/mrfelfel/the-cat-network-base/lib"
)

// defaultDocument is servers-v2.json rather than the historical servers.json.
//
// The v2 document is the one that carries the runtime config block (payment
// authority, support, public URLs), and a client that reads only servers.json
// gets addresses but no config. The desktop needs both from one call: the
// checkout host and the update channel are what §4.2 of the guide is about.
const defaultDocument = "servers-v2.json"

// defaultBuild is the distribution whose payment switch is reported. The
// desktop has no store flavor: it is the direct build.
const defaultBuild = "standalone"

func main() {
	fs := flag.NewFlagSet("resolve-probe", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	doc := fs.String("doc", defaultDocument, "document path inside the repo")
	build := fs.String("build", defaultBuild, "distribution name for the payment switch")
	timeout := fs.Duration("timeout", 12*time.Second, "overall deadline")
	refresh := fs.Bool("refresh", false, "ignore the cache and contact the network")
	wantConfig := fs.Bool("config", false, "also fetch the document for its config block")
	seeds := fs.String("seeds", "62.220.127.238:30001", "comma-separated ip:port seeds")
	if err := fs.Parse(os.Args[1:]); err != nil {
		// -h is answered by flag itself; anything else is a real error.
		if err == flag.ErrHelp {
			os.Exit(0)
		}
		fail(err)
	}
	if fs.NArg() != 1 {
		fail(fmt.Errorf("usage: resolve-probe [flags] <cache-dir>"))
	}
	cacheDir := fs.Arg(0)

	cachePath := cachePathFor(cacheDir, *doc)
	if *refresh && cachePath != "" {
		// Resolve's fast path reads the file on every run, and the library
		// exposes no force flag, so removing it is exactly "fetch again".
		_ = os.Remove(cachePath)
	}

	r := catnet.Build(catnet.Options{
		Repo:      "mrfelfel/the-cat-network-base",
		Branch:    "main",
		File:      *doc,
		CachePath: cachePath,
		Seeds:     parseSeeds(*seeds),
	})

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	res, err := r.Resolve(ctx)
	if err != nil {
		fail(err)
	}

	out := map[string]any{
		"addrs":   res.Addrs,
		"source":  res.Source,
		"layer":   res.Layer,
		"cached":  res.Cached,
		"stale":   res.Stale,
		"expires": res.ExpiresAt.UTC().Format(time.RFC3339),
	}
	if servers := encodeServers(res.Servers); len(servers) > 0 {
		out["servers"] = servers
	}
	cfg := r.Config()
	if cfg == nil && *wantConfig {
		// A layer-0 probe answers with addresses and returns before any
		// document is fetched, so the config block is empty on a network
		// healthy enough to need it least. The desktop needs the config at
		// startup (checkout host, update channel), so ask for the document
		// explicitly; the worst case is that it fails and we keep the
		// addresses we already have.
		cfg = fetchConfig(cacheDir, *doc, *timeout)
	}
	if cfg != nil {
		out["config"] = encodeConfig(cfg, *build)
	}
	emit(out)
}

// fetchConfig resolves again against the same cache, this time skipping the
// layer-0 probe.
//
// It runs a second Resolve rather than calling an internal fetch helper because
// the library only exposes the whole chain: with no seeds there is nothing to
// probe, so the chain goes straight to the document layers. The first call has
// already written the document to the cache when it succeeded, so this second
// one usually returns from disk without touching the network at all.
func fetchConfig(cacheDir, doc string, timeout time.Duration) *catnet.Config {
	r := catnet.Build(catnet.Options{
		Repo:      "mrfelfel/the-cat-network-base",
		Branch:    "main",
		File:      doc,
		CachePath: cachePathFor(cacheDir, doc),
	})
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if _, err := r.Resolve(ctx); err != nil {
		return nil
	}
	return r.Config()
}

// cachePathFor derives the cache file name from the document path, the same
// way the mobile bindings do. Two documents must never share a cache entry, or
// a client reading the new layout could be served the old one from disk.
func cachePathFor(dir, file string) string {
	if dir == "" {
		return ""
	}
	name := "catnet-servers.json"
	if file != "" {
		name = "catnet-" + strings.NewReplacer("/", "_", "\\", "_").Replace(file) + ".cache"
	}
	return filepath.Join(dir, name)
}

func parseSeeds(s string) []catnet.SeedSource {
	var out []catnet.SeedSource
	for _, hp := range strings.Split(s, ",") {
		hp = strings.TrimSpace(hp)
		i := strings.LastIndex(hp, ":")
		if i < 1 {
			continue
		}
		port, err := strconv.Atoi(hp[i+1:])
		if err != nil || port < 1 || port > 65535 {
			continue
		}
		out = append(out, catnet.SeedSource{Host: hp[:i], Port: port})
	}
	return out
}

type probeServer struct {
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Tag    string `json:"tag,omitempty"`
	Weight int    `json:"weight,omitempty"`
}

func encodeServers(in []catnet.Server) []probeServer {
	out := make([]probeServer, len(in))
	for i, s := range in {
		out[i] = probeServer{Host: s.Host, Port: s.Port, Tag: s.Tag, Weight: s.Weight}
	}
	return out
}

// encodeConfig flattens the document's config into the shape the desktop
// reads. A nil result means the document carried no config at all, which the
// caller must treat as "keep the compiled-in defaults", not as empty values.
func encodeConfig(c *catnet.Config, build string) map[string]any {
	if c == nil {
		return nil
	}
	out := map[string]any{}
	if c.Payments != nil {
		out["payments"] = map[string]any{
			"mode":           c.Payments.Mode(),
			"direct_enabled": catnet.PaymentsEnabled(c, build),
		}
	}
	if c.Support != nil {
		out["support"] = c.Support
	}
	if c.URLs != nil {
		out["urls"] = c.URLs
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func emit(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		fail(err)
	}
	fmt.Println(string(b))
}

func fail(err error) {
	b, _ := json.Marshal(map[string]string{"error": err.Error()})
	fmt.Println(string(b))
	os.Exit(1)
}
