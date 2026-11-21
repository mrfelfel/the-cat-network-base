package main

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"time"

	catnet "github.com/mrfelfel/the-cat-network-base/lib"
)

// cmdLayers exercises every fetch layer on its own, so an operator can see
// which routes survive from a given network — and, with -block, which still
// work when a layer is taken away.
//
// The resolver normally stops at the first layer that answers, which is right
// in production and useless for diagnosing: from this machine it is always
// layer 1, and nothing else is ever tried. This runs each layer in isolation.
func cmdLayers(args []string) error {
	fs := flag.NewFlagSet("layers", flag.ExitOnError)
	rf := bindResolverFlags(fs)
	block := fs.String("block", "", "comma-separated layers to simulate as blocked: static,dns,udp-dns,goproxy,mirror")
	timeout := fs.Duration("timeout", 20*time.Second, "per-layer timeout")
	_ = fs.Parse(args)

	blocked := map[string]bool{}
	for _, b := range strings.Split(*block, ",") {
		if b = strings.TrimSpace(b); b != "" {
			blocked[b] = true
		}
	}

	// The document path is derived the same way buildLayers does, so this
	// probes exactly what the resolver would ask for.
	doc := "/" + *rf.repo + "/" + *rf.branch + "/" + *rf.file
	if *rf.repo == "" {
		doc = "/" + *rf.file
	}
	fmt.Printf("document  %s\n", doc)
	if len(blocked) > 0 {
		fmt.Printf("blocking  %s\n", *block)
	}
	fmt.Println()

	type outcome struct {
		name string
		err  error
		took time.Duration
		n    int
	}
	var results []outcome

	for _, tc := range layerCases(*block) {
		if blocked[tc.key] {
			results = append(results, outcome{name: tc.name, err: fmt.Errorf("simulated block")})
			continue
		}
		start := time.Now()
		n, err := tc.run(doc, *timeout)
		results = append(results, outcome{name: tc.name, err: err, took: time.Since(start), n: n})
	}

	failed := 0
	for _, r := range results {
		if r.err != nil {
			failed++
			fmt.Printf("  FAIL  %-34s %v\n", r.name, r.err)
			continue
		}
		fmt.Printf("  ok    %-34s %d server(s)  %s\n", r.name, r.n, r.took.Round(time.Millisecond))
	}
	fmt.Printf("\n%d ok, %d failed\n", len(results)-failed, failed)
	if failed > 0 {
		return fmt.Errorf("%d layer(s) unavailable", failed)
	}
	return nil
}

type layerCase struct {
	key  string
	name string
	run  func(doc string, timeout time.Duration) (int, error)
}

// layerCases builds one isolated probe per layer, in the resolver's order.
func layerCases(doc string) []layerCase {
	return []layerCase{
		{"static", "static IP → raw.githubusercontent.com", func(d string, t time.Duration) (int, error) {
			return fetchOne(context.Background(), catnet.StaticHostSource{
				IP: "185.199.108.133", Host: "raw.githubusercontent.com", Path: d,
			}, t)
		}},
		{"dns", "DNS (DoT/DoH)", func(d string, t time.Duration) (int, error) {
			return fetchOne(context.Background(), catnet.DNSLayer{
				Hosts: []catnet.HostPath{{Host: "raw.githubusercontent.com", Path: d}},
			}, t)
		}},
		{"udp-dns", "plain UDP DNS (national resolvers)", func(d string, t time.Duration) (int, error) {
			return fetchOne(context.Background(), catnet.UDPDNSSource{
				Hosts:   []catnet.HostPath{{Host: "raw.githubusercontent.com", Path: d}},
				Servers: []string{"10.202.10.202", "178.22.122.100"},
			}, t)
		}},
		{"goproxy", "Go module proxy", func(d string, t time.Duration) (int, error) {
			return fetchOne(context.Background(), catnet.GoProxySource{
				Base: "https://package-mirror.liara.ir/repository/go",
				// The module path must include the host, as go.mod declares it.
				// A bare "owner/name" asks the proxy for a module that does not
				// exist and comes back 404 — which looks exactly like a blocked
				// proxy, so this is worth getting right.
				Module: "github.com/mrfelfel/the-cat-network-base",
				File:   fileOf(d),
			}, t)
		}},
	}
}

func fileOf(docPath string) string {
	if i := strings.LastIndex(docPath, "/"); i >= 0 {
		return docPath[i+1:]
	}
	return docPath
}

// fetchOne runs a single source against a timeout and reports how many servers
// its document carried, so a layer that "succeeds" with an empty answer is not
// mistaken for a working one.
func fetchOne(ctx context.Context, src catnet.Source, timeout time.Duration) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	raw, err := src.Fetch(ctx)
	if err != nil {
		return 0, err
	}
	env, err := catnet.ParseEnvelope(raw, catnet.Descriptor(), catnet.Keys)
	if err != nil {
		return 0, fmt.Errorf("fetched but did not verify: %v", err)
	}
	return len(env.Payload.Servers), nil
}
