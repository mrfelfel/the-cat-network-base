package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	catnet "github.com/mrfelfel/the-cat-network-base/lib"
)

type resolverFlags struct {
	repo    *string
	branch  *string
	file    *string
	seeds   *string
	dns     *string
	mirrors *string
	cache   *string
}

func bindResolverFlags(fs *flag.FlagSet) *resolverFlags {
	return &resolverFlags{
		repo:    fs.String("repo", "mrfelfel/the-cat-network-base", "GitHub owner/name"),
		branch:  fs.String("branch", "main", "branch or tag holding the document"),
		file:    fs.String("file", "servers.json", "document path in the repo"),
		seeds:   fs.String("seeds", "", "comma-separated ip:port seed addresses"),
		dns:     fs.String("dns", "", "TXT record name, e.g. _catnet.catgram.ir"),
		mirrors: fs.String("mirrors", "", "comma-separated extra mirror URLs"),
		cache:   fs.String("cache", defaultCachePath(), "cache file (empty disables)"),
	}
}

func buildResolver(fs *flag.FlagSet, r *resolverFlags) *catnet.Resolver {
	if r == nil {
		r = bindResolverFlags(fs)
	}
	opts := catnet.Options{
		Repo:      *r.repo,
		Branch:    *r.branch,
		File:      *r.file,
		DNSName:   *r.dns,
		CachePath: *r.cache,
	}
	for _, u := range splitComma(*r.mirrors) {
		opts.Mirrors = append(opts.Mirrors, u)
	}
	for _, hp := range splitComma(*r.seeds) {
		s, err := parseSeed(hp)
		if err != nil {
			fmt.Fprintf(os.Stderr, "catnetctl: ignoring seed %q: %v\n", hp, err)
			continue
		}
		opts.Seeds = append(opts.Seeds, s)
	}
	return catnet.Build(opts)
}

func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseSeed(hp string) (catnet.SeedSource, error) {
	i := strings.LastIndex(hp, ":")
	if i < 1 {
		return catnet.SeedSource{}, fmt.Errorf("want ip:port")
	}
	var port int
	if _, err := fmt.Sscanf(hp[i+1:], "%d", &port); err != nil || port < 1 || port > 65535 {
		return catnet.SeedSource{}, fmt.Errorf("bad port %q", hp[i+1:])
	}
	return catnet.SeedSource{Host: hp[:i], Port: port}, nil
}

func defaultCachePath() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return dir + "/catnet/servers.json"
}

func contextWithSignal() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func strictUnmarshal(b []byte, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
