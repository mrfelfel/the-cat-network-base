package mobile

import (
	"strconv"
	"strings"

	catnet "github.com/mrfelfel/the-cat-network-base/lib"
)

func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseSeed(hp string) (catnet.SeedSource, bool) {
	i := strings.LastIndex(hp, ":")
	if i < 1 {
		return catnet.SeedSource{}, false
	}
	port, err := strconv.Atoi(hp[i+1:])
	if err != nil || port < 1 || port > 65535 {
		return catnet.SeedSource{}, false
	}
	return catnet.SeedSource{Host: hp[:i], Port: port}, true
}
