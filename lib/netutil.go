package catnet

import (
	"fmt"
	"net"
	"strconv"
)

// splitHostPort parses "host:port" including the "[v6]:port" form.
func splitHostPort(addr string) (string, int, error) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, fmt.Errorf("catnet: %q is not host:port", addr)
	}
	port, err := strconv.Atoi(p)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("catnet: bad port in %q", addr)
	}
	return h, port, nil
}
