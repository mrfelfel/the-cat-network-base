package catnet

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"time"
)

// Probe is the layer-zero reachability check: a bare TCP connect to each seed
// address, in parallel, with a short deadline. It answers "can I already reach
// the network?" before spending anything on fetching a document.
type Probe struct {
	// Timeout bounds the whole probe, not each address. Default 500ms.
	Timeout time.Duration
}

// ProbeResult is the outcome for one address.
type ProbeResult struct {
	Addr  string
	RTT   time.Duration
	Err   error
	order int
}

// ProbeAll connects to every address concurrently and returns the reachable
// ones, fastest first. It never returns an error: an empty slice means "none
// reachable", which is a normal outcome that moves the resolver to layer one.
func ProbeAll(ctx context.Context, addrs []string, timeout time.Duration) []ProbeResult {
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	out := make([]ProbeResult, len(addrs))
	var wg sync.WaitGroup
	for i, a := range addrs {
		wg.Add(1)
		go func(i int, a string) {
			defer wg.Done()
			out[i] = probeOne(ctx, a, i)
		}(i, a)
	}
	wg.Wait()

	var ok []ProbeResult
	for _, r := range out {
		if r.Err == nil {
			ok = append(ok, r)
		}
	}
	sortByRTT(ok)
	return ok
}

func probeOne(ctx context.Context, addr string, order int) ProbeResult {
	start := time.Now()
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return ProbeResult{Addr: addr, Err: err, order: order}
	}
	rtt := time.Since(start)
	c.Close()
	return ProbeResult{Addr: addr, RTT: rtt, order: order}
}

// ProbeTLS additionally completes a TLS handshake, which rejects hosts that
// accept TCP but are a wrong service or a black-holed middlebox.
func ProbeTLS(ctx context.Context, addr, serverName string, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 900 * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer raw.Close()
	c := tls.Client(raw, &tls.Config{ServerName: serverName})
	defer c.Close()
	return c.HandshakeContext(ctx)
}

func sortByRTT(r []ProbeResult) {
	// Insertion sort: n is the number of seeds, always tiny.
	for i := 1; i < len(r); i++ {
		for j := i; j > 0 && r[j].RTT < r[j-1].RTT; j-- {
			r[j], r[j-1] = r[j-1], r[j]
		}
	}
}

// Name satisfies Source so a Probe can also act as a layer.
func (Probe) Name() string { return "probe" }
