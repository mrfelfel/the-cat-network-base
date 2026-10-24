package catnet

import (
	"context"
	"time"
)

// Refresher re-runs Resolve on a timer while the caller keeps it running.
//
// The point is to exploit the windows when the network *is* up: a connection
// that drops mid-session is useless if the last good document is hours old, so
// a background loop keeps the cache and the learned registry current whenever
// connectivity happens to exist.
type Refresher struct {
	Resolver *Resolver
	// Interval between attempts. Default 30 minutes.
	Interval time.Duration
	// OnResult is called after each attempt; err is nil on success.
	OnResult func(*Result, error)
}

// Run blocks until ctx is cancelled. The first refresh happens after one
// interval, since the caller has just resolved for itself.
func (f *Refresher) Run(ctx context.Context) {
	interval := f.Interval
	if interval <= 0 {
		interval = 30 * time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			res, err := f.Resolver.refresh(ctx)
			if f.OnResult != nil {
				f.OnResult(res, err)
			}
		}
	}
}

// refresh resolves while skipping the cache fast-path, so upstream is actually
// contacted. A failure is not reported as an error: the cache is still valid
// and the caller keeps whatever it had.
func (r *Resolver) refresh(ctx context.Context) (*Result, error) {
	r.mu.Lock()
	r.forceRefresh = true
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.forceRefresh = false
		r.mu.Unlock()
	}()
	return r.Resolve(ctx)
}

// startUpgrade schedules one background full resolve after a bootstrap win.
//
// The bootstrap answer is addresses only, by design: the registry does not fit
// in a TXT record. This fetches the full document so every layer's inputs are
// learned and the next resolve is complete. It runs at most once at a time and
// never blocks the caller; a failure is silent because the caller already has a
// working address.
func (r *Resolver) startUpgrade() {
	if !r.upgradeRunning.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer r.upgradeRunning.Store(false)
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		_, _ = r.refresh(ctx)
	}()
}
