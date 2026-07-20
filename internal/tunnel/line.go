package tunnel

import (
	"context"
	"net"
	"sort"
	"sync"
	"time"
)

const (
	// probeTimeout bounds a single TCP probe of a gateway line.
	probeTimeout = 3 * time.Second
	// failCooldown keeps a line that just failed connection out of the
	// probe winners, so a TCP-open-but-TLS-dead endpoint (e.g. the
	// campus-internal address seen from outside) stops eating every
	// reconnect attempt.
	failCooldown = 90 * time.Second
)

// Lines tracks the ordered gateway line pool: probes pick the
// lowest-latency reachable line, failures rotate the pool.
type Lines struct {
	mu     sync.Mutex
	addrs  []string
	failed map[string]time.Time
	// offset marks the preferred starting point; Rotate advances it after
	// line-switch error codes.
	offset int
}

// NewLines builds a line pool from host:port addresses.
func NewLines(addrs []string) *Lines {
	return &Lines{addrs: append([]string(nil), addrs...), failed: make(map[string]time.Time)}
}

// Addrs returns the current ordered line list (rotation applied).
func (l *Lines) Addrs() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, 0, len(l.addrs))
	for i := range len(l.addrs) {
		out = append(out, l.addrs[(l.offset+i)%len(l.addrs)])
	}
	return out
}

// Rotate advances the preferred line after a line-switch trigger.
func (l *Lines) Rotate() {
	l.mu.Lock()
	if len(l.addrs) > 0 {
		l.offset = (l.offset + 1) % len(l.addrs)
	}
	l.mu.Unlock()
}

// ReportFailure puts a line in cooldown after a connect failure.
func (l *Lines) ReportFailure(addr string) {
	l.mu.Lock()
	l.failed[addr] = time.Now()
	l.mu.Unlock()
}

// Best probes every line concurrently and returns the reachable one with the
// lowest latency, skipping lines in cooldown; if every line is cooling down
// or none answers, falls back to the preferred line.
func (l *Lines) Best(ctx context.Context) (string, error) {
	addrs := l.Addrs()
	if len(addrs) == 0 {
		return "", ErrNoLines
	}
	if len(addrs) == 1 {
		return addrs[0], nil
	}

	// Eligible = not recently failed; keep all if that would empty the pool.
	l.mu.Lock()
	now := time.Now()
	eligible := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		if failedAt, ok := l.failed[addr]; !ok || now.Sub(failedAt) > failCooldown {
			eligible = append(eligible, addr)
		}
	}
	l.mu.Unlock()
	if len(eligible) == 0 {
		eligible = addrs
	}

	type result struct {
		addr    string
		latency time.Duration
		ok      bool
	}
	results := make([]result, len(eligible))
	var wg sync.WaitGroup
	for i, addr := range eligible {
		wg.Add(1)
		go func(i int, addr string) {
			defer wg.Done()
			start := time.Now()
			probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
			defer cancel()
			conn, err := (&net.Dialer{}).DialContext(probeCtx, "tcp", addr)
			if err != nil {
				return
			}
			conn.Close()
			results[i] = result{addr: addr, latency: time.Since(start), ok: true}
		}(i, addr)
	}
	wg.Wait()

	var reachable []result
	for _, r := range results {
		if r.ok {
			reachable = append(reachable, r)
		}
	}
	if len(reachable) == 0 {
		// Nothing answered the probe; try the preferred line anyway.
		return eligible[0], nil
	}
	sort.Slice(reachable, func(i, j int) bool { return reachable[i].latency < reachable[j].latency })
	return reachable[0].addr, nil
}

// ErrNoLines signals an empty gateway line pool.
var ErrNoLines = &LineError{"no gateway lines configured"}

// LineError is a line-selection failure.
type LineError struct{ Msg string }

func (e *LineError) Error() string { return e.Msg }
