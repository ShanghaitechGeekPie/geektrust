package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	// probeTimeout bounds a single TLS attempt to a gateway line.
	probeTimeout = 3 * time.Second
	// lineRaceDelay gives the preferred line a short head start. Healthy
	// lines normally win without opening duplicate gateway connections, while
	// a stalled line cannot hold up the fallback.
	lineRaceDelay = 150 * time.Millisecond
	// failCooldown keeps a line that just failed connection out of the
	// probe winners, so a TCP-open-but-TLS-dead endpoint (e.g. the
	// campus-internal address seen from outside) stops eating every
	// reconnect attempt.
	failCooldown = 90 * time.Second
)

// Lines tracks an ordered gateway pool. The healthy preferred line starts
// first, fallbacks join a staggered race, and failed lines enter cooldown.
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

// ReportSuccess makes addr the preferred first attempt and clears any prior
// cooldown. It is called only after a complete TLS handshake succeeds.
func (l *Lines) ReportSuccess(addr string) {
	l.mu.Lock()
	delete(l.failed, addr)
	for i, candidate := range l.addrs {
		if candidate == addr {
			l.offset = i
			break
		}
	}
	l.mu.Unlock()
}

func (l *Lines) eligible() []string {
	addrs := l.Addrs()
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
		return addrs
	}
	return eligible
}

// allLinesTried reports whether every configured line either reached the
// caller's next protocol stage or failed its TLS attempt recently. This lets a
// stale session be refreshed even when one gateway rejects authentication and
// another cannot get as far as authentication.
func (l *Lines) allLinesTried(tried map[string]bool) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.addrs) == 0 {
		return false
	}
	now := time.Now()
	for _, addr := range l.addrs {
		if tried[addr] {
			continue
		}
		failedAt, failed := l.failed[addr]
		if !failed || now.Sub(failedAt) > failCooldown {
			return false
		}
	}
	return true
}

type lineDialResult struct {
	addr string
	conn net.Conn
	err  error
}

// DialTLS races eligible lines with a small stagger and returns the first
// completed TLS connection. The winning socket is reused by the caller; this
// avoids the old probe-close-redial sequence and does not wait for a slower
// probe after one line is ready.
func (l *Lines) DialTLS(ctx context.Context) (net.Conn, string, error) {
	eligible := l.eligible()
	if len(eligible) == 0 {
		return nil, "", ErrNoLines
	}

	raceCtx, cancel := context.WithCancel(ctx)
	results := make(chan lineDialResult, len(eligible))
	for i, addr := range eligible {
		go func(position int, addr string) {
			if position > 0 {
				timer := time.NewTimer(time.Duration(position) * lineRaceDelay)
				select {
				case <-timer.C:
				case <-raceCtx.Done():
					timer.Stop()
					results <- lineDialResult{addr: addr, err: raceCtx.Err()}
					return
				}
			}
			attemptCtx, attemptCancel := context.WithTimeout(raceCtx, probeTimeout)
			conn, err := probeGatewayTLS(attemptCtx, addr)
			attemptCancel()
			if raceCtx.Err() != nil && conn != nil {
				conn.Close()
				conn = nil
			}
			results <- lineDialResult{addr: addr, conn: conn, err: err}
		}(i, addr)
	}

	var failures []error
	for received := 0; received < len(eligible); received++ {
		select {
		case result := <-results:
			if result.err != nil {
				if err := ctx.Err(); err != nil {
					cancel()
					go closeLineResults(results, len(eligible)-received-1)
					return nil, "", err
				}
				if !errors.Is(result.err, context.Canceled) {
					l.ReportFailure(result.addr)
					failures = append(failures, fmt.Errorf("gateway %s: %w", result.addr, result.err))
				}
				continue
			}
			if result.conn == nil {
				failures = append(failures, fmt.Errorf("gateway %s returned no connection", result.addr))
				continue
			}
			if err := ctx.Err(); err != nil {
				result.conn.Close()
				cancel()
				go closeLineResults(results, len(eligible)-received-1)
				return nil, "", err
			}
			cancel()
			go closeLineResults(results, len(eligible)-received-1)
			l.ReportSuccess(result.addr)
			return result.conn, result.addr, nil
		case <-ctx.Done():
			cancel()
			go closeLineResults(results, len(eligible)-received)
			return nil, "", ctx.Err()
		}
	}
	cancel()
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	return nil, "", fmt.Errorf("no TLS-capable gateway line: %w", errors.Join(failures...))
}

func closeLineResults(results <-chan lineDialResult, remaining int) {
	for range remaining {
		if result := <-results; result.conn != nil {
			result.conn.Close()
		}
	}
}

// Best retains the diagnostic line-selection API. Runtime callers should use
// DialTLS so the successful connection is not discarded and opened again.
func (l *Lines) Best(ctx context.Context) (string, error) {
	conn, addr, err := l.DialTLS(ctx)
	if conn != nil {
		conn.Close()
	}
	return addr, err
}

func probeGatewayTLS(ctx context.Context, addr string) (net.Conn, error) {
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	conn := tls.Client(raw, gatewayTLSConfig(addr))
	if err := conn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return conn, nil
}

// ErrNoLines signals an empty gateway line pool.
var ErrNoLines = &LineError{"no gateway lines configured"}

// LineError is a line-selection failure.
type LineError struct{ Msg string }

func (e *LineError) Error() string { return e.Msg }
