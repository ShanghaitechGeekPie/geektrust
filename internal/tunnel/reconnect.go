package tunnel

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"time"

	"geektrust/internal/frame"
	"geektrust/internal/session"
)

const (
	reconnectBase = 1 * time.Second
	reconnectMax  = 30 * time.Second
)

// Manager owns the live tunnel: it (re)connects on demand with exponential
// backoff, switches gateway lines on tunnel-layer error codes, and forces a
// silent re-login when tunnel authentication keeps rejecting the session.
type Manager struct {
	provider session.CredentialProvider
	logger   *slog.Logger

	linesMu  sync.Mutex
	lines    *Lines
	gateways []string

	mu         sync.Mutex
	cur        *Tunnel
	connecting *connectCall
}

// connectCall is one in-flight connect shared by every concurrent caller:
// all waiters block on done and then read the same result.
type connectCall struct {
	done   chan struct{} // closed once tunnel/err are populated
	tunnel *Tunnel
	err    error
}

// NewManager builds a tunnel manager over the credential provider.
func NewManager(provider session.CredentialProvider, logger *slog.Logger) *Manager {
	return &Manager{provider: provider, logger: logger}
}

// Tunnel returns a live tunnel authenticated with the current session,
// connecting or reconnecting as needed. A tunnel left over from a rotated
// session is closed and re-established. Concurrent callers share one
// in-flight connect attempt.
func (m *Manager) Tunnel(ctx context.Context) (*Tunnel, error) {
	cred, err := m.provider.Credential(ctx)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	if t := m.cur; t != nil && t.Alive() && t.SID() == cred.SID {
		m.mu.Unlock()
		return t, nil
	}
	// Dead, or authenticated with a since-rotated session.
	if t := m.cur; t != nil {
		t.Close()
		m.cur = nil
	}
	call := m.connecting
	if call == nil {
		call = &connectCall{done: make(chan struct{})}
		m.connecting = call
		m.mu.Unlock()

		t, err := m.connect(ctx)

		m.mu.Lock()
		if err == nil {
			m.cur = t
		}
		m.connecting = nil
		m.mu.Unlock()
		call.tunnel, call.err = t, err
		close(call.done)
		return t, err
	}
	m.mu.Unlock()
	select {
	case <-call.done:
		return call.tunnel, call.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// SwitchLine rotates the preferred gateway line and kills the current tunnel
// so the next use reconnects elsewhere. Called when per-connection auth
// reports a line-switch code.
func (m *Manager) SwitchLine() {
	m.mu.Lock()
	t := m.cur
	m.mu.Unlock()
	m.linesMu.Lock()
	if m.lines != nil {
		m.lines.Rotate()
		if t != nil {
			// Cool the failed line down so the next Best() actually picks
			// another gateway instead of the same fastest one.
			m.lines.ReportFailure(t.Addr())
		}
	}
	m.linesMu.Unlock()
	if t != nil {
		m.logger.Info("switching gateway line", "from", t.Addr())
		t.Close()
	}
}

// Close shuts down the current tunnel without reconnecting.
func (m *Manager) Close() {
	m.mu.Lock()
	t := m.cur
	m.cur = nil
	m.mu.Unlock()
	if t != nil {
		t.Close()
	}
}

// connect retries dial+tunnel-auth with exponential backoff until it succeeds
// or ctx is done. Line-switch codes rotate the pool; other tunnel-auth
// failures eventually invalidate the session for a silent re-login.
func (m *Manager) connect(ctx context.Context) (*Tunnel, error) {
	backoff := reconnectBase
	// Per session generation: which lines were tried at all, and which
	// reached tunnel auth and rejected it. The session is invalidated only
	// once every configured line has been tried and at least one rejection
	// came back from the auth stage (lines failing at TCP/TLS never reach
	// auth — e.g. internal gateways seen from outside — and must not block
	// the refresh decision).
	authRejects := make(map[string]int64)
	tried := make(map[string]bool)
	rejectSID := ""
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		cred, err := m.provider.Credential(ctx)
		if err != nil {
			m.logger.Error("no valid session for tunnel", "err", err)
		} else {
			if cred.SID != rejectSID {
				authRejects = make(map[string]int64)
				tried = make(map[string]bool)
				rejectSID = cred.SID
			}
			lines := m.ensureLines(cred.Gateways)
			addr, err := lines.Best(ctx)
			if err != nil {
				return nil, err // empty line pool: configuration error
			}
			t, err := Dial(ctx, addr, cred.SID, m.logger)
			if err == nil {
				return t, nil
			}
			m.logger.Warn("tunnel connect failed", "addr", addr, "err", err)
			if ctx.Err() != nil {
				// Caller cancellation is not the line's fault.
				return nil, ctx.Err()
			}
			lines.ReportFailure(addr)
			tried[addr] = true

			var authErr *frame.TunnelAuthError
			if errors.As(err, &authErr) {
				if authErr.ShouldSwitchLine() {
					lines.Rotate()
				} else {
					authRejects[addr] = authErr.Code
				}
			}
			if len(tried) >= len(cred.Gateways) && len(authRejects) > 0 {
				m.logger.Warn("tunnel auth rejected on every reachable line; re-logging in",
					"rejects", len(authRejects))
				m.provider.Invalidate()
				authRejects = make(map[string]int64)
				tried = make(map[string]bool)
			}
		}

		m.logger.Info("tunnel reconnect backoff", "delay", backoff)
		timer := time.NewTimer(backoff)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		}
		if backoff *= 2; backoff > reconnectMax {
			backoff = reconnectMax
		}
	}
}

// ensureLines rebuilds the line pool when the credential's gateway list
// changes (e.g. after a re-login fetched new nodeGroup addresses).
func (m *Manager) ensureLines(gateways []string) *Lines {
	m.linesMu.Lock()
	defer m.linesMu.Unlock()
	if m.lines == nil || !slices.Equal(m.gateways, gateways) {
		m.gateways = append([]string(nil), gateways...)
		m.lines = NewLines(gateways)
		m.logger.Debug("gateway line pool updated", "lines", gateways)
	}
	return m.lines
}

// Lines returns the current ordered gateway line list (diagnostics).
func (m *Manager) Lines() []string {
	m.linesMu.Lock()
	defer m.linesMu.Unlock()
	if m.lines == nil {
		return nil
	}
	return m.lines.Addrs()
}
