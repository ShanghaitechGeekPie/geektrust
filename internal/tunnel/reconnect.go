package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ShanghaitechGeekPie/geektrust/internal/frame"
	"github.com/ShanghaitechGeekPie/geektrust/internal/session"
)

const (
	reconnectBase        = 1 * time.Second
	reconnectMax         = 30 * time.Second
	sharedConnectTimeout = 45 * time.Second
)

// Manager owns the live tunnel: it (re)connects on demand with exponential
// backoff, switches gateway lines on tunnel-layer error codes, and forces a
// silent re-login when tunnel authentication keeps rejecting the session.
type Manager struct {
	groupsMu          sync.Mutex
	groups            map[string]*Manager
	MaxAttempts       int
	DialContext       func(context.Context, string, string) (net.Conn, error)
	GatewayTLSConfig  *tls.Config
	GatewayTrustStore GatewayTrustStore
	provider          session.CredentialProvider
	logger            *slog.Logger

	linesMu  sync.Mutex
	lines    *Lines
	gateways []string
	directMu sync.Mutex
	// directLines keeps line health per node-group gateway set. Direct TCP
	// connections are short-lived, so retaining the winning line avoids a
	// fresh multi-line race for every proxied connection.
	directLines map[string]*Lines

	closed     bool
	mu         sync.Mutex
	cur        *Tunnel
	connecting *connectCall
}

// connectCall is one in-flight connect shared by every concurrent caller:
// all waiters block on done and then read the same result.
type connectCall struct {
	done     chan struct{} // closed once err is populated
	cancel   context.CancelFunc
	waiters  int
	finished bool
	err      error
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
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		m.mu.Lock()
		closed := m.closed
		m.mu.Unlock()
		if closed {
			return nil, ErrTunnelDead
		}
		cred, err := m.provider.Credential(ctx)
		if err != nil {
			return nil, err
		}
		m.mu.Lock()
		if m.closed {
			m.mu.Unlock()
			return nil, ErrTunnelDead
		}
		if t := m.cur; t != nil && t.Alive() && t.SID() == cred.SID {
			m.mu.Unlock()
			return t, nil
		}
		if t := m.cur; t != nil {
			t.Close()
			m.cur = nil
		}
		call := m.connecting
		if call == nil {
			// Each waiter owns its cancellation. The shared operation stops only
			// when all waiters leave, the manager closes, or its total budget expires.
			connectCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), sharedConnectTimeout)
			call = &connectCall{done: make(chan struct{}), cancel: cancel}
			m.connecting = call
			go m.runConnect(connectCtx, call)
		}
		call.waiters++
		m.mu.Unlock()
		err = m.waitConnect(ctx, call)
		if err != nil {
			return nil, err
		}
		// Re-read credentials and the published tunnel after joining. A session
		// may have changed while authentication was in progress.
	}
}

func (m *Manager) waitConnect(ctx context.Context, call *connectCall) error {
	defer func() {
		m.mu.Lock()
		call.waiters--
		if call.waiters == 0 && !call.finished {
			if m.connecting == call {
				m.connecting = nil
			}
			call.cancel()
		}
		m.mu.Unlock()
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-call.done:
		if err := ctx.Err(); err != nil {
			return err
		}
		return call.err
	}
}

func (m *Manager) runConnect(ctx context.Context, call *connectCall) {
	t, err := m.connect(ctx)
	call.cancel()
	m.mu.Lock()
	if m.closed || m.connecting != call || call.waiters == 0 {
		if t != nil {
			t.Close()
			t = nil
		}
		if m.closed {
			err = ErrTunnelDead
		} else {
			err = context.Canceled
		}
	}
	if m.connecting == call {
		m.connecting = nil
		if err == nil {
			m.cur = t
		}
	}
	if !call.finished {
		call.err = err
		call.finished = true
		close(call.done)
	}
	m.mu.Unlock()
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
			// Cool the failed line down so the next TLS race starts with
			// another gateway.
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
	m.groupsMu.Lock()
	m.mu.Lock()
	m.closed = true
	if call := m.connecting; call != nil {
		m.connecting = nil
		call.cancel()
		if !call.finished {
			call.err = ErrTunnelDead
			call.finished = true
			close(call.done)
		}
	}
	t := m.cur
	m.cur = nil
	m.mu.Unlock()
	for _, g := range m.groups {
		g.Close()
	}
	m.groups = nil
	m.groupsMu.Unlock()
	if t != nil {
		t.Close()
	}
}

// connect retries dial+tunnel-auth with bounded exponential backoff. Line-switch codes rotate the pool; other tunnel-auth
// failures eventually invalidate the session for a silent re-login.
func (m *Manager) connect(ctx context.Context) (*Tunnel, error) {
	backoff := reconnectBase
	var lastErr error
	// Per session generation: which lines were tried at all, and which
	// reached tunnel auth and rejected it. The session is invalidated only
	// once every configured line has been tried and at least one rejection
	// came back from the auth stage (lines failing at TCP/TLS never reach
	// auth — e.g. internal gateways seen from outside — and must not block
	// the refresh decision).
	authRejects := make(map[string]int64)
	tried := make(map[string]bool)
	rejectSID := ""
	limit := m.MaxAttempts
	if limit <= 0 {
		limit = 3
	}
	for attempt := 0; attempt < limit; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		cred, err := m.provider.Credential(ctx)
		if err != nil {
			lastErr = err
			m.logger.Error("no valid session for tunnel", "err", err)
		} else {
			if cred.SID != rejectSID {
				authRejects = make(map[string]int64)
				tried = make(map[string]bool)
				rejectSID = cred.SID
			}
			lines := m.ensureLines(cred.Gateways)
			conn, addr, err := lines.DialTLS(ctx)
			if err != nil {
				lastErr = err
				if errors.Is(err, ErrNoLines) {
					return nil, err // empty line pool: configuration error
				}
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				m.logger.Warn("gateway TLS connection failed", "err", err)
			} else {
				t, err := authenticateTunnel(ctx, conn, addr, cred.SID, m.logger)
				if err == nil {
					return t, nil
				}
				m.logger.Warn("tunnel authentication failed", "addr", addr, "err", err)
				lastErr = err
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
			}
			if len(authRejects) > 0 && lines.allLinesTried(tried) {
				m.logger.Warn("tunnel auth rejected on every reachable line; re-logging in",
					"rejects", len(authRejects))
				// Only drop the credential we actually used: a concurrent
				// refresh may already have replaced it with a working one.
				m.provider.InvalidateIfCurrent(cred)
				authRejects = make(map[string]int64)
				tried = make(map[string]bool)
			}
		}

		if attempt+1 == limit {
			return nil, fmt.Errorf("tunnel connection failed after %d attempts: %w", limit, lastErr)
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
	return nil, errors.New("tunnel attempts exhausted")
}

// ensureLines rebuilds the line pool when the credential's gateway list
// changes (e.g. after a re-login fetched new nodeGroup addresses).
func (m *Manager) ensureLines(gateways []string) *Lines {
	m.linesMu.Lock()
	defer m.linesMu.Unlock()
	if m.lines == nil || !slices.Equal(m.gateways, gateways) {
		m.gateways = append([]string(nil), gateways...)
		m.lines = NewLines(gateways)
		m.lines.DialContext = m.DialContext
		m.lines.TLSConfig = m.GatewayTLSConfig
		m.lines.GatewayTrustStore = m.GatewayTrustStore
		m.logger.Debug("gateway line pool updated", "lines", gateways)
	}
	return m.lines
}

func (m *Manager) ensureDirectLines(gateways []string) *Lines {
	key := strings.Join(gateways, "\x00")
	m.directMu.Lock()
	defer m.directMu.Unlock()
	if m.directLines == nil {
		m.directLines = make(map[string]*Lines)
	}
	if m.directLines[key] == nil {
		m.directLines[key] = NewLines(gateways)
		m.directLines[key].DialContext = m.DialContext
		m.directLines[key].TLSConfig = m.GatewayTLSConfig
		m.directLines[key].GatewayTrustStore = m.GatewayTrustStore
	}
	return m.directLines[key]
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

type groupProvider struct {
	session.CredentialProvider
	group string
}

func (p groupProvider) Credential(ctx context.Context) (*session.Credential, error) {
	c, err := p.CredentialProvider.Credential(ctx)
	if err != nil {
		return nil, err
	}
	scoped := *c
	scoped.Original = c
	scoped.Gateways = c.GatewaysForGroup(p.group)
	return &scoped, nil
}
func (p groupProvider) InvalidateIfCurrent(c *session.Credential) bool {
	if c.Original == nil {
		return false
	}
	return p.CredentialProvider.InvalidateIfCurrent(c.Original)
}

// ForApp returns the manager that owns the application's gateway group.
func (m *Manager) ForApp(ctx context.Context, appID string) (*Manager, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	if closed {
		return nil, ErrTunnelDead
	}
	c, err := m.provider.Credential(ctx)
	if err != nil {
		return nil, err
	}
	if c.Policy == nil {
		return nil, errors.New("missing resource policy")
	}
	group := c.GatewayGroupForApp(appID)
	if group == "" && sameGatewayAddresses(c.Gateways, c.GatewaysForGroup("")) {
		return m, nil
	}
	m.groupsMu.Lock()
	m.mu.Lock()
	closed = m.closed
	m.mu.Unlock()
	if closed {
		m.groupsMu.Unlock()
		return nil, ErrTunnelDead
	}
	if m.groups == nil {
		m.groups = make(map[string]*Manager)
	}
	g := m.groups[group]
	if g == nil {
		g = NewManager(groupProvider{m.provider, group}, m.logger)
		g.MaxAttempts = m.MaxAttempts
		g.DialContext = m.DialContext
		g.GatewayTLSConfig = m.GatewayTLSConfig
		g.GatewayTrustStore = m.GatewayTrustStore
		m.groups[group] = g
	}
	m.groupsMu.Unlock()
	return g, nil
}

func sameGatewayAddresses(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
