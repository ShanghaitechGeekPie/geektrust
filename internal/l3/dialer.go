package l3

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"syscall"
	"time"

	"geektrust/internal/session"
	"geektrust/internal/tunnel"
)

const (
	// dialAttempts/dialRetryDelay implement the churn backoff: the gateway
	// briefly refuses new connections (no SYN-ACK) after rapid connect
	// churn. The delay scales with the attempt (1.5s, 3s, 4.5s) since
	// churn windows outlast a fixed pause. Persistent auth rejections
	// (e.g. address check) exit after one attempt instead.
	dialAttempts   = 4
	dialRetryDelay = 1500 * time.Millisecond
)

// Dialer establishes authenticated IP flows through the tunnel. Inbound
// proxies use TCP; the resolver also uses connected UDP for internal DNS.
type Dialer struct {
	Manager  *tunnel.Manager
	Provider session.CredentialProvider
	Logger   *slog.Logger

	stackMu sync.Mutex
	stacks  map[*tunnel.Tunnel]*tcpStack
}

// Dial connects to an already-resolved tunnel TCP target. appID is the
// authorizing application chosen by the resolver; domain carries the original
// hostname for wildcard-authorized targets.
func (d *Dialer) Dial(ctx context.Context, ip string, port int, appID, domain string) (net.Conn, error) {
	if err := validateTarget(ip, port); err != nil {
		return nil, err
	}
	return d.dialWithRetry(ctx, "tcp", ip, port, func() (net.Conn, error) {
		return d.dialOnce(ctx, ip, port, appID, domain)
	})
}

// DialUDP opens an authenticated connected UDP flow. It is intentionally
// exposed only to internal services such as split-horizon DNS; SOCKS5 UDP
// ASSOCIATE remains unsupported.
func (d *Dialer) DialUDP(ctx context.Context, ip string, port int, appID, domain string) (net.Conn, error) {
	if err := validateTarget(ip, port); err != nil {
		return nil, err
	}
	return d.dialWithRetry(ctx, "udp", ip, port, func() (net.Conn, error) {
		return d.dialUDPOnce(ctx, ip, port, appID, domain)
	})
}

func validateTarget(ip string, port int) error {
	if v4 := net.ParseIP(ip).To4(); v4 == nil {
		return fmt.Errorf("dial %s:%d: only IPv4 targets are supported", ip, port)
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("dial %s:%d: port out of range 1..65535", ip, port)
	}
	return nil
}

func (d *Dialer) dialWithRetry(ctx context.Context, network, ip string, port int, dial func() (net.Conn, error)) (net.Conn, error) {
	var lastErr error
	attempts := 0
	for attempt := range dialAttempts {
		attempts = attempt + 1
		if attempt > 0 {
			d.Logger.Debug("dial retry", "network", network, "ip", ip, "port", port,
				"attempt", attempt+1, "cause", lastErr)
			timer := time.NewTimer(dialRetryPause(attempt, lastErr))
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			}
		}
		conn, err := dial()
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// RST/connection-refused and persistent auth rejections cannot improve
		// on an immediate retry. Gateway busy and line-switch responses can.
		if !shouldRetryDial(lastErr) {
			break
		}
	}
	var rej *AuthRejectedError
	if errors.As(lastErr, &rej) && rej.Code == 10000005 {
		return nil, fmt.Errorf("dial %s:%d: gateway address check rejected the target; it is probably not an authorized VPN resource (code 10000005)", ip, port)
	}
	return nil, fmt.Errorf("dial %s:%d after %d attempt(s): %w", ip, port, attempts, lastErr)
}
func shouldRetryDial(err error) bool {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return false
	}
	var rejected *AuthRejectedError
	if errors.As(err, &rejected) {
		return rejected.SwitchLine || rejected.Code == 10000008
	}
	return true
}

func dialRetryPause(attempt int, err error) time.Duration {
	var rejected *AuthRejectedError
	if errors.As(err, &rejected) && rejected.Code == 10000008 {
		return 500 * time.Millisecond * time.Duration(attempt)
	}
	return dialRetryDelay * time.Duration(attempt)
}

// AuthRejectedError is a non-zero per-connection auth code from the gateway.
type AuthRejectedError struct {
	Code       int64
	Message    string
	SwitchLine bool // gateway asked for another line
}

func (e *AuthRejectedError) Error() string {
	return fmt.Sprintf("per-conn auth rejected: code %d: %s", e.Code, e.Message)
}

func (d *Dialer) stackFor(tun *tunnel.Tunnel) (*tcpStack, error) {
	d.stackMu.Lock()
	defer d.stackMu.Unlock()
	if current := d.stacks[tun]; current != nil {
		return current, nil
	}
	transport, err := newTCPStack(tun, d.Logger)
	if err != nil {
		return nil, err
	}
	if d.stacks == nil {
		d.stacks = make(map[*tunnel.Tunnel]*tcpStack)
	}
	d.stacks[tun] = transport
	go func() {
		<-tun.Dead()
		transport.destroy()
		d.stackMu.Lock()
		if d.stacks[tun] == transport {
			delete(d.stacks, tun)
		}
		d.stackMu.Unlock()
	}()
	return transport, nil
}

type authorizedFlow struct {
	transport *tcpStack
	srcPort   uint16
	token     string
}

func (f *authorizedFlow) release() {
	f.transport.release(f.srcPort)
}

func (d *Dialer) authorizeFlow(ctx context.Context, ip string, port int, appID, domain string, protocol int) (*authorizedFlow, error) {
	tun, err := d.Manager.Tunnel(ctx)
	if err != nil {
		return nil, err
	}
	cred, err := d.Provider.Credential(ctx)
	if err != nil {
		return nil, err
	}
	if appID == "" {
		appID = cred.Policy.AppIDFor(net.ParseIP(ip).To4(), port, cred.AppID)
	}
	transport, err := d.stackFor(tun)
	if err != nil {
		return nil, err
	}
	srcPort, err := tun.ReserveConn(transport.endpoint)
	if err != nil {
		return nil, err
	}
	if !transport.endpoint.addRoute(srcPort) {
		tun.UnregisterConn(srcPort)
		return nil, tunnel.ErrTunnelDead
	}
	flow := &authorizedFlow{transport: transport, srcPort: srcPort}

	authID := tun.NextAuthID()
	body, err := buildAuthRequestIP(cred.SID, appID, cred.DeviceID, ip, port, tun.VIP(), srcPort, authID, domain, protocol)
	if err != nil {
		flow.release()
		return nil, err
	}
	resp, err := tun.RequestAuth(ctx, authID, body)
	if err != nil {
		flow.release()
		return nil, fmt.Errorf("per-conn auth: %w", err)
	}
	if resp.Code != 0 {
		flow.release()
		rej := &AuthRejectedError{Code: resp.Code, Message: resp.Message, SwitchLine: resp.ShouldSwitchLine()}
		if rej.SwitchLine {
			d.Logger.Warn("per-conn auth requests line switch",
				"code", resp.Code, "message", resp.Message)
			d.Manager.SwitchLine()
		}
		return nil, rej
	}
	if resp.ConnectToken == "" {
		flow.release()
		return nil, errors.New("per-conn auth returned no connectToken")
	}
	flow.token = resp.ConnectToken
	return flow, nil
}

func (d *Dialer) dialOnce(ctx context.Context, ip string, port int, appID, domain string) (net.Conn, error) {
	flow, err := d.authorizeFlow(ctx, ip, port, appID, domain, protocolTCP)
	if err != nil {
		return nil, err
	}
	handshakeDeadline := time.Now().Add(tcpHandshakeTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(handshakeDeadline) {
		handshakeDeadline = ctxDeadline
	}
	if !flow.transport.endpoint.updateRoute(flow.srcPort, dataRoute{
		token: flow.token, deadline: handshakeDeadline,
	}) {
		flow.release()
		return nil, tunnel.ErrTunnelDead
	}

	conn, err := flow.transport.dial(ctx, net.ParseIP(ip).To4(), flow.srcPort, uint16(port), handshakeDeadline)
	if err != nil {
		// Expire the route immediately: the asynchronous FIFO may still contain
		// a SYN/RST, which must be dropped rather than sent after retry.
		flow.transport.endpoint.updateRoute(flow.srcPort, dataRoute{
			token: flow.token, deadline: time.Now().Add(-time.Second),
		})
		flow.transport.releaseLater(flow.srcPort)
		return nil, err
	}
	if !flow.transport.endpoint.updateRoute(flow.srcPort, dataRoute{token: flow.token}) {
		conn.Close()
		return nil, tunnel.ErrTunnelDead
	}
	return &managedTCPConn{TCPConn: conn, stack: flow.transport, port: flow.srcPort}, nil
}

func (d *Dialer) dialUDPOnce(ctx context.Context, ip string, port int, appID, domain string) (net.Conn, error) {
	flow, err := d.authorizeFlow(ctx, ip, port, appID, domain, protocolUDP)
	if err != nil {
		return nil, err
	}
	if !flow.transport.endpoint.updateRoute(flow.srcPort, dataRoute{token: flow.token}) {
		flow.release()
		return nil, tunnel.ErrTunnelDead
	}
	conn, err := flow.transport.dialUDP(ctx, net.ParseIP(ip).To4(), flow.srcPort, uint16(port))
	if err != nil {
		flow.release()
		return nil, err
	}
	return &managedUDPConn{UDPConn: conn, stack: flow.transport, port: flow.srcPort}, nil
}
