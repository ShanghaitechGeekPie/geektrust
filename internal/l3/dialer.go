package l3

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
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

// Dialer establishes TCP connections through the tunnel. Inbound proxies
// depend only on its Dial method and never see aTrust details.
type Dialer struct {
	Manager  *tunnel.Manager
	Provider session.CredentialProvider
	Logger   *slog.Logger

	stackMu sync.Mutex
	stacks  map[*tunnel.Tunnel]*tcpStack
}

// Dial connects to an already-resolved tunnel IP:port (domain resolution
// happens in the inbound layer). appID is the authorizing application
// chosen by the resolver; if empty, it is looked up from the IP policy.
// domain carries the original hostname for wildcard-authorized targets.
// Failures are retried with the churn backoff; line-switch auth codes
// rotate the gateway line.
func (d *Dialer) Dial(ctx context.Context, ip string, port int, appID, domain string) (net.Conn, error) {
	// Validate before any tunnel work: the data plane is IPv4-only and the
	// wire narrows the port to uint16 (a wrapped value would mismatch the
	// auth request's destPort).
	if v4 := net.ParseIP(ip).To4(); v4 == nil {
		return nil, fmt.Errorf("dial %s:%d: only IPv4 targets are supported", ip, port)
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("dial %s:%d: port out of range 1..65535", ip, port)
	}
	var lastErr error
	attempts := 0
	for attempt := range dialAttempts {
		attempts = attempt + 1
		if attempt > 0 {
			d.Logger.Debug("dial retry", "ip", ip, "port", port,
				"attempt", attempt+1, "cause", lastErr)
			timer := time.NewTimer(dialRetryDelay * time.Duration(attempt))
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			}
		}
		conn, err := d.dialOnce(ctx, ip, port, appID, domain)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// A persistent auth rejection (e.g. address check) never changes
		// with retries; only churn (handshake loss) and line switches do.
		var rej *AuthRejectedError
		if errors.As(lastErr, &rej) && !rej.SwitchLine {
			break
		}
	}
	var rej *AuthRejectedError
	if errors.As(lastErr, &rej) && rej.Code == 10000005 {
		return nil, fmt.Errorf("dial %s:%d: gateway address check rejected the target; it is probably not an authorized VPN resource (code 10000005)", ip, port)
	}
	return nil, fmt.Errorf("dial %s:%d after %d attempt(s): %w", ip, port, attempts, lastErr)
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

func (d *Dialer) dialOnce(ctx context.Context, ip string, port int, appID, domain string) (net.Conn, error) {
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
	release := func() { transport.release(srcPort) }

	authID := tun.NextAuthID()
	body, err := buildAuthRequestIP(cred.SID, appID, cred.DeviceID, ip, port, tun.VIP(), srcPort, authID, domain)
	if err != nil {
		release()
		return nil, err
	}
	resp, err := tun.RequestAuth(ctx, authID, body)
	if err != nil {
		release()
		return nil, fmt.Errorf("per-conn auth: %w", err)
	}
	if resp.Code != 0 {
		release()
		rej := &AuthRejectedError{Code: resp.Code, Message: resp.Message, SwitchLine: resp.ShouldSwitchLine()}
		if rej.SwitchLine {
			d.Logger.Warn("per-conn auth requests line switch",
				"code", resp.Code, "message", resp.Message)
			d.Manager.SwitchLine()
		}
		return nil, rej
	}
	if resp.ConnectToken == "" {
		release()
		return nil, errors.New("per-conn auth returned no connectToken")
	}
	handshakeDeadline := time.Now().Add(tcpHandshakeTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(handshakeDeadline) {
		handshakeDeadline = ctxDeadline
	}
	if !transport.endpoint.updateRoute(srcPort, dataRoute{
		token: resp.ConnectToken, deadline: handshakeDeadline,
	}) {
		release()
		return nil, tunnel.ErrTunnelDead
	}

	conn, err := transport.dial(ctx, net.ParseIP(ip).To4(), srcPort, uint16(port), handshakeDeadline)
	if err != nil {
		// Expire the route immediately: the asynchronous FIFO may still contain
		// a SYN/RST, which must be dropped rather than sent after retry.
		transport.endpoint.updateRoute(srcPort, dataRoute{
			token: resp.ConnectToken, deadline: time.Now().Add(-time.Second),
		})
		transport.releaseLater(srcPort)
		return nil, err
	}
	routeAlive := transport.endpoint.updateRoute(srcPort, dataRoute{token: resp.ConnectToken})
	if !routeAlive {
		conn.Close()
		return nil, tunnel.ErrTunnelDead
	}
	return &managedTCPConn{TCPConn: conn, stack: transport, port: srcPort}, nil
}
