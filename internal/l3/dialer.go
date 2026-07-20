package l3

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"geektrust/internal/session"
	"geektrust/internal/tunnel"
)

const (
	// dialAttempts/dialRetryDelay implement the churn backoff: the gateway
	// briefly refuses new connections (no SYN-ACK, or auth code 10000005
	// "address check error") after rapid connect churn (TECHNICAL.md §12.2;
	// reference: 4 attempts, 1.5s apart). The delay scales with the attempt
	// (1.5s, 3s, 4.5s) since churn windows outlast a fixed pause.
	dialAttempts   = 4
	dialRetryDelay = 1500 * time.Millisecond
)

// Dialer establishes TCP connections through the tunnel (PLAN.md §2.1, §5.2).
// Inbound proxies depend only on its Dial method and never see aTrust details.
type Dialer struct {
	Manager  *tunnel.Manager
	Provider session.CredentialProvider
	Logger   *slog.Logger
}

// Dial connects to an already-resolved tunnel IP:port (domain resolution
// happens in the inbound layer, PLAN.md §2.1). Failures are retried with the
// churn backoff; line-switch auth codes rotate the gateway line.
func (d *Dialer) Dial(ctx context.Context, ip string, port int) (net.Conn, error) {
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
		conn, err := d.dialOnce(ctx, ip, port)
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
	SwitchLine bool // gateway asked for another line (TECHNICAL.md §11.2)
}

func (e *AuthRejectedError) Error() string {
	return fmt.Sprintf("per-conn auth rejected: code %d: %s", e.Code, e.Message)
}

func (d *Dialer) dialOnce(ctx context.Context, ip string, port int) (net.Conn, error) {
	tun, err := d.Manager.Tunnel(ctx)
	if err != nil {
		return nil, err
	}
	cred, err := d.Provider.Credential(ctx)
	if err != nil {
		return nil, err
	}

	appID := cred.AppID
	if mapped, ok := cred.IPApps[ip]; ok && mapped != "" {
		appID = mapped
	}

	srcPort, err := tun.AllocSrcPort()
	if err != nil {
		return nil, err
	}
	authID := tun.NextAuthID()
	body, err := buildAuthRequestIP(cred.SID, appID, cred.DeviceID, ip, port, tun.VIP(), srcPort, authID)
	if err != nil {
		return nil, err
	}

	// Register before auth so the reader can route the very first packets.
	conn := newTCPConn(tun, "", tun.VIP(), net.ParseIP(ip).To4(), srcPort, uint16(port))
	tun.RegisterConn(srcPort, conn)
	cleanup := func() {
		tun.UnregisterConn(srcPort)
		conn.Close()
	}

	resp, err := tun.RequestAuth(ctx, authID, body)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("per-conn auth: %w", err)
	}
	if resp.Code != 0 {
		cleanup()
		rej := &AuthRejectedError{Code: resp.Code, Message: resp.Message, SwitchLine: resp.ShouldSwitchLine()}
		if rej.SwitchLine {
			d.Logger.Warn("per-conn auth requests line switch",
				"code", resp.Code, "message", resp.Message)
			d.Manager.SwitchLine()
		}
		return nil, rej
	}
	if resp.ConnectToken == "" {
		cleanup()
		return nil, errors.New("per-conn auth returned no connectToken")
	}
	conn.token = resp.ConnectToken

	if err := conn.handshake(ctx); err != nil {
		cleanup()
		return nil, err
	}
	return conn, nil
}
