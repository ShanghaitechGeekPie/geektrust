package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ShanghaitechGeekPie/geektrust/internal/session"
)

type reconnectTestProvider struct {
	credential atomic.Pointer[session.Credential]
}

func (p *reconnectTestProvider) Credential(ctx context.Context) (*session.Credential, error) {
	return p.credential.Load(), ctx.Err()
}
func (p *reconnectTestProvider) InvalidateIfCurrent(*session.Credential) bool { return false }

type reconnectJoinedContext struct {
	context.Context
	joined chan struct{}
	once   sync.Once
}

func (c *reconnectJoinedContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.joined) })
	return c.Context.Done()
}

func newReconnectGateway(t *testing.T, beforeReply func(string)) (*Manager, *reconnectTestProvider) {
	t.Helper()
	certServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	cert := certServer.Certificate()
	certs := certServer.TLS.Certificates
	certServer.Close()
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: certs})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				br := bufio.NewReader(c)
				method := make([]byte, 3)
				if _, err := io.ReadFull(br, method); err != nil {
					return
				}
				header := make([]byte, 4)
				if _, err := io.ReadFull(br, header); err != nil {
					return
				}
				payload := make([]byte, binary.BigEndian.Uint16(header[2:]))
				if _, err := io.ReadFull(br, payload); err != nil {
					return
				}
				vipRequest := make([]byte, 10)
				if _, err := io.ReadFull(br, vipRequest); err != nil {
					return
				}
				var auth struct {
					SID string `json:"sid"`
				}
				if json.Unmarshal(payload, &auth) != nil {
					return
				}
				if beforeReply != nil {
					beforeReply(auth.SID)
				}
				body := []byte(`{"code":0,"data":{"deviceId":"test-device"}}`)
				reply := []byte{5, 0xd0, 0x53, 0}
				reply = binary.BigEndian.AppendUint16(reply, uint16(len(body)))
				reply = append(reply, body...)
				reply = append(reply, 5, 0, 0, 1, 10, 0, 0, 2, 0, 0)
				if _, err := c.Write(reply); err != nil {
					return
				}
				c.SetDeadline(time.Time{})
				io.Copy(io.Discard, br)
			}()
		}
	}()
	provider := &reconnectTestProvider{}
	provider.credential.Store(&session.Credential{SID: "old-session", Gateways: []string{listener.Addr().String()}})
	m := NewManager(provider, slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.MaxAttempts = 1
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	m.GatewayTLSConfig = &tls.Config{RootCAs: roots}
	t.Cleanup(m.Close)
	return m, provider
}

func TestSharedConnectSurvivesFirstWaiterCancellation(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "deadline"}[deadline], func(t *testing.T) {
			m, _ := newReconnectGateway(t, nil)
			entered := make(chan struct{})
			release := make(chan struct{})
			var once sync.Once
			m.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				once.Do(func() { close(entered) })
				select {
				case <-release:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
				return (&net.Dialer{}).DialContext(ctx, network, address)
			}
			var ctx context.Context
			var cancel context.CancelFunc
			if deadline {
				ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
			} else {
				ctx, cancel = context.WithCancel(context.Background())
			}
			defer cancel()
			first := make(chan error, 1)
			go func() { _, err := m.Tunnel(ctx); first <- err }()
			<-entered
			secondCtx := &reconnectJoinedContext{Context: context.Background(), joined: make(chan struct{})}
			second := make(chan error, 1)
			go func() { _, err := m.Tunnel(secondCtx); second <- err }()
			select {
			case <-secondCtx.joined:
			case <-time.After(time.Second):
				t.Fatal("second waiter did not join")
			}
			if !deadline {
				cancel()
			}
			err := <-first
			if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("first waiter: %v", err)
			}
			close(release)
			select {
			case err := <-second:
				if err != nil {
					t.Fatalf("remaining waiter failed: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("remaining waiter did not connect")
			}
			m.mu.Lock()
			tun := m.cur
			m.mu.Unlock()
			if tun == nil || !tun.Alive() {
				t.Fatal("successful shared connection was not published")
			}
		})
	}
}

func TestLastWaiterCancellationAllowsFreshConnect(t *testing.T) {
	m, _ := newReconnectGateway(t, nil)
	entered := make(chan struct{})
	canceled := make(chan struct{})
	cleanup := make(chan struct{})
	var calls atomic.Int32
	defer close(cleanup)
	m.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if calls.Add(1) == 1 {
			close(entered)
			<-ctx.Done()
			close(canceled)
			<-cleanup
			return nil, ctx.Err()
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { _, err := m.Tunnel(ctx); first <- err }()
	<-entered
	cancel()
	<-first
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("last waiter did not cancel underlying dial")
	}
	ctx2, done := context.WithTimeout(context.Background(), 3*time.Second)
	defer done()
	tun, err := m.Tunnel(ctx2)
	if err != nil || tun == nil || !tun.Alive() {
		t.Fatalf("fresh connection: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("underlying dials=%d, want 2", calls.Load())
	}
}

func TestManagerCloseUnblocksWaitersBeforeDialReturns(t *testing.T) {
	m := NewManager(managerTestProvider{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.MaxAttempts = 1
	entered := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	m.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		close(entered)
		<-release
		return nil, ctx.Err()
	}
	result := make(chan error, 1)
	go func() { _, err := m.Tunnel(context.Background()); result <- err }()
	<-entered
	m.Close()
	select {
	case err := <-result:
		if !errors.Is(err, ErrTunnelDead) {
			t.Fatalf("close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("close waited for injected dialer")
	}
}

func TestSharedConnectRechecksSessionAfterAuthentication(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	m, p := newReconnectGateway(t, func(sid string) {
		if sid == "old-session" {
			once.Do(func() { close(entered) })
			<-release
		}
	})
	result := make(chan *Tunnel, 1)
	errs := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		tun, err := m.Tunnel(ctx)
		result <- tun
		errs <- err
	}()
	<-entered
	old := p.credential.Load()
	p.credential.Store(&session.Credential{SID: "new-session", Gateways: old.Gateways})
	close(release)
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	if tun := <-result; tun == nil || tun.SID() != "new-session" {
		t.Fatal("returned tunnel authenticated with superseded session")
	}
}

func TestAuthenticatedTunnelOutlivesConnectContext(t *testing.T) {
	m, p := newReconnectGateway(t, nil)
	cred := p.credential.Load()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", cred.Gateways[0], m.GatewayTLSConfig)
	if err != nil {
		t.Fatal(err)
	}
	tun, err := authenticateTunnel(ctx, conn, cred.Gateways[0], cred.SID, m.logger)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	cancel()
	select {
	case <-tun.Dead():
		t.Fatal("canceling completed authentication killed the live tunnel")
	case <-time.After(20 * time.Millisecond):
	}
}
