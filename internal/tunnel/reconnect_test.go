package tunnel

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ShanghaitechGeekPie/geektrust/internal/sdpc"
	"github.com/ShanghaitechGeekPie/geektrust/internal/session"
)

type managerTestProvider struct{}

func (managerTestProvider) Credential(ctx context.Context) (*session.Credential, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &session.Credential{SID: "test-session", Gateways: []string{"gateway.example:441"}}, nil
}
func (managerTestProvider) InvalidateIfCurrent(*session.Credential) bool { return false }

func TestManagerCloseCancelsConnect(t *testing.T) {
	m := NewManager(managerTestProvider{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.MaxAttempts = 1
	started := make(chan struct{})
	var once sync.Once
	m.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		once.Do(func() { close(started) })
		<-ctx.Done()
		return nil, ctx.Err()
	}
	result := make(chan error, 1)
	go func() { _, err := m.Tunnel(context.Background()); result <- err }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("connect did not start")
	}
	m.Close()
	m.Close()
	select {
	case err := <-result:
		if !errors.Is(err, ErrTunnelDead) {
			t.Fatalf("close result: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("close did not cancel connect")
	}
	if _, err := m.Tunnel(context.Background()); !errors.Is(err, ErrTunnelDead) {
		t.Fatal("closed manager reconnected")
	}
}

type groupTestProvider struct{ credential *session.Credential }

func (p *groupTestProvider) Credential(context.Context) (*session.Credential, error) {
	return p.credential, nil
}
func (p *groupTestProvider) InvalidateIfCurrent(c *session.Credential) bool { return c == p.credential }

func TestGroupManagerTracksGroupAcrossPolicyRefresh(t *testing.T) {
	p := &groupTestProvider{credential: &session.Credential{SID: "first", Policy: &sdpc.Resource{AppNodeGroups: map[string]string{"a": "g", "b": "g"}, NodeGroups: map[string][]string{"g": {"g:441"}, "h": {"h:441"}}}}}
	m := NewManager(p, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer m.Close()
	g, err := m.ForApp(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	p.credential = &session.Credential{SID: "second", Policy: &sdpc.Resource{AppNodeGroups: map[string]string{"a": "h", "b": "g"}, NodeGroups: map[string][]string{"g": {"g:441"}, "h": {"h:441"}}}}
	b, err := m.ForApp(context.Background(), "b")
	if err != nil {
		t.Fatal(err)
	}
	if b != g {
		t.Fatal("group manager not reused")
	}
	cred, err := b.provider.Credential(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(cred.Gateways) != 1 || cred.Gateways[0] != "g:441" {
		t.Fatalf("group g drifted to %v", cred.Gateways)
	}
	if !b.provider.InvalidateIfCurrent(cred) {
		t.Fatal("copied credential did not preserve identity")
	}
	conn, peer := net.Pipe()
	defer peer.Close()
	tun := &Tunnel{conn: conn, dead: make(chan struct{}), addr: "g:441"}
	b.cur = tun
	b.lines = NewLines([]string{"g:441", "other:441"})
	b.SwitchLine()
	if tun.Alive() {
		t.Fatal("selected group tunnel survived line switch")
	}
	m.Close()
	if _, err := m.ForApp(context.Background(), "b"); !errors.Is(err, ErrTunnelDead) {
		t.Fatal("closed manager accepted an app lookup")
	}
}
