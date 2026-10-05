package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/ShanghaitechGeekPie/geektrust/auth"
	"github.com/ShanghaitechGeekPie/geektrust/deployment"
	"github.com/ShanghaitechGeekPie/geektrust/internal/session"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type contractIdentity struct {
	calls   atomic.Int32
	subject string
}

func (i *contractIdentity) Info(context.Context) (auth.IdentityInfo, error) {
	i.calls.Add(1)
	return auth.IdentityInfo{Issuer: "fixture", Subject: i.subject, Kind: "passkey"}, nil
}
func (i *contractIdentity) Authenticate(context.Context, *http.Client, auth.IdentityRequest) error {
	return errors.New("unexpected authentication")
}

type contractStore struct {
	state session.State
	loads atomic.Int32
}

func (s *contractStore) Load(context.Context, SessionScope) ([]byte, error) {
	s.loads.Add(1)
	return json.Marshal(s.state)
}
func (s *contractStore) Save(context.Context, SessionScope, []byte) error { return nil }
func (s *contractStore) Delete(context.Context, SessionScope) error       { return nil }
func contractOptions(id *contractIdentity, store *contractStore) Options {
	return Options{ControllerURL: "https://controller.example", DeviceID: "0123456789ABCDEF0123456789ABCDEF", Auth: AuthOptions{Identity: id}, Deployment: deployment.Options{Profile: deployment.Generic, Fallbacks: &deployment.Fallbacks{ApplicationID: "app", Gateways: []string{"gateway.example:441"}}}, Network: NetworkOptions{ControlTransport: compatibilityTransport{}}, SessionStore: store}
}
func validState() session.State {
	return session.State{Version: 1, ControllerURL: "https://controller.example", IdentityIssuer: "fixture", IdentitySubject: "account", IdentityKind: "passkey", DeviceID: "0123456789ABCDEF0123456789ABCDEF", ClientType: "browser", SID: "secret", Cookies: []session.CookieRecord{{Name: "sid", Value: "secret"}}}
}
func TestNewAndScopedRestore(t *testing.T) {
	for _, wrong := range []bool{false, true} {
		i := &contractIdentity{subject: "account"}
		s := &contractStore{state: validState()}
		if wrong {
			s.state.ControllerURL = "https://other.example"
		}
		c, e := New(contractOptions(i, s))
		if e != nil {
			t.Fatal(e)
		}
		if i.calls.Load() != 0 || s.loads.Load() != 0 {
			t.Fatal("constructor performed I/O")
		}
		_, e = c.Connect(context.Background())
		if wrong && e == nil {
			t.Fatal("foreign cache accepted")
		}
		if !wrong && e != nil {
			t.Fatal(e)
		}
		c.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		if e = c.Shutdown(ctx); e != nil {
			t.Fatal(e)
		}
		cancel()
	}
}
func TestSubscribersAndIdentityChange(t *testing.T) {
	i := &contractIdentity{subject: "account"}
	s := &contractStore{state: validState()}
	c, e := New(contractOptions(i, s))
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	a := c.Subscribe(ctx)
	b := c.Subscribe(context.Background())
	<-a
	<-b
	cancel()
	if _, ok := <-a; ok {
		t.Fatal("canceled subscriber remained open")
	}
	if _, e = c.Connect(context.Background()); e != nil {
		t.Fatal(e)
	}
	select {
	case <-b:
	case <-time.After(time.Second):
		t.Fatal("second subscriber was canceled")
	}
	i.subject = "another"
	_, e = c.Connect(context.Background())
	var typed *Error
	if !errors.As(e, &typed) || typed.Info.Kind != ErrorIdentityChanged {
		t.Fatal("changed identity accepted")
	}
}
func TestExplicitEmptyGatewayList(t *testing.T) {
	i := &contractIdentity{subject: "account"}
	s := &contractStore{state: validState()}
	o := contractOptions(i, s)
	o.Network.AllowedGateways = []string{}
	c, e := New(o)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if _, e = c.Connect(context.Background()); e == nil {
		t.Fatal("empty allowed list used fallback gateways")
	}
}
func TestDNSCallbackPurposeAndSafeErrors(t *testing.T) {
	i := &contractIdentity{subject: "account"}
	s := &contractStore{state: validState()}
	o := contractOptions(i, s)
	seen := false
	o.CheckTarget = func(_ context.Context, target Target) error {
		seen = target.Purpose == DNSQueryTarget && target.IP == netip.MustParseAddr("192.0.2.53")
		return errors.New("do not expose ticket=secret")
	}
	c, e := New(o)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	e = (checkedDNSDialer{c}).check(context.Background(), "192.0.2.53", 53, "udp")
	if !seen || e == nil {
		t.Fatal("DNS target callback omitted")
	}
	wrapped := safeError("lookup", e)
	if strings.Contains(wrapped.Error(), "secret") || strings.Contains(errors.Unwrap(wrapped).Error(), "secret") {
		t.Fatal("error chain leaked secrets")
	}
}

type blockingIdentity struct {
	entered chan struct{}
	release chan struct{}
}

func (i blockingIdentity) Info(context.Context) (auth.IdentityInfo, error) {
	close(i.entered)
	<-i.release
	return auth.IdentityInfo{Issuer: "fixture", Subject: "account", Kind: "passkey"}, nil
}
func (i blockingIdentity) Authenticate(context.Context, *http.Client, auth.IdentityRequest) error {
	return nil
}
func TestShutdownBoundsUncooperativeIdentity(t *testing.T) {
	i := blockingIdentity{make(chan struct{}), make(chan struct{})}
	o := contractOptions(&contractIdentity{subject: "account"}, &contractStore{state: validState()})
	o.Auth.Identity = i
	c, e := New(o)
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { _, e := c.Connect(context.Background()); done <- e }()
	<-i.entered
	c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if e = c.Shutdown(ctx); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("shutdown did not honor deadline")
	}
	close(i.release)
	if e = <-done; e == nil {
		t.Fatal("late identity published a closed session")
	}
	if e = c.Shutdown(context.Background()); e != nil {
		t.Fatal(e)
	}
}

func TestExpiredSessionReauthenticates(t *testing.T) {
	i := &contractIdentity{subject: "account"}
	s := &contractStore{state: validState()}
	o := contractOptions(i, s)
	o.Network.ControlTransport = controllerTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"code":0,"data":{"isOnline":false}}`))}, nil
	})
	c, e := New(o)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if _, e = c.Connect(context.Background()); e == nil || !strings.Contains(e.Error(), "unexpected authentication") {
		t.Fatal("expired cached session blocked fresh authentication")
	}
}
