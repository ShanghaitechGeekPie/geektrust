package runtime

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ShanghaitechGeekPie/geektrust/internal/session"
)

func reviewClient(t *testing.T) *Runtime {
	t.Helper()
	c, err := New(contractOptions(&contractIdentity{subject: "account"}, &contractStore{state: validState()}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}
func TestConnectResultDoesNotOwnStatusMemory(t *testing.T) {
	c := reviewClient(t)
	info, err := c.Connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	original := info.Gateways[0]
	info.Gateways[0] = "caller mutation"
	if c.Status().Session.Gateways[0] != original {
		t.Fatal("caller mutated the runtime snapshot")
	}
}
func receiveReady(t *testing.T, ch <-chan Event) Event {
	t.Helper()
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	for {
		select {
		case e := <-ch:
			if e.Status.State == Ready {
				return e
			}
		case <-timer.C:
			t.Fatal("ready event missing")
		}
	}
}
func TestSubscriberSnapshotsAreIndependent(t *testing.T) {
	c := reviewClient(t)
	a := c.Subscribe(context.Background())
	b := c.Subscribe(context.Background())
	<-a
	<-b
	if _, err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	first, second := receiveReady(t, a), receiveReady(t, b)
	expected := second.Status.Session.Gateways[0]
	first.Status.Session.Gateways[0] = "one subscriber"
	if second.Status.Session.Gateways[0] != expected {
		t.Fatal("subscribers shared mutable snapshot memory")
	}
}
func TestLateSuccessDoesNotResurrectInvalidatedStatus(t *testing.T) {
	c := reviewClient(t)
	if _, err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	old := c.provider.Current()
	c.provider.Invalidate()
	o := clientObserver{c}
	o.OnSessionEvent(session.Event{Kind: session.EventInvalidated})
	o.OnSessionEvent(session.Event{Kind: session.EventLoginSuccess, Session: &session.SessionInfo{Generation: old.Generation, Username: old.Username}})
	if c.Status().State == Ready {
		t.Fatal("queued success resurrected an invalidated session")
	}
}
func TestDisjointGatewayFilterFailsConnect(t *testing.T) {
	opts := contractOptions(&contractIdentity{subject: "account"}, &contractStore{state: validState()})
	opts.Network.AllowedGateways = []string{"excluded.example:441"}
	c, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err = c.Connect(context.Background()); err == nil {
		t.Fatal("connect accepted a filter with no usable gateway")
	}
}

func TestInvalidationClosesBlockedConnection(t *testing.T) {
	c := reviewClient(t)
	if _, err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	defer right.Close()
	conn, err := c.ownConnection(c.provider.Current(), left, false)
	if err != nil {
		t.Fatal(err)
	}
	reading := make(chan error, 1)
	go func() { _, err := conn.Read(make([]byte, 1)); reading <- err }()
	c.provider.Invalidate()
	select {
	case err := <-reading:
		if err == nil {
			t.Fatal("invalidated read succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("old session left a blocked connection open")
	}
}

func TestIdentityWaitHonorsCancellation(t *testing.T) {
	i := blockingIdentity{make(chan struct{}), make(chan struct{})}
	o := contractOptions(&contractIdentity{subject: "account"}, &contractStore{state: validState()})
	o.Auth.Identity = i
	c, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	first := make(chan error, 1)
	go func() { _, err := c.Connect(context.Background()); first <- err }()
	<-i.entered
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	second := make(chan error, 1)
	go func() { _, err := c.Connect(ctx); second <- err }()
	select {
	case err := <-second:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("second caller = %v", err)
		}
	case <-time.After(time.Second):
		close(i.release)
		<-first
		t.Fatal("cancelled caller waited for another identity operation")
	}
	close(i.release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
}

type blockingSaveStore struct {
	contractStore
	entered, release, deleted chan struct{}
	mu                        sync.Mutex
	present                   bool
}

func (s *blockingSaveStore) Save(context.Context, SessionScope, []byte) error {
	close(s.entered)
	<-s.release
	s.mu.Lock()
	s.present = true
	s.mu.Unlock()
	return nil
}
func (s *blockingSaveStore) Delete(context.Context, SessionScope) error {
	s.mu.Lock()
	s.present = false
	s.mu.Unlock()
	close(s.deleted)
	return nil
}
func TestForgetOrdersDeletionAfterInFlightSave(t *testing.T) {
	s := &blockingSaveStore{contractStore: contractStore{state: validState()}, entered: make(chan struct{}), release: make(chan struct{}), deleted: make(chan struct{})}
	o := contractOptions(&contractIdentity{subject: "account"}, nil)
	o.SessionStore = s
	c, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	connecting := make(chan error, 1)
	go func() { _, err := c.Connect(context.Background()); connecting <- err }()
	<-s.entered
	forgetting := make(chan error, 1)
	go func() { forgetting <- c.ForgetSession(context.Background()) }()
	select {
	case <-s.deleted:
		close(s.release)
		<-connecting
		<-forgetting
		t.Fatal("session was deleted before its pending save completed")
	case <-time.After(30 * time.Millisecond):
	}
	close(s.release)
	<-connecting // either publication won the race or it was rejected
	if err := <-forgetting; err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	present := s.present
	s.mu.Unlock()
	if present || c.provider.Current() != nil {
		t.Fatal("forgotten session survived")
	}
}

func TestCancelledForgetPreservesCurrentSession(t *testing.T) {
	c := reviewClient(t)
	if _, err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	current := c.provider.Current()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Ready gates and a canceled context must never select a destructive path.
	for range 64 {
		if err := c.ForgetSession(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled forget = %v", err)
		}
		if c.provider.Current() != current {
			t.Fatal("already canceled forget invalidated the active session")
		}
	}
}

type slowCloseConn struct {
	net.Conn
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *slowCloseConn) Close() error {
	c.once.Do(func() { close(c.entered); <-c.release })
	return c.Conn.Close()
}

func TestShutdownDeadlineBoundsConnectionClose(t *testing.T) {
	c := reviewClient(t)
	if _, err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	defer right.Close()
	raw := &slowCloseConn{Conn: left, entered: make(chan struct{}), release: make(chan struct{})}
	if _, err := c.ownConnection(c.provider.Current(), raw, false); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- c.Shutdown(ctx) }()
	<-raw.entered
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("shutdown = %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Error("shutdown deadline did not bound connection close")
	}
	close(raw.release)
	if err := c.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestControllerRequestIsCancelledBySessionInvalidation(t *testing.T) {
	entered := make(chan struct{})
	o := contractOptions(&contractIdentity{subject: "account"}, &contractStore{state: validState()})
	o.Network.ControlTransport = controllerTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/passport/v1/security/queryDevice" {
			close(entered)
			<-r.Context().Done()
			return nil, r.Context().Err()
		}
		return (fixtureTransport{}).RoundTrip(r)
	})
	c, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { _, err := c.QueryTrustDevice(context.Background()); result <- err }()
	<-entered
	c.provider.Invalidate()
	select {
	case err := <-result:
		if !errors.Is(err, session.ErrSessionReplaced) {
			t.Fatalf("request = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("old controller request remained active")
	}
}

func TestLogoutCurrentDeviceInvalidatesSessionAndConnections(t *testing.T) {
	o := contractOptions(&contractIdentity{subject: "account"}, &contractStore{state: validState()})
	o.Network.ControlTransport = controllerTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/passport/v1/security/queryDevice" || r.URL.Path == "/passport/v1/security/logoutDevice" {
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"code":0,"data":{"selfId":"current-device"}}`))}, nil
		}
		return (fixtureTransport{}).RoundTrip(r)
	})
	c, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	defer right.Close()
	conn, err := c.ownConnection(c.provider.Current(), left, false)
	if err != nil {
		t.Fatal(err)
	}
	read := make(chan error, 1)
	go func() { _, err := conn.Read(make([]byte, 1)); read <- err }()
	if err := c.LogoutTrustDevice(context.Background(), "current-device"); err != nil {
		t.Fatal(err)
	}
	if c.provider.Current() != nil {
		t.Fatal("self logout left current credentials active")
	}
	select {
	case <-read:
	case <-time.After(time.Second):
		t.Fatal("self logout left a blocked connection open")
	}
}

func TestSessionEventsIncludeCurrentResources(t *testing.T) {
	o := contractOptions(&contractIdentity{subject: "account"}, &contractStore{state: validState()})
	o.Network.ControlTransport = controllerTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/controller/v1/user/clientResource" {
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"code":0,"data":{"appList":{"data":{"appInfo":[{"apps":[{"id":"resource-app","addressList":[{"host":"192.0.2.1","port":"443","protocol":"tcp"}]}]}]}}}}`))}, nil
		}
		return (fixtureTransport{}).RoundTrip(r)
	})
	c, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.provider.Credential(context.Background()); err != nil {
		t.Fatal(err)
	}
	event := receiveReady(t, c.Subscribe(context.Background()))
	if event.Status.Session == nil || len(event.Status.Session.Resources) != 1 || event.Status.Session.Resources[0].Address != "192.0.2.1" {
		t.Fatalf("session event omitted policy resources: %+v", event.Status.Session)
	}
}
