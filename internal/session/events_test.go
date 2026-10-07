package session

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ShanghaitechGeekPie/geektrust/internal/sdpc"
	"github.com/ShanghaitechGeekPie/geektrust/internal/settings"
)

// recordObserver collects events and lets tests hook individual kinds.
type recordObserver struct {
	mu     sync.Mutex
	events []Event
	hook   func(Event)
}

func (o *recordObserver) OnSessionEvent(ev Event) {
	if o.hook != nil {
		o.hook(ev)
	}
	o.mu.Lock()
	o.events = append(o.events, ev)
	o.mu.Unlock()
}

func (o *recordObserver) kinds() []EventKind {
	o.mu.Lock()
	defer o.mu.Unlock()
	kinds := make([]EventKind, len(o.events))
	for i, ev := range o.events {
		kinds[i] = ev.Kind
	}
	return kinds
}

func (o *recordObserver) waitFor(t *testing.T, kind EventKind) Event {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		o.mu.Lock()
		for _, ev := range o.events {
			if ev.Kind == kind {
				o.mu.Unlock()
				return ev
			}
		}
		o.mu.Unlock()
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for event %q; got %v", kind, o.kinds())
	return Event{}
}

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

const testDeviceID = "0123456789ABCDEF0123456789ABCDEF"

func failingProvider(t *testing.T) *Provider {
	t.Helper()
	p := NewProvider(settings.Session{DeviceID: testDeviceID, BaseURL: "http://127.0.0.1:1", Platform: "Mac", ClientType: "browser"}, testLogger(), nil)
	p.Authenticate = func(context.Context, *http.Client) (string, error) {
		return "", errors.New("fixture authentication failed")
	}
	return p
}

func TestSanitizeErrorText(t *testing.T) {
	cases := []struct{ in, want string }{
		{`cas chain: Get "https://vpn.example/auth/cas?ticket=ST-12345&lang=zh-CN": dial`, `cas chain: Get "https://vpn.example/auth/cas?ticket=***&lang=zh-CN": dial`},
		{`Get "https://x/?sid=abc123": EOF`, `Get "https://x/?sid=***": EOF`},
		{`check "https://x/?code=654321": timeout`, `check "https://x/?code=***": timeout`},
		{`POST "https://x/?PASSWORD=hunter2&lang=zh-CN": refused`, `POST "https://x/?PASSWORD=***&lang=zh-CN": refused`},
		{"plain error without secrets", "plain error without secrets"},
	}
	for _, tt := range cases {
		if got := SanitizeErrorText(tt.in); got != tt.want {
			t.Errorf("sanitize(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
	long := strings.Repeat("a", 400)
	if got := SanitizeErrorText(long); len([]rune(got)) != 300 {
		t.Errorf("truncated rune count = %d, want 300", len([]rune(got)))
	}
	wide := strings.Repeat("界", 400)
	got := SanitizeErrorText(wide)
	if len([]rune(got)) != 300 || !strings.HasSuffix(got, "…") {
		t.Errorf("multibyte truncation broke UTF-8 or length: %d runes", len([]rune(got)))
	}
}

func TestLoginFailureEmitsOrderedEvents(t *testing.T) {
	p := failingProvider(t)
	obs := &recordObserver{}
	p.AddObserver(obs)

	if _, err := p.Credential(context.Background()); err == nil {
		t.Fatal("expected login failure")
	}
	failed := obs.waitFor(t, EventLoginFailed)
	kinds := obs.kinds()
	if len(kinds) != 2 || kinds[0] != EventLoginStart || kinds[1] != EventLoginFailed {
		t.Fatalf("event kinds = %v, want [login_start login_failed]", kinds)
	}
	if strings.Contains(failed.Message, "ST-") {
		t.Errorf("unsanitized message: %q", failed.Message)
	}
}

func TestObserverCallbackMayReenterProvider(t *testing.T) {
	p := failingProvider(t)
	var calls atomic.Int32
	done := make(chan struct{})
	obs := &recordObserver{hook: func(ev Event) {
		// The callback runs on the drainer; calling back into the provider
		// must not deadlock. Only reenter once to avoid an event loop.
		if ev.Kind == EventLoginStart && calls.CompareAndSwap(0, 1) {
			_, _ = p.Credential(context.Background())
			close(done)
		}
	}}
	p.AddObserver(obs)
	_, _ = p.Credential(context.Background())
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("observer reentering Credential deadlocked")
	}
}

// restoreHandler serves onlineInfo and clientResource for restore tests.
func restoreHandler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/passport/v1/user/onlineInfo":
		json.NewEncoder(w).Encode(map[string]any{
			"code": 0, "message": "OK",
			"data": map[string]any{"isOnline": true, "username": "u1", "displayName": "测试用户", "clientIp": "192.0.2.9"},
		})
	case "/controller/v1/user/clientResource":
		json.NewEncoder(w).Encode(map[string]any{
			"code": 0, "message": "OK",
			"data": map[string]any{
				"appList": map[string]any{"data": map[string]any{
					"appInfo": []any{},
					"config":  map[string]any{"nodeGroupConf": map[string]any{"nodeGroupList": []any{}}},
				}},
				"sdpPolicy": map[string]any{"data": map[string]any{
					"clientOption": map[string]any{"dnsOptionV2": map[string]any{"firstDNS": "192.0.2.53"}},
				}},
			},
		})
	default:
		http.NotFound(w, r)
	}
}

// newRestoreFixture returns a provider with a persisted session whose
// controller is backed by the given handler.
func newRestoreFixture(t *testing.T, handler http.HandlerFunc) *Provider {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.enc")
	if err := NewStore(statePath, false).Save(context.Background(), &State{
		ControllerURL: srv.URL, Username: "u1",
		SID:        "synthetic-sid",
		DeviceID:   testDeviceID,
		CsrfToken:  "synthetic-csrf",
		Cookies:    []CookieRecord{{Name: "sid", Value: "synthetic-sid"}},
		ClientType: "browser",
	}); err != nil {
		t.Fatal(err)
	}
	p := NewProvider(settings.Session{DeviceID: testDeviceID, BaseURL: srv.URL, Platform: "Mac", ClientType: "browser", Gateways: []string{"192.0.2.1:441"}, LegacyGatewayOverride: true}, testLogger(), nil)
	p.SetStore(NewStore(statePath, false))
	p.Authenticate = func(context.Context, *http.Client) (string, error) {
		return "", errors.New("fixture full login disabled")
	}
	return p
}

func TestRestoreSuccessEmitsSessionInfo(t *testing.T) {
	p := newRestoreFixture(t, restoreHandler)
	activeDuringEvent := make(chan bool, 1)
	obs := &recordObserver{hook: func(ev Event) {
		if ev.Kind == EventRestoreOK {
			// The credential must be published before the event is queued.
			_, sc := p.ActiveSession()
			activeDuringEvent <- sc != nil
		}
	}}
	p.AddObserver(obs)

	if _, err := p.Credential(context.Background()); err != nil {
		t.Fatalf("restore failed: %v", err)
	}
	ev := obs.waitFor(t, EventRestoreOK)
	select {
	case ok := <-activeDuringEvent:
		if !ok {
			t.Error("ActiveSession returned nil inside restore_success callback")
		}
	case <-time.After(time.Second):
		t.Fatal("restore_success hook did not run")
	}
	if ev.Session == nil {
		t.Fatal("restore_success carries no SessionInfo")
	}
	if ev.Session.Username != "u1" || ev.Session.DisplayName != "测试用户" || ev.Session.ClientIP != "192.0.2.9" {
		t.Errorf("user fields = %+v", ev.Session)
	}
	if ev.Session.ClientType != "browser" || ev.Session.DeviceID != testDeviceID {
		t.Errorf("device fields = %+v", ev.Session)
	}
	if len(ev.Session.DNS) != 1 || ev.Session.DNS[0] != "192.0.2.53" {
		t.Errorf("effective DNS = %v", ev.Session.DNS)
	}
	if len(ev.Session.Gateways) == 0 {
		t.Error("effective gateways empty")
	}
}

func TestTryForceReloginReservation(t *testing.T) {
	t.Run("forced run skips restore and publishes to joiners", func(t *testing.T) {
		// The persisted state would restore successfully; the forced run must
		// skip it (and fail on the missing keystore), while a joined Credential
		// waiter receives the same outcome.
		p := newRestoreFixture(t, restoreHandler)
		obs := &recordObserver{}
		p.AddObserver(obs)

		run, ok := p.TryForceRelogin()
		if !ok {
			t.Fatal("idle provider refused relogin")
		}
		waiter := make(chan error, 1)
		joined := signalJoin(context.Background())
		go func() {
			_, err := p.Credential(joined)
			waiter <- err
		}()
		waitForJoiner(t, joined)

		run(context.Background())
		if err := <-waiter; err == nil {
			t.Fatal("waiter got a credential; the forced run must skip restore and fail on the missing keystore")
		}
		obs.waitFor(t, EventLoginFailed)
		for _, kind := range obs.kinds() {
			if kind == EventRestoreOK {
				t.Fatal("forced run used the persisted restore path")
			}
		}
	})

	t.Run("idle reserves and releases", func(t *testing.T) {
		p := failingProvider(t)
		obs := &recordObserver{}
		p.AddObserver(obs)

		run, ok := p.TryForceRelogin()
		if !ok {
			t.Fatal("idle provider refused relogin")
		}
		if _, ok2 := p.TryForceRelogin(); ok2 {
			t.Fatal("second relogin accepted while reservation pending")
		}
		run(context.Background()) // fails: keystore missing
		obs.waitFor(t, EventLoginFailed)
		if _, ok3 := p.TryForceRelogin(); !ok3 {
			t.Fatal("relogin refused after reservation completed")
		}
	})

	t.Run("clears current session with event", func(t *testing.T) {
		p := failingProvider(t)
		obs := &recordObserver{}
		p.AddObserver(obs)
		p.mu.Lock()
		p.cur = &Credential{SID: "synthetic"}
		p.mu.Unlock()

		run, ok := p.TryForceRelogin()
		if !ok {
			t.Fatal("relogin refused")
		}
		p.mu.Lock()
		cur := p.cur
		forced := p.forceLogin
		p.mu.Unlock()
		if cur != nil {
			t.Error("relogin reservation did not clear the session")
		}
		if forced {
			t.Error("relogin reservation must not set the global forceLogin flag")
		}
		obs.waitFor(t, EventInvalidated)
		run(context.Background())
		obs.waitFor(t, EventLoginFailed)
	})

	t.Run("rejected while acquisition in flight", func(t *testing.T) {
		gate := make(chan struct{})
		probed := make(chan struct{})
		var once sync.Once
		p := newRestoreFixture(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/passport/v1/user/onlineInfo" {
				once.Do(func() { close(probed) })
				<-gate
			}
			restoreHandler(w, r)
		})

		credCh := make(chan error, 1)
		go func() {
			_, err := p.Credential(context.Background())
			credCh <- err
		}()
		select {
		case <-probed:
		case <-time.After(3 * time.Second):
			t.Fatal("restore did not reach onlineInfo")
		}
		if _, ok := p.TryForceRelogin(); ok {
			t.Fatal("relogin accepted while acquisition in flight")
		}
		close(gate)
		if err := <-credCh; err != nil {
			t.Fatalf("gated restore failed: %v", err)
		}
	})
}

func TestInvalidateIfCurrent(t *testing.T) {
	p := failingProvider(t)
	obs := &recordObserver{}
	p.AddObserver(obs)

	current := &Credential{SID: "current"}
	stale := &Credential{SID: "stale"}
	p.mu.Lock()
	p.cur = current
	p.mu.Unlock()

	if p.InvalidateIfCurrent(stale) {
		t.Fatal("stale expected invalidated the session")
	}
	p.mu.Lock()
	if p.cur != current || p.forceLogin {
		t.Error("stale invalidation mutated state")
	}
	p.mu.Unlock()

	if !p.InvalidateIfCurrent(current) {
		t.Fatal("current expected did not invalidate")
	}
	p.mu.Lock()
	if p.cur != nil || !p.forceLogin {
		t.Error("invalidation did not clear cur and set forceLogin")
	}
	p.mu.Unlock()
	obs.waitFor(t, EventInvalidated)
}

func TestDispatcherDropsOldestAndStampsCount(t *testing.T) {
	p := failingProvider(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	obs := &recordObserver{hook: func(Event) {
		once.Do(func() {
			close(entered)
			<-release // hold the drainer while the queue overflows
		})
	}}
	p.AddObserver(obs)

	p.emit(Event{Kind: EventLoginStart})
	<-entered
	// One event is in the blocked callback; 299 more queue behind it with
	// cap 256, so exactly 43 oldest events are dropped.
	const extra = 299
	for range extra {
		p.emit(Event{Kind: EventLoginFailed})
	}
	close(release)

	deadline := time.Now().Add(3 * time.Second)
	for {
		obs.mu.Lock()
		n := len(obs.events)
		var last Event
		if n > 0 {
			last = obs.events[n-1]
		}
		obs.mu.Unlock()
		if n == 257 && last.Dropped == 43 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("delivered %d events with last Dropped %d, want 257 and 43", n, last.Dropped)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// The join branch evaluates Done; this test context signals that point without production counters.
type joinContext struct {
	context.Context
	once   sync.Once
	joined chan struct{}
}

func signalJoin(ctx context.Context) *joinContext {
	return &joinContext{Context: ctx, joined: make(chan struct{})}
}
func (c *joinContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.joined) })
	return c.Context.Done()
}
func waitForJoiner(t *testing.T, c *joinContext) {
	t.Helper()
	select {
	case <-c.joined:
	case <-time.After(3 * time.Second):
		t.Fatal("caller did not join the production refresh")
	}
}

func TestFinishRefreshPublishesLoginSuccess(t *testing.T) {
	p := failingProvider(t)
	active := make(chan bool, 1)
	obs := &recordObserver{hook: func(ev Event) {
		if ev.Kind == EventLoginSuccess {
			_, sc := p.ActiveSession()
			active <- sc != nil
		}
	}}
	p.AddObserver(obs)

	call := &refreshCall{done: make(chan struct{})}
	p.mu.Lock()
	p.refreshing = call
	p.mu.Unlock()

	cred := &Credential{controller: &sdpc.Client{}, SID: "sid", DeviceID: testDeviceID, Gateways: []string{"g1"}}
	session := &SessionInfo{Username: "u1", DisplayName: "测试用户", DeviceID: testDeviceID}

	// A waiter joins the reserved slot and must receive the published result.
	waiter := make(chan error, 1)
	joined := signalJoin(context.Background())
	go func() {
		got, err := p.Credential(joined)
		if err == nil && got != cred {
			t.Errorf("waiter got %p, want %p", got, cred)
		}
		waiter <- err
	}()
	waitForJoiner(t, joined)

	p.finishRefresh(call, cred, session, false, nil)
	if err := <-waiter; err != nil {
		t.Fatalf("waiter error: %v", err)
	}
	ev := obs.waitFor(t, EventLoginSuccess)
	select {
	case ok := <-active:
		if !ok {
			t.Error("ActiveSession returned nil inside login_success callback")
		}
	case <-time.After(time.Second):
		t.Fatal("login_success hook did not run")
	}
	if ev.Session != session {
		t.Errorf("event session = %p, want %p", ev.Session, session)
	}
	if !strings.Contains(ev.Message, "测试用户") {
		t.Errorf("message = %q", ev.Message)
	}
	p.mu.Lock()
	if p.cur != cred || p.refreshing != nil {
		t.Error("finishRefresh did not publish the credential and clear the slot")
	}
	p.mu.Unlock()
}

func TestSessionInfoCopiesSlices(t *testing.T) {
	cred := &Credential{DeviceID: "d", Gateways: []string{"g1"}, DNS: []string{"n1"}}
	info := newSessionInfo(&sdpc.OnlineInfo{Username: "u"}, cred, "client")
	info.Gateways[0] = "mutated"
	if cred.Gateways[0] != "g1" {
		t.Error("SessionInfo aliases credential gateways")
	}
}

func TestInvalidationRejectsInFlightRestore(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	p := newRestoreFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/controller/v1/user/clientResource" {
			close(entered)
			<-release
		}
		restoreHandler(w, r)
	})
	defer p.Close()
	result := make(chan error, 1)
	go func() { _, err := p.Credential(context.Background()); result <- err }()
	<-entered
	p.Invalidate()
	close(release)
	if err := <-result; !errors.Is(err, ErrSessionReplaced) {
		t.Fatalf("stale restore = %v, want session replaced", err)
	}
	cred, sc := p.ActiveSession()
	if cred != nil || sc != nil {
		t.Fatal("invalidated acquisition published a controller or credential")
	}
}
