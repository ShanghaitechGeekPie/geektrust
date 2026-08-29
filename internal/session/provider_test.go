package session

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"geektrust/internal/config"
	"geektrust/internal/sdpc"
)

type smsHandlerFunc func(context.Context, func(context.Context) error) (string, error)

func (f smsHandlerFunc) Prompt(ctx context.Context, resend func(context.Context) error) (string, error) {
	return f(ctx, resend)
}

// TestProviderSingleFlightBroadcast: every concurrent caller of Credential
// must observe the same in-flight login result (regression: a size-1 result
// channel stranded all waiters but one).
func TestProviderSingleFlightBroadcast(t *testing.T) {
	p := &Provider{store: NewStore(filepath.Join(t.TempDir(), "state.enc"))}

	var logins atomic.Int32
	// Stand in for the real login: slow, and counts invocations.
	acquire := func(ctx context.Context) (*Credential, error) {
		logins.Add(1)
		time.Sleep(50 * time.Millisecond)
		return &Credential{SID: "shared"}, nil
	}

	const waiters = 8
	var wg sync.WaitGroup
	results := make([]*Credential, waiters)
	errs := make([]error, waiters)

	// Drive the same code shape as Credential: one leader runs acquire,
	// the rest wait on the shared call.
	p.mu.Lock()
	call := &refreshCall{done: make(chan struct{})}
	p.refreshing = call
	p.mu.Unlock()

	for i := range waiters {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i == 0 {
				cred, err := acquire(context.Background())
				p.mu.Lock()
				p.cur = cred
				p.refreshing = nil
				p.mu.Unlock()
				call.cred, call.err = cred, err
				close(call.done)
				results[i], errs[i] = cred, err
				return
			}
			// Waiters join the in-flight call.
			p.mu.Lock()
			c := p.refreshing
			p.mu.Unlock()
			if c == nil {
				// Leader already finished: cached path.
				p.mu.Lock()
				results[i] = p.cur
				p.mu.Unlock()
				return
			}
			<-c.done
			results[i], errs[i] = c.cred, c.err
		}(i)
	}
	wg.Wait()

	if n := logins.Load(); n != 1 {
		t.Errorf("login ran %d times, want exactly 1", n)
	}
	for i := range waiters {
		if errs[i] != nil || results[i] == nil || results[i].SID != "shared" {
			t.Errorf("waiter %d got cred=%v err=%v", i, results[i], errs[i])
		}
	}
}

func TestRestoreSkipsDifferentClientType(t *testing.T) {
	tests := []struct {
		name       string
		stateType  string
		configType string
	}{
		{name: "browser state in client mode", stateType: "browser", configType: "client"},
		{name: "client state in browser mode", stateType: "client", configType: "browser"},
		{name: "legacy state in client mode", configType: "client"},
		{name: "legacy state in browser mode", configType: "browser"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			statePath := filepath.Join(t.TempDir(), "state.enc")
			store := NewStore(statePath)
			const deviceID = "0123456789ABCDEF0123456789ABCDEF"
			if err := store.Save(&State{
				SID:        "synthetic-session",
				DeviceID:   deviceID,
				Cookies:    []CookieRecord{{Name: "sid", Value: "synthetic-session"}},
				ClientType: tt.stateType,
			}); err != nil {
				t.Fatal(err)
			}

			p := &Provider{
				cfg: &config.Config{
					BaseURL:    "http://127.0.0.1:1",
					Platform:   "Mac",
					DeviceID:   deviceID,
					ClientType: tt.configType,
				},
				logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
				store:  store,
			}
			cred, session, err := p.restore(context.Background())
			if err != nil {
				t.Fatalf("restore returned error instead of skipping mismatched state: %v", err)
			}
			if cred != nil || session != nil {
				t.Fatalf("restore returned credential for mismatched state: %+v %+v", cred, session)
			}
		})
	}
}

// TestInvalidateSkipsRestore: after Invalidate the next refresh must not
// restore the rejected persisted session (regression: restore ran first and
// handed back the very credential the caller declared dead).
func TestInvalidateSkipsRestore(t *testing.T) {
	dir := t.TempDir()
	st := NewStore(filepath.Join(dir, "state.enc"))
	if err := st.Save(&State{SID: "old-session", DeviceID: "D", Cookies: []CookieRecord{{Name: "sid", Value: "old-session"}}}); err != nil {
		t.Fatal(err)
	}
	p := &Provider{store: st}

	p.Invalidate()
	p.mu.Lock()
	skip := p.forceLogin
	p.mu.Unlock()
	if !skip {
		t.Fatal("Invalidate must set forceLogin")
	}
	// acquire consumes the flag.
	p.mu.Lock()
	consumed := p.forceLogin
	p.forceLogin = false
	p.mu.Unlock()
	if !consumed {
		t.Fatal("forceLogin flag lost before acquire")
	}
}

// TestStoreKeyPermissionTightening: a pre-existing world-readable key file is
// tightened to 0600 on use (regression: permissive modes were accepted).
func TestStoreKeyPermissionTightening(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "state.enc.key")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	if err := os.WriteFile(keyPath, key, 0o644); err != nil {
		t.Fatal(err)
	}
	st := NewStore(filepath.Join(dir, "state.enc"))
	if err := st.Save(&State{SID: "s"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("key perm = %o, want 600", info.Mode().Perm())
	}
	// The original key must still decrypt the state (tighten, never replace).
	got, err := st.Load()
	if err != nil || got.SID != "s" {
		t.Errorf("Load after tighten = %v, %v", got, err)
	}
}

// TestStoreKeyExclusiveCreate: when the key appears between the missing-check
// and creation, the existing key wins (O_EXCL path).
func TestStoreKeyExclusiveCreate(t *testing.T) {
	dir := t.TempDir()
	st := NewStore(filepath.Join(dir, "state.enc"))
	// Simulate the winner: create the key first.
	winner := NewStore(filepath.Join(dir, "state.enc"))
	if err := winner.Save(&State{SID: "winner"}); err != nil {
		t.Fatal(err)
	}
	// A second store over the same files must reuse the winner's key.
	if err := st.Save(&State{SID: "second"}); err != nil {
		t.Fatal(err)
	}
	got, err := st.Load()
	if err != nil || got.SID != "second" {
		t.Errorf("Load = %v, %v", got, err)
	}
}

func TestSMSFlowRequestsFullLoginRestartAfterExpiredResend(t *testing.T) {
	var sends atomic.Int32
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/passport/v1/auth/sms" || r.URL.Query().Get("action") != "sendsms" {
			http.NotFound(w, r)
			return
		}
		code := int64(sdpc.CodeOK)
		message := "OK"
		if sends.Add(1) == 2 {
			code = sdpc.CodeAuthTimeout
			message = "当前认证已超时"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"code": code, "message": message, "data": map[string]any{}})
	}))
	defer controller.Close()

	p := &Provider{
		logger: testLogger(),
		smsHandler: smsHandlerFunc(func(ctx context.Context, resend func(context.Context) error) (string, error) {
			return "", resend(ctx)
		}),
	}
	sc := sdpc.NewClient(controller.URL, "Mac", "device", controller.Client())
	_, err := p.smsFlow(context.Background(), sc)
	if !errors.Is(err, errSMSAuthSessionExpired) {
		t.Fatalf("expired resend error = %v, want full-login restart marker", err)
	}
	if !sdpc.IsSessionExpired(err) {
		t.Fatalf("expired resend lost typed controller cause: %v", err)
	}
	if got := sends.Load(); got != 2 {
		t.Fatalf("send calls = %d, want initial send plus one resend", got)
	}
}

func TestSMSFlowRequestsFullLoginRestartAfterExpiredCodeCheck(t *testing.T) {
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/passport/v1/auth/sms" {
			http.NotFound(w, r)
			return
		}
		response := map[string]any{"code": int64(sdpc.CodeOK), "message": "OK", "data": map[string]any{}}
		if r.URL.Query().Get("action") == "checkcode" {
			response["code"] = sdpc.CodeSessionInvalid
			response["message"] = "会话无效"
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer controller.Close()

	p := &Provider{
		logger: testLogger(),
		smsHandler: smsHandlerFunc(func(context.Context, func(context.Context) error) (string, error) {
			return "123456", nil
		}),
	}
	sc := sdpc.NewClient(controller.URL, "Mac", "device", controller.Client())
	_, err := p.smsFlow(context.Background(), sc)
	if !errors.Is(err, errSMSAuthSessionExpired) {
		t.Fatalf("expired check error = %v, want full-login restart marker", err)
	}
	if !sdpc.IsSessionExpired(err) {
		t.Fatalf("expired check lost typed controller cause: %v", err)
	}
}

func TestSMSFlowDoesNotLoopWhenInitialSendAlreadyExpired(t *testing.T) {
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": sdpc.CodeAuthTimeout, "message": "当前认证已超时", "data": map[string]any{},
		})
	}))
	defer controller.Close()

	p := &Provider{logger: testLogger(), smsHandler: smsHandlerFunc(func(context.Context, func(context.Context) error) (string, error) {
		t.Fatal("prompt must not open after the initial send fails")
		return "", nil
	})}
	sc := sdpc.NewClient(controller.URL, "Mac", "device", controller.Client())
	_, err := p.smsFlow(context.Background(), sc)
	if err == nil || !sdpc.IsSessionExpired(err) {
		t.Fatalf("initial send error = %v, want typed session expiration", err)
	}
	if errors.Is(err, errSMSAuthSessionExpired) {
		t.Fatalf("initial send error was marked for an unbounded automatic retry: %v", err)
	}
}
