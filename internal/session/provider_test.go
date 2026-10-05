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
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/ShanghaitechGeekPie/geektrust/internal/sdpc"
	"github.com/ShanghaitechGeekPie/geektrust/internal/settings"
)

type smsHandlerFunc func(context.Context, func(context.Context) error) (string, error)

func (f smsHandlerFunc) Prompt(ctx context.Context, resend func(context.Context) error) (string, error) {
	return f(ctx, resend)
}

// TestProviderSingleFlightBroadcast: every concurrent caller of Credential
// must observe the same in-flight login result (regression: a size-1 result
// channel stranded all waiters but one).
func TestProviderSingleFlightBroadcast(t *testing.T) {
	p := failingProvider(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	sentinel := errors.New("fixture authentication stopped")
	var calls atomic.Int32
	p.Authenticate = func(context.Context, *http.Client) (string, error) {
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-release
		return "", sentinel
	}
	const count = 8
	out := make(chan error, count)
	go func() { _, e := p.Credential(context.Background()); out <- e }()
	<-entered
	var joined []*joinContext
	for i := 1; i < count; i++ {
		ctx := signalJoin(context.Background())
		joined = append(joined, ctx)
		go func() { _, e := p.Credential(ctx); out <- e }()
	}
	for _, ctx := range joined {
		waitForJoiner(t, ctx)
	}
	close(release)
	for i := 0; i < count; i++ {
		if e := <-out; !errors.Is(e, sentinel) {
			t.Fatalf("caller lost result: %v", e)
		}
	}
	if calls.Load() != 1 {
		t.Fatal("production authentication repeated")
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
			if err := store.Save(context.Background(), &State{
				SID:        "synthetic-session",
				DeviceID:   deviceID,
				Cookies:    []CookieRecord{{Name: "sid", Value: "synthetic-session"}},
				ClientType: tt.stateType,
			}); err != nil {
				t.Fatal(err)
			}

			p := &Provider{
				cfg: &settings.Session{
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
	var probes atomic.Int32
	p := newRestoreFixture(t, func(w http.ResponseWriter, r *http.Request) { probes.Add(1); restoreHandler(w, r) })
	called := false
	stop := errors.New("forced login")
	p.Authenticate = func(context.Context, *http.Client) (string, error) { called = true; return "", stop }
	p.Invalidate()
	if _, e := p.Credential(context.Background()); !errors.Is(e, stop) || !called {
		t.Fatal("real login path not used")
	}
	if probes.Load() != 0 {
		t.Fatal("invalidated session was restored")
	}
}

func TestStoreReadPreservesExistingPermissions(t *testing.T) {
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
	if err := st.Save(context.Background(), &State{SID: "s"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o644 {
		t.Errorf("key perm = %o, want 644", info.Mode().Perm())
	}
	// The original key must still decrypt the state (tighten, never replace).
	got, err := st.Load(context.Background())
	if err != nil || got.SID != "s" {
		t.Errorf("Load after tighten = %v, %v", got, err)
	}
}

// TestStoreReusesExistingKey: when the key appears between the missing-check
// and creation, the existing key wins (O_EXCL path).
func TestStoreReusesExistingKey(t *testing.T) {
	dir := t.TempDir()
	st := NewStore(filepath.Join(dir, "state.enc"))
	// Simulate the winner: create the key first.
	winner := NewStore(filepath.Join(dir, "state.enc"))
	if err := winner.Save(context.Background(), &State{SID: "winner"}); err != nil {
		t.Fatal(err)
	}
	// A second store over the same files must reuse the winner's key.
	if err := st.Save(context.Background(), &State{SID: "second"}); err != nil {
		t.Fatal(err)
	}
	got, err := st.Load(context.Background())
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
