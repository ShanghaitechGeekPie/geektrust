package webui

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"geektrust/internal/sdpc"
	"geektrust/internal/session"
)

type fakeProvider struct {
	sc        *sdpc.Client
	reloginOK atomic.Bool
	runCh     chan struct{}
}

func (f *fakeProvider) ActiveSDPC() *sdpc.Client { return f.sc }

func (f *fakeProvider) TryForceRelogin() (func(context.Context), bool) {
	if !f.reloginOK.Load() {
		return nil, false
	}
	return func(context.Context) { close(f.runCh) }, true
}

// newPanelTestServer starts the panel on a free loopback port with the
// canonical Web.Listen the Host check compares against.
func newPanelTestServer(t *testing.T, clientType string, provider ProviderAPI) (*httptest.Server, *Hub, *Broker) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(clientType)
	cfg.Web.Listen = listener.Addr().String()
	hub := NewHub(cfg)
	broker := NewBroker(hub.SetSMSPending)
	s := NewServer(hub, broker, provider, cfg)
	srv := httptest.NewUnstartedServer(s.http.Handler)
	srv.Listener = listener
	srv.Start()
	t.Cleanup(srv.Close)
	return srv, hub, broker
}

func doJSON(t *testing.T, client *http.Client, method, url string, body string, headers map[string]string) *http.Response {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

var jsonHeaders = map[string]string{"Content-Type": "application/json"}

func TestStatusHeadersAndRedLine(t *testing.T) {
	fp := &fakeProvider{}
	srv, hub, _ := newPanelTestServer(t, "client", fp)

	hub.OnSessionEvent(session.Event{
		Kind:    session.EventLoginFailed,
		Message: session.SanitizeErrorText(`cas chain: Get "https://x/auth/cas?ticket=ST-777": EOF`),
	})

	resp := doJSON(t, srv.Client(), "GET", srv.URL+"/api/status", "", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	for k, want := range map[string]string{
		"Content-Security-Policy": "frame-ancestors 'none'",
		"X-Frame-Options":         "DENY",
		"X-Content-Type-Options":  "nosniff",
	} {
		if got := resp.Header.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	body := readBody(t, resp)
	for _, forbidden := range []string{"ST-777", "synthetic-sid", "csrf_token"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("status body leaks %q", forbidden)
		}
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatal(err)
	}
	if m["state"] != StateOffline || m["device_id"] == "" || m["sms_gen"] != float64(0) {
		t.Errorf("snapshot = %v", m)
	}
	events, _ := m["events"].([]any)
	if len(events) != 1 {
		t.Fatalf("events = %v", events)
	}
	ev, _ := events[0].(map[string]any)
	if len(ev) != 3 || ev["ts"] == nil || ev["kind"] == nil || ev["message"] == nil {
		t.Errorf("event object = %v, want exactly ts/kind/message", ev)
	}
}

func TestHostOriginAndContentTypeChecks(t *testing.T) {
	fp := &fakeProvider{}
	srv, _, _ := newPanelTestServer(t, "client", fp)
	host := strings.TrimPrefix(srv.URL, "http://")

	// Wrong Host → 403 (DNS rebinding).
	req, _ := http.NewRequest("GET", srv.URL+"/api/status", nil)
	req.Host = "evil.example"
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 403 {
		t.Errorf("wrong Host = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()

	// Cross-site Origin POST → 403.
	resp = doJSON(t, srv.Client(), "POST", srv.URL+"/api/relogin", "{}",
		map[string]string{"Content-Type": "application/json", "Origin": "http://evil.example"})
	if resp.StatusCode != 403 {
		t.Errorf("cross Origin = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()

	// Non-JSON POST > 403.
	resp = doJSON(t, srv.Client(), "POST", srv.URL+"/api/relogin", "x=1",
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if resp.StatusCode != 403 {
		t.Errorf("form POST = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()

	// Near-JSON media types must not pass the exact check.
	resp = doJSON(t, srv.Client(), "POST", srv.URL+"/api/relogin", "{}",
		map[string]string{"Content-Type": "application/jsonp"})
	if resp.StatusCode != 403 {
		t.Errorf("jsonp POST = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()

	// Unknown API path > JSON 404 (not the frontend shell).
	resp = doJSON(t, srv.Client(), "POST", srv.URL+"/api/unknown", "{}", jsonHeaders)
	if resp.StatusCode != 404 {
		t.Errorf("unknown API = %d, want 404", resp.StatusCode)
	}
	if body := readBody(t, resp); !strings.Contains(body, `"error"`) {
		t.Errorf("unknown API body = %s", body)
	}

	// GET on a POST-only endpoint > JSON 404: with the catch-all routes the
	// method-specific patterns yield to the API fallback, which answers the
	// method contract as "no such endpoint".
	resp = doJSON(t, srv.Client(), "GET", srv.URL+"/api/sms", "", nil)
	if resp.StatusCode != 404 {
		t.Errorf("GET /api/sms = %d, want 404", resp.StatusCode)
	}
	resp.Body.Close()

	// Same-origin Origin header passes the middleware (reaches the handler,
	// which 409s because no login is in progress).
	resp = doJSON(t, srv.Client(), "POST", srv.URL+"/api/relogin", "{}",
		map[string]string{"Content-Type": "application/json", "Origin": "http://" + host})
	if resp.StatusCode == 403 {
		t.Errorf("same-origin POST rejected by middleware")
	}
	resp.Body.Close()
}

func TestEventsStream(t *testing.T) {
	fp := &fakeProvider{}
	srv, _, _ := newPanelTestServer(t, "client", fp)

	resp := doJSON(t, srv.Client(), "GET", srv.URL+"/api/events", "", nil)
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("events content-type = %q", ct)
	}
	// Read the complete first frame (through its terminating blank line).
	br := bufio.NewReader(resp.Body)
	var frame strings.Builder
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("reading first frame: %v", err)
		}
		if line == "\n" {
			break
		}
		frame.WriteString(line)
	}
	if !strings.HasPrefix(frame.String(), "data: ") || !strings.Contains(frame.String(), `"state":"offline"`) {
		t.Errorf("first frame = %q", frame.String())
	}
}

func TestSMSEndpoints(t *testing.T) {
	fp := &fakeProvider{}
	srv, _, broker := newPanelTestServer(t, "client", fp)

	// Bad code format → 400.
	resp := doJSON(t, srv.Client(), "POST", srv.URL+"/api/sms", `{"code":"12345","gen":1}`, jsonHeaders)
	if resp.StatusCode != 400 {
		t.Errorf("short code = %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()

	// No pending → 409.
	resp = doJSON(t, srv.Client(), "POST", srv.URL+"/api/sms", `{"code":"123456","gen":1}`, jsonHeaders)
	if resp.StatusCode != 409 {
		t.Errorf("no pending = %d, want 409", resp.StatusCode)
	}
	resp.Body.Close()

	// Resend without pending → 409.
	resp = doJSON(t, srv.Client(), "POST", srv.URL+"/api/sms/resend", `{"gen":1}`, jsonHeaders)
	if resp.StatusCode != 409 {
		t.Errorf("resend no pending = %d, want 409", resp.StatusCode)
	}
	resp.Body.Close()

	// Arm a prompt; the snapshot generation must drive a 202 submit.
	promptCh, cancel := startPrompt(broker, func(context.Context) error {
		return &sdpc.APIError{Op: "sms", Code: sdpc.CodeSMSStillValid, Message: "rate limited"}
	})
	defer cancel()
	gen := waitArmed(t, broker)

	var snap struct {
		SMSPending bool   `json:"sms_pending"`
		SMSGen     uint64 `json:"sms_gen"`
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		resp = doJSON(t, srv.Client(), "GET", srv.URL+"/api/status", "", nil)
		if err := json.Unmarshal([]byte(readBody(t, resp)), &snap); err == nil && snap.SMSPending && snap.SMSGen == gen {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("snapshot never showed pending gen %d", gen)
		}
		time.Sleep(2 * time.Millisecond)
	}

	// Stale generation → 409.
	resp = doJSON(t, srv.Client(), "POST", srv.URL+"/api/sms", `{"code":"123456","gen":999}`, jsonHeaders)
	if resp.StatusCode != 409 {
		t.Errorf("stale gen = %d, want 409", resp.StatusCode)
	}
	resp.Body.Close()

	// Typed rate-limit error → 429.
	body, _ := json.Marshal(map[string]uint64{"gen": gen})
	resp = doJSON(t, srv.Client(), "POST", srv.URL+"/api/sms/resend", string(body), jsonHeaders)
	if resp.StatusCode != 429 {
		t.Errorf("rate-limited resend = %d, want 429", resp.StatusCode)
	}
	if body := readBody(t, resp); !strings.Contains(body, "rate limited") {
		t.Errorf("429 body = %s", body)
	}

	// Valid submit > 202 and the prompt receives the code.
	resp = doJSON(t, srv.Client(), "POST", srv.URL+"/api/sms",
		fmt.Sprintf(`{"code":"123456","gen":%d}`, gen), jsonHeaders)
	if resp.StatusCode != 202 {
		t.Errorf("valid submit = %d, want 202", resp.StatusCode)
	}
	resp.Body.Close()
	if r := recvPrompt(t, promptCh); r.err != nil || r.code != "123456" {
		t.Fatalf("prompt = %+v", r)
	}

	// An expired controller authentication is accepted as an automatic
	// full-login restart, and the old prompt receives the typed cause so it can
	// retire instead of remaining stuck behind the dialog.
	expired := &sdpc.APIError{Op: "sms", Code: sdpc.CodeAuthTimeout, Message: "当前认证已超时"}
	promptCh, cancelExpired := startPrompt(broker, func(context.Context) error { return expired })
	defer cancelExpired()
	gen = waitArmed(t, broker)
	body, _ = json.Marshal(map[string]uint64{"gen": gen})
	resp = doJSON(t, srv.Client(), "POST", srv.URL+"/api/sms/resend", string(body), jsonHeaders)
	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("expired resend = %d, want 202", resp.StatusCode)
	}
	if body := readBody(t, resp); !strings.Contains(body, `"restarting":true`) {
		t.Errorf("expired resend body = %s", body)
	}
	if r := recvPrompt(t, promptCh); !sdpc.IsSessionExpired(r.err) {
		t.Fatalf("expired prompt = %+v", r)
	}
}

func TestReloginEndpoint(t *testing.T) {
	fp := &fakeProvider{runCh: make(chan struct{})}
	srv, _, _ := newPanelTestServer(t, "client", fp)

	resp := doJSON(t, srv.Client(), "POST", srv.URL+"/api/relogin", "{}", jsonHeaders)
	if resp.StatusCode != 409 {
		t.Errorf("busy relogin = %d, want 409", resp.StatusCode)
	}
	resp.Body.Close()

	fp.reloginOK.Store(true)
	resp = doJSON(t, srv.Client(), "POST", srv.URL+"/api/relogin", "{}", jsonHeaders)
	if resp.StatusCode != 202 {
		t.Errorf("relogin = %d, want 202", resp.StatusCode)
	}
	resp.Body.Close()
	select {
	case <-fp.runCh:
	case <-time.After(3 * time.Second):
		t.Fatal("reserved relogin run was not invoked")
	}
}

// trustController fakes the controller's trust-device endpoints.
func trustController(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/passport/v1/security/queryDevice":
			json.NewEncoder(w).Encode(map[string]any{
				"code": 0, "message": "OK",
				"data": map[string]any{
					"data":               []map[string]any{{"id": "dev-1", "deviceName": "Test-Mac", "onlineStatus": true}},
					"selfId":             "dev-1",
					"currentTrustStatus": 1,
					"trustDeviceConfig":  map[string]any{"enable": true},
				},
			})
		case r.URL.Path == "/passport/v1/security/trustDevice",
			r.URL.Path == "/passport/v1/security/untrustDevice",
			r.URL.Path == "/passport/v1/security/logoutDevice":
			json.NewEncoder(w).Encode(map[string]any{"code": 0, "message": "OK", "data": map[string]any{}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func sdpcToController(t *testing.T, controllerURL string) *sdpc.Client {
	t.Helper()
	sc := sdpc.NewClient(controllerURL, "Mac", "0123456789ABCDEF0123456789ABCDEF", &http.Client{})
	sc.SetCSRF("synthetic-csrf")
	return sc
}

func TestTrustDeviceEndpoints(t *testing.T) {
	t.Run("no active session", func(t *testing.T) {
		fp := &fakeProvider{}
		srv, _, _ := newPanelTestServer(t, "client", fp)
		resp := doJSON(t, srv.Client(), "GET", srv.URL+"/api/trust-devices", "", nil)
		if resp.StatusCode != 503 {
			t.Errorf("list without session = %d, want 503", resp.StatusCode)
		}
		resp.Body.Close()
	})

	t.Run("browser mode bind rejected", func(t *testing.T) {
		fp := &fakeProvider{sc: sdpcToController(t, "http://127.0.0.1:1")}
		srv, _, _ := newPanelTestServer(t, "browser", fp)
		resp := doJSON(t, srv.Client(), "POST", srv.URL+"/api/trust-devices/bind", "{}", jsonHeaders)
		if resp.StatusCode != 409 {
			t.Errorf("browser bind = %d, want 409", resp.StatusCode)
		}
		resp.Body.Close()
	})

	t.Run("full flow against fake controller", func(t *testing.T) {
		controller := trustController(t)
		fp := &fakeProvider{sc: sdpcToController(t, controller.URL)}
		srv, _, _ := newPanelTestServer(t, "client", fp)

		resp := doJSON(t, srv.Client(), "GET", srv.URL+"/api/trust-devices", "", nil)
		if resp.StatusCode != 200 {
			t.Fatalf("list = %d", resp.StatusCode)
		}
		var list map[string]any
		if err := json.Unmarshal([]byte(readBody(t, resp)), &list); err != nil {
			t.Fatal(err)
		}
		if list["selfId"] != "dev-1" || list["trustDeviceConfig"] == nil {
			t.Errorf("passthrough = %v", list)
		}

		for _, tc := range []struct {
			path, body string
		}{
			{"/api/trust-devices/bind", "{}"},
			{"/api/trust-devices/unbind", `{"ids":["dev-2"]}`},
			{"/api/trust-devices/logout", `{"id":"dev-1"}`},
		} {
			resp := doJSON(t, srv.Client(), "POST", srv.URL+tc.path, tc.body, jsonHeaders)
			if resp.StatusCode != 200 {
				t.Errorf("%s = %d, want 200", tc.path, resp.StatusCode)
			}
			resp.Body.Close()
		}

		// Empty id list → 400.
		resp = doJSON(t, srv.Client(), "POST", srv.URL+"/api/trust-devices/unbind", `{"ids":[]}`, jsonHeaders)
		if resp.StatusCode != 400 {
			t.Errorf("empty ids = %d, want 400", resp.StatusCode)
		}
		resp.Body.Close()
	})
}

func TestStaticPlaceholderWithoutFrontend(t *testing.T) {
	fp := &fakeProvider{}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := testConfig("client")
	cfg.Web.Listen = listener.Addr().String()
	hub := NewHub(cfg)
	server := NewServer(hub, NewBroker(hub.SetSMSPending), fp, cfg)
	server.hasUI = false // force the placeholder branch regardless of local build state
	srv := httptest.NewUnstartedServer(server.http.Handler)
	srv.Listener = listener
	srv.Start()
	defer srv.Close()

	resp := doJSON(t, srv.Client(), "GET", srv.URL+"/", "", nil)
	body := readBody(t, resp)
	if resp.StatusCode != 200 || !strings.Contains(body, "前端资源尚未构建") {
		t.Errorf("placeholder = %d %q", resp.StatusCode, body[:min(len(body), 80)])
	}
}

// TestStaticServesBuiltFrontend asserts the embedded production build is
// served end to end. It skips on clean checkouts where dist holds only
// .gitkeep (the placeholder path is covered above).
func TestStaticServesBuiltFrontend(t *testing.T) {
	fp := &fakeProvider{}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := testConfig("client")
	cfg.Web.Listen = listener.Addr().String()
	hub := NewHub(cfg)
	server := NewServer(hub, NewBroker(hub.SetSMSPending), fp, cfg)
	if !server.hasUI {
		t.Skip("frontend not built; run make web")
	}
	srv := httptest.NewUnstartedServer(server.http.Handler)
	srv.Listener = listener
	srv.Start()
	defer srv.Close()

	resp := doJSON(t, srv.Client(), "GET", srv.URL+"/", "", nil)
	body := readBody(t, resp)
	if resp.StatusCode != 200 || !strings.Contains(body, `id="root"`) {
		t.Fatalf("index = %d %q", resp.StatusCode, body[:min(len(body), 120)])
	}
	asset := strings.TrimPrefix(strings.TrimSpace(strings.Split(strings.Split(body, "src=")[1], "\"")[1]), "/")
	resp = doJSON(t, srv.Client(), "GET", srv.URL+"/"+asset, "", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("asset %s = %d", asset, resp.StatusCode)
	}
	resp.Body.Close()

	// SPA fallback: an unknown non-API path also gets the app shell.
	resp = doJSON(t, srv.Client(), "GET", srv.URL+"/some/route", "", nil)
	if body := readBody(t, resp); resp.StatusCode != 200 || !strings.Contains(body, `id="root"`) {
		t.Errorf("SPA fallback = %d", resp.StatusCode)
	}
}

// TestShutdownWithOpenEventStream is the regression test for the 5-second
// exit hang: SSE handlers never go idle on their own, so Shutdown must
// actively close the hub's subscribers to finish before its deadline.
func TestShutdownWithOpenEventStream(t *testing.T) {
	fp := &fakeProvider{}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := testConfig("client")
	cfg.Web.Listen = listener.Addr().String()
	hub := NewHub(cfg)
	server := NewServer(hub, NewBroker(hub.SetSMSPending), fp, cfg)
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()

	resp := doJSON(t, &http.Client{}, "GET", "http://"+cfg.Web.Listen+"/api/events", "", nil)
	defer resp.Body.Close()
	if _, err := bufio.NewReader(resp.Body).ReadString('\n'); err != nil {
		t.Fatalf("reading first SSE line: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown = %v after %v; the SSE stream kept the server alive", err, time.Since(start))
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("Shutdown took %v, want prompt teardown", elapsed)
	}
	if err := <-served; !errors.Is(err, http.ErrServerClosed) {
		t.Errorf("Serve returned %v, want ErrServerClosed", err)
	}

	// Post-shutdown subscribers get a pre-closed channel, never a hang.
	ch, _, cancelSub := hub.Subscribe()
	defer cancelSub()
	if _, ok := <-ch; ok {
		t.Error("Subscribe after CloseSubscribers returned a live channel")
	}
}

func TestStatusCacheControlNoStore(t *testing.T) {
	srv, _, _ := newPanelTestServer(t, "client", &fakeProvider{})
	resp := doJSON(t, srv.Client(), "GET", srv.URL+"/api/status", "", nil)
	resp.Body.Close()
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

func TestPostBodyTooLargeRejected(t *testing.T) {
	srv, _, _ := newPanelTestServer(t, "client", &fakeProvider{})
	huge := `{"code":"` + strings.Repeat("1", 128<<10) + `","gen":1}`
	resp := doJSON(t, srv.Client(), "POST", srv.URL+"/api/sms", huge, jsonHeaders)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("oversized POST = %d, want 400", resp.StatusCode)
	}
}

// TestStaticAssetCachingAndMissing pins the rebuild-safety contract: hashed
// assets are immutable, the shell always revalidates, and a purged asset is
// a hard 404 instead of HTML masquerading as JavaScript. Skips on clean
// checkouts without a built frontend.
func TestStaticAssetCachingAndMissing(t *testing.T) {
	fp := &fakeProvider{}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := testConfig("client")
	cfg.Web.Listen = listener.Addr().String()
	hub := NewHub(cfg)
	server := NewServer(hub, NewBroker(hub.SetSMSPending), fp, cfg)
	if !server.hasUI {
		t.Skip("frontend not built; run make web")
	}
	srv := httptest.NewUnstartedServer(server.http.Handler)
	srv.Listener = listener
	srv.Start()
	defer srv.Close()

	resp := doJSON(t, srv.Client(), "GET", srv.URL+"/", "", nil)
	body := readBody(t, resp)
	if got := resp.Header.Get("Cache-Control"); got != "no-cache" {
		t.Errorf("index Cache-Control = %q, want no-cache", got)
	}
	asset := strings.TrimPrefix(strings.TrimSpace(strings.Split(strings.Split(body, "src=")[1], "\"")[1]), "/")
	resp = doJSON(t, srv.Client(), "GET", srv.URL+"/"+asset, "", nil)
	resp.Body.Close()
	if got := resp.Header.Get("Cache-Control"); !strings.Contains(got, "immutable") {
		t.Errorf("asset Cache-Control = %q, want immutable", got)
	}

	resp = doJSON(t, srv.Client(), "GET", srv.URL+"/assets/index-ZZZZZZZZ.js", "", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("missing asset = %d, want 404", resp.StatusCode)
	}

	// Directory paths fall back to the shell instead of a listing.
	resp = doJSON(t, srv.Client(), "GET", srv.URL+"/assets", "", nil)
	if body := readBody(t, resp); resp.StatusCode != 200 || !strings.Contains(body, `id="root"`) {
		t.Errorf("directory path = %d, want SPA shell", resp.StatusCode)
	}
}
