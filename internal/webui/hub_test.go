package webui

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"geektrust/internal/config"
	"geektrust/internal/session"
)

func testConfig(clientType string) *config.Config {
	return &config.Config{
		DeviceID:   "0123456789ABCDEF0123456789ABCDEF",
		ClientType: clientType,
		Inbound: config.Inbound{
			SOCKS5: config.Listener{Enabled: true, Listen: "127.0.0.1:1080"},
			HTTP:   config.Listener{Enabled: false},
		},
	}
}

func snapshotJSON(t *testing.T, h *Hub) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(h.Snapshot(), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestHubStateDerivation(t *testing.T) {
	h := NewHub(testConfig("client"))
	if got := snapshotJSON(t, h)["state"]; got != StateOffline {
		t.Fatalf("initial state = %v", got)
	}

	h.OnSessionEvent(session.Event{Kind: session.EventLoginStart})
	if got := snapshotJSON(t, h)["state"]; got != StateConnecting {
		t.Fatalf("after login_start = %v", got)
	}

	h.OnSessionEvent(session.Event{Kind: session.EventLoginSuccess, Session: &session.SessionInfo{
		Username: "u1", DisplayName: "测试用户", ClientIP: "192.0.2.9",
		DeviceID: "0123456789ABCDEF0123456789ABCDEF", ClientType: "client",
		Gateways: []string{"gw1:441"}, DNS: []string{"192.0.2.53"},
	}})
	m := snapshotJSON(t, h)
	if got := m["state"]; got != StateOnline {
		t.Fatalf("after login_success = %v", got)
	}
	user, _ := m["user"].(map[string]any)
	if user["username"] != "u1" || user["display_name"] != "测试用户" || user["client_ip"] != "192.0.2.9" {
		t.Errorf("user = %v", user)
	}
	if gw, _ := m["gateways"].([]any); len(gw) != 1 || gw[0] != "gw1:441" {
		t.Errorf("gateways = %v", m["gateways"])
	}
	if m["last_error"] != nil {
		t.Errorf("last_error = %v, want null", m["last_error"])
	}

	// invalidated clears session-derived fields.
	h.OnSessionEvent(session.Event{Kind: session.EventInvalidated})
	m = snapshotJSON(t, h)
	if m["state"] != StateOffline || m["user"] != nil || m["gateways"] != nil || m["dns"] != nil {
		t.Errorf("after invalidated: %v", m)
	}

	// login_failed records a sanitized error; a later restore clears it.
	h.OnSessionEvent(session.Event{Kind: session.EventLoginStart})
	h.OnSessionEvent(session.Event{Kind: session.EventLoginFailed, Message: "boom"})
	m = snapshotJSON(t, h)
	if m["state"] != StateOffline {
		t.Errorf("after login_failed state = %v", m["state"])
	}
	if m["last_error"] != "boom" {
		t.Errorf("last_error = %v", m["last_error"])
	}
	h.OnSessionEvent(session.Event{Kind: session.EventRestoreOK, Session: &session.SessionInfo{Username: "u1"}})
	m = snapshotJSON(t, h)
	if m["state"] != StateOnline || m["last_error"] != nil {
		t.Errorf("failure → restore_success left stale error: %v", m["last_error"])
	}
}

func TestHubSMSPendingCarriesGeneration(t *testing.T) {
	h := NewHub(testConfig("client"))
	h.SetSMSPending(true, 7)
	m := snapshotJSON(t, h)
	if m["state"] != StateSMSRequired || m["sms_pending"] != true || m["sms_gen"] != float64(7) {
		t.Errorf("armed snapshot = %v", m)
	}
	h.SetSMSPending(false, 0)
	m = snapshotJSON(t, h)
	if m["state"] != StateOffline || m["sms_pending"] != false || m["sms_gen"] != float64(0) {
		t.Errorf("cleared snapshot = %v", m)
	}
}

func TestHubHistoryShapeAndRing(t *testing.T) {
	h := NewHub(testConfig("client"))
	for range 60 {
		h.OnSessionEvent(session.Event{Kind: session.EventLoginStart, Time: time.Now(), Message: "m"})
	}
	raw := h.Snapshot()
	var m struct {
		Events []map[string]any `json:"events"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Events) != maxHistoryEvents {
		t.Fatalf("ring kept %d events, want %d", len(m.Events), maxHistoryEvents)
	}
	for i, ev := range m.Events {
		if len(ev) != 3 || ev["ts"] == nil || ev["kind"] == nil || ev["message"] == nil {
			t.Fatalf("event %d has keys %v, want exactly ts/kind/message", i, ev)
		}
	}
}

func TestHubSnapshotHasNoCredentials(t *testing.T) {
	h := NewHub(testConfig("client"))
	h.OnSessionEvent(session.Event{
		Kind:    session.EventLoginFailed,
		Message: session.SanitizeErrorText(`cas chain: Get "https://x/auth/cas?ticket=ST-999&lang=zh-CN": EOF`),
	})
	body := string(h.Snapshot())
	for _, forbidden := range []string{"ST-999", "csrf", "\"sid\""} {
		if strings.Contains(body, forbidden) {
			t.Errorf("snapshot leaks %q: %s", forbidden, body)
		}
	}
	if !strings.Contains(body, "ticket=***") {
		t.Errorf("sanitized message missing: %s", body)
	}
}

func TestHubDropsSlowSubscriber(t *testing.T) {
	h := NewHub(testConfig("client"))
	ch, initial, cancel := h.Subscribe()
	defer cancel()
	if !strings.Contains(string(initial), `"state":"offline"`) {
		t.Errorf("initial snapshot = %s", initial)
	}
	// Never drain: after more than the buffer of 8 broadcasts the hub must
	// disconnect the slow consumer instead of blocking.
	for range 12 {
		h.SetSMSPending(true, 1)
		h.SetSMSPending(false, 0)
	}
	select {
	case _, ok := <-ch:
		if ok {
			// Drain whatever was buffered; the channel must be closed by now.
			for range ch {
			}
			return
		}
	case <-time.After(time.Second):
		t.Fatal("slow subscriber was not disconnected")
	}
}
