// Package webui implements the local status panel: a Hub holding the live
// state snapshot, the SMS Broker (web/terminal first-wins prompt), and an
// HTTP+SSE server. The panel is strictly an observer of the session
// provider: a panel failure must never affect the VPN data plane.
package webui

import (
	"encoding/json"
	"sync"
	"time"

	"geektrust/internal/config"
	"geektrust/internal/session"
)

// Panel states (§6.1 of docs/WEBUI.md).
const (
	StateOffline     = "offline"
	StateConnecting  = "connecting"
	StateSMSRequired = "sms_required"
	StateOnline      = "online"
)

const maxHistoryEvents = 50

// HistoryEvent is the JSON history unit; Session/Dropped from session.Event
// are observer-internal and never serialized here.
type HistoryEvent struct {
	TS      string `json:"ts"`
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

type userInfo struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	ClientIP    string `json:"client_ip"`
}

type proxyInfo struct {
	SOCKS5 *string `json:"socks5"`
	HTTP   *string `json:"http"`
}

// snapshot is the /api/status and SSE payload (§6.3).
type snapshot struct {
	State         string         `json:"state"`
	Since         time.Time      `json:"since"`
	LastError     *string        `json:"last_error"`
	User          *userInfo      `json:"user"`
	DeviceID      string         `json:"device_id"`
	ClientType    string         `json:"client_type"`
	Gateways      []string       `json:"gateways"`
	DNS           []string       `json:"dns"`
	Proxy         proxyInfo      `json:"proxy"`
	SMSPending    bool           `json:"sms_pending"`
	SMSGen        uint64         `json:"sms_gen"`
	EventsDropped uint64         `json:"events_dropped"`
	Events        []HistoryEvent `json:"events"`
}

// Hub keeps the live panel state. All mutations happen under mu; snapshots
// are broadcast after the lock is released... except the marshal is cheap
// and done under the lock, so subscribers always get a consistent view.
type Hub struct {
	mu         sync.Mutex
	deviceID   string
	clientType string
	proxy      proxyInfo

	acquiring     bool
	sessionActive bool
	smsPending    bool
	smsGen        uint64

	user      *userInfo
	gateways  []string
	dns       []string
	lastError *string
	state     string
	since     time.Time
	events    []HistoryEvent
	dropped   uint64

	subs map[chan []byte]struct{}
}

// NewHub builds a Hub carrying the static configuration fields.
func NewHub(cfg *config.Config) *Hub {
	h := &Hub{
		deviceID:   cfg.DeviceID,
		clientType: cfg.ClientType,
		state:      StateOffline,
		since:      time.Now(),
		subs:       make(map[chan []byte]struct{}),
	}
	if cfg.Inbound.SOCKS5.Enabled {
		listen := cfg.Inbound.SOCKS5.Listen
		h.proxy.SOCKS5 = &listen
	}
	if cfg.Inbound.HTTP.Enabled {
		listen := cfg.Inbound.HTTP.Listen
		h.proxy.HTTP = &listen
	}
	return h
}

// OnSessionEvent consumes a provider event: all state updates happen under
// the hub lock; the broadcast is marshaled and fanned out before unlock.
func (h *Hub) OnSessionEvent(ev session.Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch ev.Kind {
	case session.EventLoginStart:
		h.acquiring = true
		h.lastError = nil
	case session.EventLoginSuccess, session.EventRestoreOK:
		h.acquiring = false
		h.sessionActive = true
		h.lastError = nil
		if ev.Session != nil {
			h.user = &userInfo{
				Username:    ev.Session.Username,
				DisplayName: ev.Session.DisplayName,
				ClientIP:    ev.Session.ClientIP,
			}
			h.gateways = append([]string(nil), ev.Session.Gateways...)
			h.dns = append([]string(nil), ev.Session.DNS...)
		}
	case session.EventLoginFailed:
		h.acquiring = false
		h.sessionActive = false
		h.clearSessionLocked()
		msg := ev.Message
		h.lastError = &msg
	case session.EventInvalidated:
		h.sessionActive = false
		h.clearSessionLocked()
	}
	h.dropped = ev.Dropped
	h.appendEventLocked(ev)
	h.broadcastLocked()
}

func (h *Hub) clearSessionLocked() {
	h.user = nil
	h.gateways = nil
	h.dns = nil
}

// SetSMSPending is the Broker's pending callback and the sole source of the
// sms_required state and sms_gen value.
func (h *Hub) SetSMSPending(pending bool, gen uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.smsPending = pending
	h.smsGen = gen
	h.broadcastLocked()
}

func (h *Hub) appendEventLocked(ev session.Event) {
	he := HistoryEvent{
		TS:      ev.Time.Format(time.RFC3339),
		Kind:    string(ev.Kind),
		Message: ev.Message,
	}
	if len(h.events) >= maxHistoryEvents {
		h.events = h.events[1:]
	}
	h.events = append(h.events, he)
}

// deriveLocked computes the panel state from the three tracked facts.
func (h *Hub) deriveLocked() string {
	switch {
	case h.smsPending:
		return StateSMSRequired
	case h.acquiring:
		return StateConnecting
	case h.sessionActive:
		return StateOnline
	default:
		return StateOffline
	}
}

// broadcastLocked recomputes the state, refreshes `since` on transitions,
// and pushes the snapshot to every subscriber. Slow subscribers (full
// buffer) are disconnected instead of blocking the hub.
func (h *Hub) broadcastLocked() {
	state := h.deriveLocked()
	if state != h.state {
		h.state = state
		h.since = time.Now()
	}
	data, err := json.Marshal(h.snapshotLocked())
	if err != nil {
		return
	}
	for ch := range h.subs {
		select {
		case ch <- data:
		default:
			delete(h.subs, ch)
			close(ch)
		}
	}
}

func (h *Hub) snapshotLocked() snapshot {
	events := make([]HistoryEvent, len(h.events))
	copy(events, h.events)
	return snapshot{
		State:         h.state,
		Since:         h.since,
		LastError:     h.lastError,
		User:          h.user,
		DeviceID:      h.deviceID,
		ClientType:    h.clientType,
		Gateways:      h.gateways,
		DNS:           h.dns,
		Proxy:         h.proxy,
		SMSPending:    h.smsPending,
		SMSGen:        h.smsGen,
		EventsDropped: h.dropped,
		Events:        events,
	}
}

// Snapshot returns the current state as one JSON document.
func (h *Hub) Snapshot() []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	data, _ := json.Marshal(h.snapshotLocked())
	return data
}

// Subscribe registers an SSE channel (buffer 8) and returns it with the
// initial snapshot and a cancel function.
func (h *Hub) Subscribe() (ch chan []byte, initial []byte, cancel func()) {
	ch = make(chan []byte, 8)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	data, _ := json.Marshal(h.snapshotLocked())
	h.mu.Unlock()
	cancel = func() {
		h.mu.Lock()
		if _, ok := h.subs[ch]; ok {
			delete(h.subs, ch)
			close(ch)
		}
		h.mu.Unlock()
	}
	return ch, data, cancel
}
