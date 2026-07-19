// Package tunnel manages the TLS tunnel to the aTrust gateway: connection,
// one-shot tunnel authentication (VIP), heartbeat with active liveness
// detection, frame dispatch, and reconnection with line switching
// (TECHNICAL.md §5, §12; PLAN.md §5.1, §6).
package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"geektrust/internal/frame"
)

const (
	// HeartbeatInterval is the 0x15 send period (reference: 20s).
	HeartbeatInterval = 20 * time.Second
	// livenessLimit: no received frame for this long declares the tunnel
	// dead (PLAN.md §5.1: active "N consecutive misses" keepalive; 3× the
	// heartbeat interval).
	livenessLimit = 3 * HeartbeatInterval
	// watchInterval is how often the keepalive goroutine checks liveness.
	watchInterval = 10 * time.Second
	// authTimeout bounds a per-connection auth round trip (reference: 8s).
	authTimeout = 8 * time.Second
	// connectTimeout covers TCP+TLS+tunnel auth.
	connectTimeout = 15 * time.Second

	// firstSrcPort matches the reference client, which pre-increments from
	// 30000 (first allocation 30001). The gateway's address check rejects
	// 30000 with code 10000005.
	firstSrcPort = 30001
	lastSrcPort  = 65535
)

// ErrTunnelDead marks operations that failed because the tunnel died.
var ErrTunnelDead = errors.New("tunnel dead")

// PacketSink receives downlink IPv4 packets for one multiplexed connection.
// Implemented by l3.TCPConn; the tunnel never imports l3 (no cycle).
type PacketSink interface {
	DeliverPacket(pkt []byte)
}

// AuthResponse is a decoded per-connection auth reply (0x93).
type AuthResponse struct {
	Code         int64
	Message      string
	ConnectToken string
}

// ShouldSwitchLine reports tunnel-layer codes that mean "change gateway
// line" (TECHNICAL.md §11.2 — a different namespace from control-plane codes).
func (r *AuthResponse) ShouldSwitchLine() bool {
	switch r.Code {
	case 10000002, 10000003, 10000004, 99700001:
		return true
	}
	return false
}

type authResult struct {
	resp AuthResponse
	err  error
}

// Tunnel is one live TLS tunnel connection multiplexing many connections.
type Tunnel struct {
	conn     net.Conn
	reader   *frame.Reader
	writeMu  sync.Mutex
	vip      net.IP
	deviceID string
	logger   *slog.Logger
	addr     string

	authCounter atomic.Uint64
	portMu      sync.Mutex
	portNext    uint16

	connsMu sync.Mutex
	conns   map[uint16]PacketSink

	pendingMu sync.Mutex
	pending   map[uint64]chan authResult

	closeOnce sync.Once
	dead      chan struct{}
	lastRecv  atomic.Int64
}

// Dial connects to addr, performs the one-shot tunnel authentication and
// starts the reader and keepalive goroutines.
func Dial(ctx context.Context, addr, sid string, logger *slog.Logger) (*Tunnel, error) {
	dialCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()

	raw, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tunnel dial %s: %w", addr, err)
	}

	// The gateway accepts plain TLS without SPA (TECHNICAL.md §5.1). Its
	// certificate is issued for the portal hostname while we dial pool IPs,
	// so verification is disabled like every known client does.
	tlsCfg := &tls.Config{InsecureSkipVerify: true}
	if host, _, err := net.SplitHostPort(addr); err == nil && net.ParseIP(host) == nil {
		tlsCfg.ServerName = host
	}
	conn := tls.Client(raw, tlsCfg)
	if err := conn.HandshakeContext(dialCtx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("tunnel tls %s: %w", addr, err)
	}

	// Bound the auth exchange by the caller's deadline (or connectTimeout),
	// and unblock it if the context is canceled mid-exchange.
	deadline := time.Now().Add(connectTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	authDone := make(chan struct{})
	defer close(authDone)
	go func() {
		select {
		case <-ctx.Done():
			raw.Close()
		case <-authDone:
		}
	}()
	authFrames, err := frame.EncodeTunnelAuth(sid)
	if err != nil {
		raw.Close()
		return nil, err
	}
	if _, err := conn.Write(authFrames); err != nil {
		raw.Close()
		return nil, fmt.Errorf("tunnel auth write: %w", err)
	}
	// One bufio.Reader is shared by the auth reply and the frame loop.
	br := bufio.NewReader(conn)
	reply, err := frame.ReadTunnelAuthReply(br)
	if err != nil {
		raw.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})

	t := &Tunnel{
		conn:     conn,
		reader:   frame.NewReaderBuf(br),
		vip:      reply.VIP,
		deviceID: reply.DeviceID,
		logger:   logger,
		addr:     addr,
		conns:    make(map[uint16]PacketSink),
		pending:  make(map[uint64]chan authResult),
		dead:     make(chan struct{}),
		portNext: firstSrcPort,
	}
	t.lastRecv.Store(time.Now().UnixNano())
	go t.readLoop()
	go t.keepAlive()
	logger.Info("tunnel established", "addr", addr, "vip", reply.VIP.String(), "tunnel_device", reply.DeviceID)
	return t, nil
}

// VIP is the assigned virtual IPv4 address (uplink source / SNAT marker).
func (t *Tunnel) VIP() net.IP { return t.vip }

// DeviceID is the tunnel-internal device id from tunnel auth.
func (t *Tunnel) DeviceID() string { return t.deviceID }

// Addr is the gateway address this tunnel is connected to.
func (t *Tunnel) Addr() string { return t.addr }

// Dead is closed when the tunnel dies (read failure, heartbeat loss).
func (t *Tunnel) Dead() <-chan struct{} { return t.dead }

// Alive reports whether the tunnel is still up.
func (t *Tunnel) Alive() bool {
	select {
	case <-t.dead:
		return false
	default:
		return true
	}
}

// Close shuts the tunnel down.
func (t *Tunnel) Close() {
	t.markDead()
}

func (t *Tunnel) markDead() {
	t.closeOnce.Do(func() {
		close(t.dead)
		t.conn.Close()
		// Fail every in-flight per-connection auth.
		t.pendingMu.Lock()
		pending := t.pending
		t.pending = make(map[uint64]chan authResult)
		t.pendingMu.Unlock()
		for _, ch := range pending {
			// Non-blocking: the slot may already hold the real response,
			// which the requester then consumes instead.
			select {
			case ch <- authResult{err: ErrTunnelDead}:
			default:
			}
		}
	})
}

// --- multiplexing API used by l3 ---

// NextAuthID allocates the next conntrackHash (from 1, echoed by the gateway
// to match auth requests with responses under concurrency).
func (t *Tunnel) NextAuthID() uint64 { return t.authCounter.Add(1) }

// AllocSrcPort assigns an unused virtual source port. Downlink packets are
// routed back by this port, so it must be unique among live connections.
func (t *Tunnel) AllocSrcPort() (uint16, error) {
	t.portMu.Lock()
	defer t.portMu.Unlock()
	t.connsMu.Lock()
	defer t.connsMu.Unlock()
	for range lastSrcPort - firstSrcPort + 1 {
		port := t.portNext
		// Advance with wrap BEFORE uint16 overflow would make the
		// comparison below unreachable.
		if t.portNext == lastSrcPort {
			t.portNext = firstSrcPort
		} else {
			t.portNext++
		}
		if _, used := t.conns[port]; !used {
			return port, nil
		}
	}
	return 0, errors.New("no free virtual source port")
}

// RegisterConn routes downlink packets for srcPort to sink. Must be called
// before the handshake so the SYN-ACK can be routed.
func (t *Tunnel) RegisterConn(srcPort uint16, sink PacketSink) {
	t.connsMu.Lock()
	t.conns[srcPort] = sink
	t.connsMu.Unlock()
}

// UnregisterConn stops routing for srcPort (sends FIN first, see l3).
func (t *Tunnel) UnregisterConn(srcPort uint16) {
	t.connsMu.Lock()
	delete(t.conns, srcPort)
	t.connsMu.Unlock()
}

// RequestAuth sends a per-connection auth request (0x13) and waits for the
// matching 0x93 response (conntrackHash).
func (t *Tunnel) RequestAuth(ctx context.Context, authID uint64, body []byte) (*AuthResponse, error) {
	ch := make(chan authResult, 1)
	t.pendingMu.Lock()
	t.pending[authID] = ch
	t.pendingMu.Unlock()
	defer func() {
		t.pendingMu.Lock()
		delete(t.pending, authID)
		t.pendingMu.Unlock()
	}()

	if err := t.WriteFrame(frame.EncodeAuthRequest(body)); err != nil {
		return nil, err
	}

	timer := time.NewTimer(authTimeout)
	defer timer.Stop()
	select {
	case r := <-ch:
		return &r.resp, r.err
	case <-timer.C:
		return nil, fmt.Errorf("per-conn auth %d: timeout", authID)
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.dead:
		return nil, ErrTunnelDead
	}
}

// SendData sends one full IPv4 packet in an uplink 0x14 data frame.
func (t *Tunnel) SendData(token string, pkt []byte) error {
	fr, err := frame.EncodeData(token, pkt)
	if err != nil {
		return err
	}
	return t.WriteFrame(fr)
}

// writeTimeout bounds a single serialized write so a stalled socket cannot
// wedge the write lock (which would also stall the heartbeat and blind the
// liveness watchdog).
const writeTimeout = 30 * time.Second

// WriteFrame serializes a raw frame write (all writers share the lock).
func (t *Tunnel) WriteFrame(data []byte) error {
	if !t.Alive() {
		return ErrTunnelDead
	}
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	if !t.Alive() {
		return ErrTunnelDead
	}
	_ = t.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, err := t.conn.Write(data)
	_ = t.conn.SetWriteDeadline(time.Time{})
	if err != nil {
		t.markDead()
		return err
	}
	return nil
}

// --- background loops ---

func (t *Tunnel) readLoop() {
	defer t.markDead()
	for {
		fr, err := t.reader.ReadFrame()
		if err != nil {
			if t.Alive() {
				t.logger.Debug("tunnel read loop ended", "addr", t.addr, "err", err)
			}
			return
		}
		t.lastRecv.Store(time.Now().UnixNano())

		switch fr.Cmd {
		case frame.CmdAuthResponse:
			t.handleAuthResponse(fr.Payload)
		case frame.CmdDataResponse:
			for _, pkt := range fr.Packets {
				t.dispatch(pkt)
			}
		case frame.CmdHeartbeatResp:
			// Liveness only; lastRecv already updated.
		default:
			t.logger.Debug("tunnel ignoring frame", "cmd", fmt.Sprintf("0x%02x", fr.Cmd))
		}
	}
}

func (t *Tunnel) handleAuthResponse(payload []byte) {
	var parsed struct {
		Code    int64  `json:"code"`
		Message string `json:"message"`
		Data    struct {
			ConnectToken  string `json:"connectToken"`
			Token         string `json:"token"`
			ConntrackHash uint64 `json:"conntrackHash"`
		} `json:"data"`
	}
	if err := json.Unmarshal(payload, &parsed); err != nil {
		t.logger.Warn("tunnel: bad auth response", "err", err)
		return
	}
	token := parsed.Data.ConnectToken
	if token == "" {
		token = parsed.Data.Token
	}
	resp := authResult{resp: AuthResponse{
		Code:         parsed.Code,
		Message:      parsed.Message,
		ConnectToken: token,
	}}

	// Claim the entry before delivering: markDead then never sees a
	// dispatched request, so its failure sends cannot block on a full slot.
	t.pendingMu.Lock()
	ch, ok := t.pending[parsed.Data.ConntrackHash]
	if ok {
		delete(t.pending, parsed.Data.ConntrackHash)
	}
	t.pendingMu.Unlock()
	if !ok {
		t.logger.Debug("tunnel: auth response without pending request",
			"conntrack", parsed.Data.ConntrackHash, "code", parsed.Code)
		return
	}
	ch <- resp // buffered slot, requester has not received yet: never blocks
}

// dispatch routes a downlink IPv4 packet to the connection owning the TCP
// destination port (our virtual source port; TECHNICAL.md §7.4).
func (t *Tunnel) dispatch(pkt []byte) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 || pkt[9] != 6 {
		return
	}
	ihl := int(pkt[0]&0x0F) * 4
	if len(pkt) < ihl+4 {
		return
	}
	dport := binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])
	t.connsMu.Lock()
	sink := t.conns[dport]
	t.connsMu.Unlock()
	if sink == nil {
		t.logger.Debug("tunnel: packet for unknown port, dropping", "port", dport)
		return
	}
	sink.DeliverPacket(pkt)
}

// keepAlive sends heartbeats and declares death on sustained silence
// (PLAN.md §5.1 active keepalive, replacing the reference's send-only beat).
func (t *Tunnel) keepAlive() {
	beat := time.NewTicker(HeartbeatInterval)
	defer beat.Stop()
	watch := time.NewTicker(watchInterval)
	defer watch.Stop()
	for {
		select {
		case <-beat.C:
			if err := t.WriteFrame(frame.Heartbeat); err != nil {
				t.logger.Debug("tunnel heartbeat send failed", "addr", t.addr, "err", err)
				t.markDead()
				return
			}
		case <-watch.C:
			silence := time.Since(time.Unix(0, t.lastRecv.Load()))
			if silence > livenessLimit {
				t.logger.Warn("tunnel unresponsive, declaring dead",
					"addr", t.addr, "silence", silence.Round(time.Second))
				t.markDead()
				return
			}
		case <-t.dead:
			return
		}
	}
}
