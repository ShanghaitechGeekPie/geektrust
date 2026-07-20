package inbound

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// The aTrust IPv4 link MTU is 1400 bytes. Keeping payloads within one
	// IPv4/UDP packet avoids IP fragmentation, as required by RFC 9298.
	maxUDPPayload = 1400 - 20 - 8
	maxUDPFlows   = 64
	udpFlowIdle   = 5 * time.Minute
)

var errUDPDatagramTooLarge = errors.New("UDP datagram exceeds tunnel MTU")

type udpTarget struct {
	host string
	port int
}

func newUDPTarget(host string, port int) (udpTarget, error) {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" {
		return udpTarget{}, errors.New("empty UDP target host")
	}
	if port < 1 || port > 65535 {
		return udpTarget{}, fmt.Errorf("UDP target port %d out of range", port)
	}
	return udpTarget{host: host, port: port}, nil
}

func (t udpTarget) key() string {
	return net.JoinHostPort(t.host, strconv.Itoa(t.port))
}

type udpFlow struct {
	conn     net.Conn
	target   udpTarget
	lastUsed atomic.Int64
}

func (f *udpFlow) touch() {
	now := time.Now()
	f.lastUsed.Store(now.UnixNano())
	_ = f.conn.SetReadDeadline(now.Add(udpFlowIdle))
}

func (f *udpFlow) prepareWrite() {
	f.touch()
	_ = f.conn.SetWriteDeadline(time.Now().Add(handshakeLimit))
}

type udpFlowTable struct {
	ctx      context.Context
	cancel   context.CancelFunc
	server   *Server
	deliver  func(udpTarget, []byte) error
	maxFlows int

	closeOnce sync.Once
	mu        sync.Mutex
	closed    bool
	flows     map[string]*udpFlow
}

func newUDPFlowTable(ctx context.Context, server *Server, maxFlows int, deliver func(udpTarget, []byte) error) *udpFlowTable {
	if maxFlows < 1 {
		maxFlows = 1
	}
	flowCtx, cancel := context.WithCancel(ctx)
	t := &udpFlowTable{
		ctx: flowCtx, cancel: cancel, server: server, deliver: deliver,
		maxFlows: maxFlows, flows: make(map[string]*udpFlow),
	}
	go func() {
		<-flowCtx.Done()
		t.Close()
	}()
	return t
}

func (t *udpFlowTable) Open(ctx context.Context, target udpTarget) error {
	_, err := t.flow(ctx, target, false)
	return err
}

func (t *udpFlowTable) Send(target udpTarget, payload []byte) error {
	if len(payload) > maxUDPPayload {
		return errUDPDatagramTooLarge
	}
	for attempt := range 2 {
		flow, err := t.flow(t.ctx, target, true)
		if err != nil {
			return err
		}
		flow.prepareWrite()
		n, err := flow.conn.Write(payload)
		if err == nil && n == len(payload) {
			return nil
		}
		if err == nil {
			err = io.ErrShortWrite
		}
		t.remove(flow)
		flow.conn.Close()
		if t.ctx.Err() != nil {
			return t.ctx.Err()
		}
		if attempt == 1 {
			return err
		}
	}
	panic("unreachable")
}

func (t *udpFlowTable) flow(ctx context.Context, target udpTarget, boundSetup bool) (*udpFlow, error) {
	key := target.key()
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, net.ErrClosed
	}
	if flow := t.flows[key]; flow != nil {
		t.mu.Unlock()
		return flow, nil
	}
	t.mu.Unlock()

	if boundSetup {
		setupCtx, cancel := context.WithTimeout(ctx, handshakeLimit)
		defer cancel()
		ctx = setupCtx
	}

	resolved, err := t.server.resolver.ResolveUDP(ctx, target.host, target.port)
	if err != nil {
		return nil, err
	}
	conn, err := t.server.dialer.DialUDP(ctx, resolved.IP, target.port, resolved.AppID, resolved.Domain)
	if err != nil {
		return nil, err
	}
	flow := &udpFlow{conn: conn, target: target}
	flow.touch()

	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		conn.Close()
		return nil, net.ErrClosed
	}
	if existing := t.flows[key]; existing != nil {
		t.mu.Unlock()
		conn.Close()
		return existing, nil
	}
	if len(t.flows) >= t.maxFlows {
		oldest := t.oldestLocked()
		delete(t.flows, oldest.target.key())
		oldest.conn.Close()
	}
	t.flows[key] = flow
	t.mu.Unlock()

	go t.readFlow(flow)
	return flow, nil
}

func (t *udpFlowTable) oldestLocked() *udpFlow {
	var oldest *udpFlow
	for _, flow := range t.flows {
		if oldest == nil || flow.lastUsed.Load() < oldest.lastUsed.Load() {
			oldest = flow
		}
	}
	return oldest
}

func (t *udpFlowTable) readFlow(flow *udpFlow) {
	buffer := make([]byte, maxUDPPayload+1)
	for {
		n, err := flow.conn.Read(buffer)
		if err != nil {
			t.remove(flow)
			flow.conn.Close()
			return
		}
		flow.touch()
		if n > maxUDPPayload {
			continue
		}
		if err := t.deliver(flow.target, buffer[:n]); err != nil {
			t.Close()
			return
		}
	}
}

func (t *udpFlowTable) remove(flow *udpFlow) {
	t.mu.Lock()
	if t.flows[flow.target.key()] == flow {
		delete(t.flows, flow.target.key())
	}
	t.mu.Unlock()
}

func (t *udpFlowTable) Close() {
	t.closeOnce.Do(func() {
		t.cancel()
		t.mu.Lock()
		t.closed = true
		flows := make([]*udpFlow, 0, len(t.flows))
		for _, flow := range t.flows {
			flows = append(flows, flow)
		}
		clear(t.flows)
		t.mu.Unlock()
		for _, flow := range flows {
			flow.conn.Close()
		}
	})
}
