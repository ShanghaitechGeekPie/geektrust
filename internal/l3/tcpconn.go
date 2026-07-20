package l3

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"geektrust/internal/tunnel"
)

const (
	// handshakeTimeout bounds the SYN → SYN-ACK wait.
	handshakeTimeout = 8 * time.Second
	// inQueue bounds per-connection pending downlink packets. When full,
	// packets are dropped; the remote TCP retransmits since we never ACK
	// them. Dropping keeps the shared reader loop alive.
	inQueue = 256
	// recvCap bounds buffered unread receive data. At the cap we advertise
	// a zero window until the application drains (backpressure); without it
	// a stalled proxy client would let the reassembly buffer grow without
	// bound while we keep ACKing.
	recvCap   = 256 * 1024
	maxWindow = 65535
)

// tunnelLink is the slice of *tunnel.Tunnel a TCP endpoint needs. Narrowing
// it keeps the endpoint testable without a live gateway connection.
type tunnelLink interface {
	// SendData writes one packet; deadline bounds the serialized socket
	// write (zero = the tunnel's global timeout only).
	SendData(token string, pkt []byte, deadline time.Time) error
	Dead() <-chan struct{}
	UnregisterConn(srcPort uint16)
}

// TCPConn is a userspace TCP endpoint carried by the tunnel.
// It implements net.Conn for the inbound proxies and tunnel.PacketSink for
// downlink dispatch.
//
// Concurrency model: one run() goroutine owns the receive state machine and
// sends ACKs; Write sends data segments under seqMu. Lock order is seqMu → mu
// (never reversed); the tunnel write lock is only ever taken inside seqMu.
type TCPConn struct {
	tun     tunnelLink
	token   string
	vip     net.IP
	dstIP   net.IP
	srcPort uint16
	dstPort uint16

	// seqMu guards the sequence/send state.
	seqMu         sync.Mutex
	mySeq         uint32
	peerSeq       uint32
	synSeen       bool
	writeClosed   bool
	finPending    uint32 // FIN end-seq received out of order
	hasFinPending bool

	// mu guards the receive buffer and lifecycle read state; notify is
	// closed and replaced to wake all readers (broadcast).
	mu            sync.Mutex
	buf           bytes.Buffer
	ooo           map[uint32][]byte
	oooBytes      int
	readErr       error // io.EOF on FIN/tunnel death, error on RST
	zeroWin       bool  // last ACK advertised window 0
	notify        chan struct{}
	readDeadline  time.Time
	writeDeadline time.Time

	in   chan []byte
	once sync.Once
	done chan struct{} // closed when run() exits
	quit chan struct{} // closed by Close/abort; stops run()

	handshakeCh chan struct{} // closed once SYN-ACK arrives
}

var (
	_ net.Conn          = (*TCPConn)(nil)
	_ tunnel.PacketSink = (*TCPConn)(nil)
)

// newTCPConn creates the endpoint and starts its receive goroutine. The
// caller must RegisterConn before the handshake so the SYN-ACK routes here.
func newTCPConn(tun tunnelLink, token string, vip, dstIP net.IP, srcPort, dstPort uint16) *TCPConn {
	c := &TCPConn{
		tun:         tun,
		token:       token,
		vip:         vip,
		dstIP:       dstIP,
		srcPort:     srcPort,
		dstPort:     dstPort,
		ooo:         make(map[uint32][]byte),
		notify:      make(chan struct{}),
		in:          make(chan []byte, inQueue),
		done:        make(chan struct{}),
		quit:        make(chan struct{}),
		handshakeCh: make(chan struct{}),
	}
	go c.run()
	return c
}

// DeliverPacket enqueues a downlink IPv4 packet (called by the tunnel reader;
// never blocks).
func (c *TCPConn) DeliverPacket(pkt []byte) {
	select {
	case c.in <- pkt:
	default: // queue full: drop; unACKed data is retransmitted by the peer
	case <-c.done:
	}
}

// run owns the receive state machine.
func (c *TCPConn) run() {
	defer close(c.done)
	for {
		select {
		case pkt := <-c.in:
			c.onPacket(pkt)
		case <-c.quit:
			return
		case <-c.tun.Dead():
			c.abort(io.EOF)
			return
		}
	}
}

func (c *TCPConn) onPacket(pkt []byte) {
	seg, ok := parseTCP(pkt)
	if !ok {
		return
	}

	c.seqMu.Lock()
	if seg.flags&flagSYN != 0 && !c.synSeen {
		// SYN-ACK completes the handshake.
		c.synSeen = true
		c.peerSeq = seg.seq + 1
		c.seqMu.Unlock()
		close(c.handshakeCh)
		return
	}
	if seg.flags&flagRST != 0 {
		c.seqMu.Unlock()
		c.abort(errors.New("connection reset by peer"))
		return
	}

	needAck := false
	if len(seg.payload) > 0 {
		needAck = c.receivePayload(seg.seq, seg.payload)
	}
	if seg.flags&flagFIN != 0 {
		// FIN consumes one sequence number. Complete it only when reassembly
		// has reached its slot: a FIN reordered ahead of trailing data must
		// not ACK bytes never received nor expose EOF early.
		finEnd := seg.seq + uint32(len(seg.payload)) + 1
		if c.peerSeq == finEnd-1 {
			c.peerSeq = finEnd
			c.mu.Lock()
			c.completeFINLocked()
			c.mu.Unlock()
			needAck = true
		} else if seqAfter(finEnd-1, c.peerSeq) {
			c.finPending = finEnd
			c.hasFinPending = true
		}
	}
	if needAck {
		_ = c.sendSegmentLocked(flagACK, nil, time.Time{})
	}
	c.seqMu.Unlock()
}

// receivePayload reassembles in-order/out-of-order/overlapping data.
// Caller holds seqMu; returns whether an ACK is owed.
func (c *TCPConn) receivePayload(seq uint32, payload []byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.readErr != nil {
		return false // read side closed: stop ACKing
	}
	if c.buf.Len()+c.oooBytes >= recvCap {
		// Buffer full: drop and advertise a zero window until the
		// application drains; the peer retransmits.
		c.zeroWin = true
		return true
	}
	switch {
	case seq == c.peerSeq:
		c.buf.Write(payload)
		c.peerSeq = seq + uint32(len(payload))
		c.drainOOOLocked()
	case seqAfter(seq, c.peerSeq):
		if old, ok := c.ooo[seq]; ok {
			c.oooBytes -= len(old)
		}
		c.ooo[seq] = payload
		c.oooBytes += len(payload)
	default:
		// Retransmission/overlap: append only the new tail.
		overlap := c.peerSeq - seq
		if overlap < uint32(len(payload)) {
			tail := payload[overlap:]
			c.buf.Write(tail)
			c.peerSeq += uint32(len(tail))
			c.drainOOOLocked()
		}
	}
	c.maybeFinishFINLocked()
	c.broadcastLocked()
	return true
}

// drainOOOLocked appends buffered segments that now connect, trimming
// overlaps. Caller holds seqMu and mu.
func (c *TCPConn) drainOOOLocked() {
	for {
		progress := false
		for seq, data := range c.ooo {
			end := seq + uint32(len(data))
			if !seqAfter(end, c.peerSeq) {
				// Fully overlapped by received data: discard.
				delete(c.ooo, seq)
				c.oooBytes -= len(data)
				progress = true
				continue
			}
			if !seqAfter(seq, c.peerSeq) {
				// Starts at/before the gap edge with a tail past it.
				trim := c.peerSeq - seq
				c.buf.Write(data[trim:])
				c.peerSeq = end
				delete(c.ooo, seq)
				c.oooBytes -= len(data)
				progress = true
			}
		}
		if !progress {
			return
		}
	}
}

// maybeFinishFINLocked completes a pending out-of-order FIN once reassembly
// reaches it. Caller holds seqMu and mu.
func (c *TCPConn) maybeFinishFINLocked() {
	if c.hasFinPending && c.peerSeq == c.finPending-1 {
		c.peerSeq = c.finPending
		c.hasFinPending = false
		c.completeFINLocked()
	}
}

// completeFINLocked marks the read side finished. Caller holds mu.
func (c *TCPConn) completeFINLocked() {
	if c.readErr == nil {
		c.readErr = io.EOF
	}
	c.broadcastLocked()
}

// abort tears down without sending FIN (RST / tunnel death).
func (c *TCPConn) abort(err error) {
	c.once.Do(func() {
		c.seqMu.Lock()
		c.writeClosed = true
		c.seqMu.Unlock()

		c.tun.UnregisterConn(c.srcPort)
		close(c.quit)

		c.mu.Lock()
		if c.readErr == nil {
			c.readErr = err
		}
		c.broadcastLocked()
		c.mu.Unlock()
	})
}

// seqAfter reports whether a is after b in circular sequence space.
func seqAfter(a, b uint32) bool { return int32(a-b) > 0 }

func (c *TCPConn) broadcastLocked() {
	close(c.notify)
	c.notify = make(chan struct{})
}

// rxWinLocked computes the advertised receive window. Caller holds seqMu and
// briefly takes mu (consistent seqMu → mu order).
func (c *TCPConn) rxWinLocked() uint16 {
	c.mu.Lock()
	defer c.mu.Unlock()
	used := c.buf.Len() + c.oooBytes
	if used >= recvCap {
		return 0
	}
	rem := recvCap - used
	if rem > maxWindow {
		return maxWindow
	}
	return uint16(rem)
}

// sendSegmentLocked builds and sends one TCP segment. Caller holds seqMu.
// Before the per-conn auth delivers a token there is nothing to send under;
// skip instead of emitting a malformed frame (e.g. Close during cleanup).
// deadline is non-zero only for application data written by Write. TCP
// control traffic must remain writable after the application's deadline.
func (c *TCPConn) sendSegmentLocked(flags byte, payload []byte, deadline time.Time) error {
	if c.token == "" {
		return errors.New("no connect token yet")
	}
	seg := tcpSegment(c.vip, c.dstIP, c.srcPort, c.dstPort, c.mySeq, c.peerSeq,
		flags, c.rxWinLocked(), payload)
	return c.tun.SendData(c.token, ipPacket(c.vip, c.dstIP, 6, seg), deadline)
}

// handshake drives the client side of the three-way handshake.
func (c *TCPConn) handshake(ctx context.Context) error {
	var isn [4]byte
	if _, err := rand.Read(isn[:]); err != nil {
		return err
	}
	c.seqMu.Lock()
	c.mySeq = binary.BigEndian.Uint32(isn[:])
	err := c.sendSegmentLocked(flagSYN, nil, time.Time{})
	c.mySeq++ // SYN consumes one sequence number
	c.seqMu.Unlock()
	if err != nil {
		return fmt.Errorf("send SYN: %w", err)
	}

	hsCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	select {
	case <-c.handshakeCh:
	case <-hsCtx.Done():
		// Gateways briefly refuse new connections under churn; surface as a
		// plain error so the Dialer backs off and retries.
		return errors.New("TCP handshake failed (no SYN-ACK)")
	case <-c.done:
		return io.EOF
	}

	c.seqMu.Lock()
	err = c.sendSegmentLocked(flagACK, nil, time.Time{})
	c.seqMu.Unlock()
	if err != nil {
		return fmt.Errorf("send handshake ACK: %w", err)
	}
	return nil
}

// --- net.Conn ---

// Read returns reassembled stream bytes. EOF follows the peer's FIN (once
// reassembly reaches it), an RST or tunnel death surfaces as an error/EOF
// after the buffer drains. Draining below the cap reopens a zero window.
func (c *TCPConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	for {
		if c.buf.Len() > 0 {
			n, _ := c.buf.Read(p)
			winUpdate := false
			if c.zeroWin && c.buf.Len()+c.oooBytes < recvCap {
				c.zeroWin = false
				winUpdate = true
			}
			c.mu.Unlock()
			if winUpdate {
				c.sendWindowUpdate()
			}
			return n, nil
		}
		if c.readErr != nil {
			err := c.readErr
			c.mu.Unlock()
			return 0, err
		}
		wait := c.notify
		var timer *time.Timer
		var timeout <-chan time.Time
		if !c.readDeadline.IsZero() {
			remaining := time.Until(c.readDeadline)
			if remaining <= 0 {
				c.mu.Unlock()
				return 0, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(remaining)
			timeout = timer.C
		}
		c.mu.Unlock()
		select {
		case <-wait:
		case <-timeout:
		}
		if timer != nil {
			timer.Stop()
		}
		c.mu.Lock()
	}
}

// sendWindowUpdate ACKs with the freshly opened window after a drain.
func (c *TCPConn) sendWindowUpdate() {
	c.seqMu.Lock()
	_ = c.sendSegmentLocked(flagACK, nil, time.Time{})
	c.seqMu.Unlock()
}

// Write streams data as PSH+ACK segments of at most MSS bytes. The write
// deadline bounds both the gaps between segments and each serialized tunnel
// write, so a concurrent SetWriteDeadline takes effect at the next segment
// and an expired deadline fails a blocked write.
func (c *TCPConn) Write(p []byte) (int, error) {
	c.seqMu.Lock()
	defer c.seqMu.Unlock()
	if c.writeClosed {
		return 0, net.ErrClosed
	}
	written := 0
	for len(p) > 0 {
		c.mu.Lock()
		deadline := c.writeDeadline
		c.mu.Unlock()
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return written, os.ErrDeadlineExceeded
		}
		chunk := p
		if len(chunk) > MSS {
			chunk = chunk[:MSS]
		}
		if err := c.sendSegmentLocked(flagPSH|flagACK, chunk, deadline); err != nil {
			return written, err
		}
		c.mySeq += uint32(len(chunk))
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

// Close sends FIN+ACK and unregisters the connection, avoiding gateway-side
// conntrack buildup.
func (c *TCPConn) Close() error {
	c.once.Do(func() {
		c.seqMu.Lock()
		if !c.writeClosed {
			// Best effort: the tunnel may already be dead.
			_ = c.sendSegmentLocked(flagFIN|flagACK, nil, time.Time{})
			c.mySeq++
			c.writeClosed = true
		}
		c.seqMu.Unlock()

		c.tun.UnregisterConn(c.srcPort)
		close(c.quit)

		c.mu.Lock()
		if c.readErr == nil {
			c.readErr = io.EOF
		}
		c.broadcastLocked()
		c.mu.Unlock()
	})
	return nil
}

func (c *TCPConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: c.vip, Port: int(c.srcPort)}
}

func (c *TCPConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: c.dstIP, Port: int(c.dstPort)}
}

func (c *TCPConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *TCPConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.broadcastLocked() // re-evaluate the deadline immediately
	c.mu.Unlock()
	return nil
}

func (c *TCPConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}
