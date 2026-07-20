package l3

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// fakeTunnel is a tunnelLink double capturing uplink segments for assertions.
type fakeTunnel struct {
	mu        sync.Mutex
	sent      [][]byte
	deadlines []time.Time
	dead      chan struct{}
	unreg     []uint16
	sendErr   error
}

func newFakeTunnel() *fakeTunnel {
	return &fakeTunnel{dead: make(chan struct{})}
}

func (f *fakeTunnel) SendData(token string, pkt []byte, deadline time.Time) error {
	select {
	case <-f.dead:
		return errors.New("tunnel dead") // real tunnel returns ErrTunnelDead
	default:
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sendErr != nil {
		return f.sendErr
	}
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	f.sent = append(f.sent, cp)
	f.deadlines = append(f.deadlines, deadline)
	return nil
}

func (f *fakeTunnel) Dead() <-chan struct{} { return f.dead }

func (f *fakeTunnel) UnregisterConn(srcPort uint16) {
	f.mu.Lock()
	f.unreg = append(f.unreg, srcPort)
	f.mu.Unlock()
}

// lastSegment returns the TCP info of the most recently sent packet.
func (f *fakeTunnel) lastSegment(t *testing.T) tcpInfo {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sent) == 0 {
		t.Fatal("no segment sent")
	}
	info, ok := parseTCP(f.sent[len(f.sent)-1])
	if !ok {
		t.Fatal("sent frame is not a TCP segment")
	}
	return info
}

func (f *fakeTunnel) sentCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sent)
}

func (f *fakeTunnel) lastDeadline() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.deadlines[len(f.deadlines)-1]
}

var (
	testVIP = net.IPv4(10, 19, 240, 43).To4()
	testDst = net.IPv4(10, 15, 45, 163).To4()
)

// serverPacket builds a downlink IPv4 packet from the "server" (dst→src
// swapped, seq as given).
func serverPacket(seq, ack uint32, flags byte, payload []byte) []byte {
	seg := tcpSegment(testDst, testVIP, 443, 30001, seq, ack, flags, 65535, payload)
	return ipPacket(testDst, testVIP, 6, seg)
}

func TestHandshake(t *testing.T) {
	ft := newFakeTunnel()
	conn := newTCPConn(ft, "tok", testVIP, testDst, 30001, 443)
	defer conn.Close()

	errCh := make(chan error, 1)
	go func() { errCh <- conn.handshake(context.Background()) }()

	// SYN must go out first.
	deadline := time.Now().Add(2 * time.Second)
	for ft.sentCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	syn := ft.lastSegment(t)
	if syn.flags != flagSYN {
		t.Fatalf("first segment flags = 0x%02x, want SYN", syn.flags)
	}

	// SYN-ACK from server seq 5000 → peerSeq 5001, handshake completes, ACK out.
	conn.DeliverPacket(serverPacket(5000, syn.seq+1, flagSYN|flagACK, nil))
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("handshake: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handshake did not complete")
	}
	ack := ft.lastSegment(t)
	if ack.flags != flagACK {
		t.Errorf("handshake ACK flags = 0x%02x", ack.flags)
	}
}

func TestHandshakeTimeout(t *testing.T) {
	ft := newFakeTunnel()
	conn := newTCPConn(ft, "tok", testVIP, testDst, 30001, 443)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := conn.handshake(ctx); err == nil {
		t.Fatal("expected handshake failure without SYN-ACK")
	}
}

// establish returns a conn past the handshake with peerSeq set to base.
func establish(t *testing.T, ft *fakeTunnel, peerSeq uint32) *TCPConn {
	t.Helper()
	conn := newTCPConn(ft, "tok", testVIP, testDst, 30001, 443)
	errCh := make(chan error, 1)
	go func() { errCh <- conn.handshake(context.Background()) }()
	for ft.sentCount() == 0 {
		time.Sleep(2 * time.Millisecond)
	}
	syn := ft.lastSegment(t)
	conn.DeliverPacket(serverPacket(peerSeq-1, syn.seq+1, flagSYN|flagACK, nil))
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("handshake: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handshake stuck")
	}
	return conn
}

func readAll(t *testing.T, conn *TCPConn, n int) []byte {
	t.Helper()
	out := make([]byte, 0, n)
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for len(out) < n {
		rn, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("read after %d bytes: %v", len(out), err)
		}
		out = append(out, buf[:rn]...)
	}
	return out
}

func TestInOrderReassembly(t *testing.T) {
	ft := newFakeTunnel()
	conn := establish(t, ft, 1000)
	defer conn.Close()

	conn.DeliverPacket(serverPacket(1000, 0, flagACK|flagPSH, []byte("hello ")))
	conn.DeliverPacket(serverPacket(1006, 0, flagACK|flagPSH, []byte("world")))
	if got := readAll(t, conn, 11); string(got) != "hello world" {
		t.Errorf("payload = %q", got)
	}
	// Each data segment must be ACKed.
	if ack := ft.lastSegment(t); ack.flags&flagACK == 0 {
		t.Error("no ACK for received data")
	}
}

func TestOutOfOrderReassembly(t *testing.T) {
	ft := newFakeTunnel()
	conn := establish(t, ft, 1000)
	defer conn.Close()

	// Future segment first, then the missing piece.
	conn.DeliverPacket(serverPacket(1005, 0, flagACK|flagPSH, []byte("world")))
	conn.DeliverPacket(serverPacket(1000, 0, flagACK|flagPSH, []byte("hello")))
	if got := readAll(t, conn, 10); string(got) != "helloworld" {
		t.Errorf("payload = %q", got)
	}
}

func TestRetransmissionOverlap(t *testing.T) {
	ft := newFakeTunnel()
	conn := establish(t, ft, 1000)
	defer conn.Close()

	conn.DeliverPacket(serverPacket(1000, 0, flagACK|flagPSH, []byte("hello world")))
	// Overlapping retransmission: only the new tail may be appended.
	conn.DeliverPacket(serverPacket(1000, 0, flagACK|flagPSH, []byte("hello world!!!")))
	if got := readAll(t, conn, 14); string(got) != "hello world!!!" {
		t.Errorf("payload = %q", got)
	}
	// Pure duplicate: nothing new.
	conn.DeliverPacket(serverPacket(1000, 0, flagACK|flagPSH, []byte("hello")))
	conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	if _, err := conn.Read(make([]byte, 8)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("duplicate extended the buffer; Read err = %v", err)
	}
}

func TestFIN(t *testing.T) {
	ft := newFakeTunnel()
	conn := establish(t, ft, 1000)
	defer conn.Close()

	conn.DeliverPacket(serverPacket(1000, 0, flagACK|flagPSH, []byte("bye")))
	conn.DeliverPacket(serverPacket(1003, 0, flagFIN|flagACK, nil))
	if got := readAll(t, conn, 3); string(got) != "bye" {
		t.Errorf("payload = %q", got)
	}
	if _, err := conn.Read(make([]byte, 4)); err != io.EOF {
		t.Errorf("Read after FIN = %v, want EOF", err)
	}
}

func TestRST(t *testing.T) {
	ft := newFakeTunnel()
	conn := establish(t, ft, 1000)
	defer conn.Close()

	conn.DeliverPacket(serverPacket(1000, 0, flagRST, nil))
	deadline := time.Now().Add(2 * time.Second)
	for {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err := conn.Read(make([]byte, 4))
		if err == nil {
			if time.Now().After(deadline) {
				t.Fatal("RST never surfaced")
			}
			continue
		}
		if err == io.EOF || err.Error() == "connection reset by peer" {
			break
		}
		t.Fatalf("Read after RST = %v", err)
	}
}

func TestWriteSegmentation(t *testing.T) {
	ft := newFakeTunnel()
	conn := establish(t, ft, 1000)
	defer conn.Close()

	data := make([]byte, MSS*2+200)
	for i := range data {
		data[i] = byte(i)
	}
	before := ft.sentCount()
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Write(data)
	if err != nil || n != len(data) {
		t.Fatalf("Write = %d, %v", n, err)
	}
	// 1400 + 1400 + 200 → three data segments.
	if got := ft.sentCount() - before; got != 3 {
		t.Fatalf("segments sent = %d, want 3", got)
	}
	info := ft.lastSegment(t)
	if info.flags != flagPSH|flagACK || len(info.payload) != 200 {
		t.Errorf("last segment flags=0x%02x len=%d", info.flags, len(info.payload))
	}
}

func TestWriteDeadlineDoesNotBlockTCPControl(t *testing.T) {
	ft := newFakeTunnel()
	conn := establish(t, ft, 1000)

	if err := conn.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("expired")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Write err = %v, want deadline exceeded", err)
	}

	before := ft.sentCount()
	conn.DeliverPacket(serverPacket(1000, 0, flagACK|flagPSH, []byte("x")))
	deadline := time.Now().Add(time.Second)
	for ft.sentCount() == before && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if ft.sentCount() == before {
		t.Fatal("receive ACK was not sent")
	}
	if got := ft.lastSegment(t).flags; got != flagACK {
		t.Fatalf("receive ACK flags = 0x%02x", got)
	}
	if got := ft.lastDeadline(); !got.IsZero() {
		t.Fatalf("receive ACK inherited application deadline %v", got)
	}

	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if got := ft.lastSegment(t).flags; got != flagFIN|flagACK {
		t.Fatalf("close flags = 0x%02x", got)
	}
	if got := ft.lastDeadline(); !got.IsZero() {
		t.Fatalf("FIN inherited application deadline %v", got)
	}
}

func TestReadDeadline(t *testing.T) {
	ft := newFakeTunnel()
	conn := establish(t, ft, 1000)
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	start := time.Now()
	_, err := conn.Read(make([]byte, 4))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read err = %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("deadline honored late: %v", elapsed)
	}
	// Data arriving after a timed-out read must still be readable.
	conn.SetReadDeadline(time.Time{})
	conn.DeliverPacket(serverPacket(1000, 0, flagACK|flagPSH, []byte("late")))
	if got := readAll(t, conn, 4); string(got) != "late" {
		t.Errorf("payload = %q", got)
	}
}

func TestTunnelDeathEndsReads(t *testing.T) {
	ft := newFakeTunnel()
	conn := establish(t, ft, 1000)
	defer conn.Close()

	close(ft.dead)
	deadline := time.Now().Add(2 * time.Second)
	conn.SetReadDeadline(deadline)
	if _, err := conn.Read(make([]byte, 4)); err != io.EOF {
		t.Fatalf("Read after tunnel death = %v, want EOF", err)
	}
	if _, err := conn.Write([]byte("x")); err == nil {
		t.Error("Write after tunnel death must fail")
	}
}

func TestCloseSendsFINAndUnregisters(t *testing.T) {
	ft := newFakeTunnel()
	conn := establish(t, ft, 1000)

	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	fin := ft.lastSegment(t)
	if fin.flags&flagFIN == 0 {
		t.Errorf("close segment flags = 0x%02x, want FIN", fin.flags)
	}
	ft.mu.Lock()
	unreg := append([]uint16(nil), ft.unreg...)
	ft.mu.Unlock()
	if len(unreg) == 0 || unreg[len(unreg)-1] != 30001 {
		t.Errorf("unregister = %v, want 30001", unreg)
	}
	if _, err := conn.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Write after Close = %v, want ErrClosed", err)
	}
}

// TestCloseStopsRunGoroutine: Close must end the receive goroutine
// (regression: it previously lingered until tunnel death, leaking one
// goroutine per closed connection).
func TestCloseStopsRunGoroutine(t *testing.T) {
	ft := newFakeTunnel()
	conn := establish(t, ft, 1000)
	conn.Close()
	select {
	case <-conn.done:
	case <-time.After(2 * time.Second):
		t.Fatal("run() did not exit after Close")
	}
}

// TestOutOfOrderFIN: a FIN arriving ahead of trailing data must not expose
// EOF early; it completes once reassembly reaches it (regression: immediate
// FIN handling ACKed a gap and truncated the stream).
func TestOutOfOrderFIN(t *testing.T) {
	ft := newFakeTunnel()
	conn := establish(t, ft, 1000)
	defer conn.Close()

	// Future FIN at seq 1005 (end 1006) before the 1000..1005 data.
	conn.DeliverPacket(serverPacket(1005, 0, flagFIN|flagACK, nil))
	conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := conn.Read(make([]byte, 8)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("early read = %v, want timeout (FIN must wait for the data)", err)
	}

	conn.DeliverPacket(serverPacket(1000, 0, flagACK|flagPSH, []byte("hello")))
	if got := readAll(t, conn, 5); string(got) != "hello" {
		t.Errorf("payload = %q", got)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 4)); err != io.EOF {
		t.Fatalf("read after FIN completion = %v, want EOF", err)
	}
}

// TestRSTFullTeardown: RST must reject writes, end reads and unregister
// (regression: it only set a read error and left the endpoint writable).
func TestRSTFullTeardown(t *testing.T) {
	ft := newFakeTunnel()
	conn := establish(t, ft, 1000)

	conn.DeliverPacket(serverPacket(1000, 0, flagRST, nil))
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := conn.Write([]byte("x")); errors.Is(err, net.ErrClosed) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := conn.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Write after RST = %v, want ErrClosed", err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 4)); err == nil || err == io.EOF {
		t.Errorf("Read after RST = %v, want reset error", err)
	}
	ft.mu.Lock()
	unreg := append([]uint16(nil), ft.unreg...)
	ft.mu.Unlock()
	if len(unreg) == 0 || unreg[len(unreg)-1] != 30001 {
		t.Errorf("RST did not unregister: %v", unreg)
	}
}

// TestZeroWindowBackpressure: once the receive buffer is full, further
// segments are dropped (not ACKed into memory) until the app drains and a
// window update goes out (regression: unbounded buffering).
func TestZeroWindowBackpressure(t *testing.T) {
	ft := newFakeTunnel()
	conn := establish(t, ft, 1000)
	defer conn.Close()

	seg := make([]byte, 1400)
	seq := uint32(1000)
	sent := 0
	for sent < recvCap+10*1400 {
		conn.DeliverPacket(serverPacket(seq, 0, flagACK|flagPSH, seg))
		seq += uint32(len(seg))
		sent += len(seg)
	}
	// Give run() a moment to process the queue.
	time.Sleep(100 * time.Millisecond)

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, recvCap+64*1024)
	total := 0
	for {
		conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			break
		}
	}
	if total > recvCap+1400 {
		t.Fatalf("buffered %d bytes, cap is %d (backpressure failed)", total, recvCap)
	}
	if total < recvCap-1400 {
		t.Fatalf("buffered only %d bytes, expected ~%d", total, recvCap)
	}

	// Draining opened the window: an ACK must have gone out.
	if ack := ft.lastSegment(t); ack.flags&flagACK == 0 {
		t.Error("no window-update ACK after drain")
	}
	// The dropped tail retransmits and is now accepted.
	conn.DeliverPacket(serverPacket(1000+uint32(total), 0, flagACK|flagPSH, seg[:100]))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	more := make([]byte, 100)
	n, err := io.ReadFull(conn, more)
	if err != nil || n != 100 {
		t.Errorf("retransmitted tail read = %d, %v", n, err)
	}
}
