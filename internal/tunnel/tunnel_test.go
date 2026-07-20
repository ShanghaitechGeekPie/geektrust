package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

func testTunnel(conn net.Conn) *Tunnel {
	return &Tunnel{
		conn:      conn,
		writeGate: make(chan struct{}, 1),
		dead:      make(chan struct{}),
		pending:   make(map[uint64]chan authResult),
		conns:     make(map[uint16]PacketSink),
		portNext:  firstSrcPort,
	}
}

type discardSink struct{}

func (discardSink) DeliverPacket([]byte) {}

type captureSink chan []byte

func (s captureSink) DeliverPacket(packet []byte) {
	s <- append([]byte(nil), packet...)
}

func TestDispatchRoutesUDPByDestinationPort(t *testing.T) {
	tun := testTunnel(nil)
	sink := make(captureSink, 1)
	port, err := tun.ReserveConn(sink)
	if err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 28)
	packet[0] = 0x45
	packet[9] = 17
	binary.BigEndian.PutUint16(packet[22:24], port)
	tun.dispatch(packet)
	select {
	case got := <-sink:
		if len(got) != len(packet) {
			t.Fatalf("delivered UDP packet length = %d, want %d", len(got), len(packet))
		}
	default:
		t.Fatal("UDP packet was not delivered")
	}
}

func TestReserveConnIsAtomicUnderConcurrency(t *testing.T) {
	tun := testTunnel(nil)
	const count = 512
	ports := make(chan uint16, count)
	errs := make(chan error, count)
	var wg sync.WaitGroup
	for range count {
		wg.Add(1)
		go func() {
			defer wg.Done()
			port, err := tun.ReserveConn(discardSink{})
			if err != nil {
				errs <- err
				return
			}
			ports <- port
		}()
	}
	wg.Wait()
	close(ports)
	close(errs)
	for err := range errs {
		t.Fatalf("ReserveConn: %v", err)
	}
	seen := make(map[uint16]struct{}, count)
	for port := range ports {
		if port < firstSrcPort || port > lastSrcPort {
			t.Fatalf("port %d outside allocation range", port)
		}
		if _, duplicate := seen[port]; duplicate {
			t.Fatalf("duplicate reserved port %d", port)
		}
		seen[port] = struct{}{}
	}
	if len(seen) != count {
		t.Fatalf("reserved %d ports, want %d", len(seen), count)
	}
}

type shortWriteConn struct {
	net.Conn
}

func (shortWriteConn) Write(p []byte) (int, error) {
	return len(p) - 1, nil
}

func TestWriteFrameShortWriteKillsTunnel(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	tun := testTunnel(shortWriteConn{left})

	err := tun.WriteFrame([]byte("frame"), time.Now().Add(time.Second))
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("WriteFrame err = %v, want short write", err)
	}
	select {
	case <-tun.dead:
	default:
		t.Fatal("short socket write did not kill the tunnel")
	}
}

func TestWriteFrameContextCancelBoundsQueueWait(t *testing.T) {
	tun := testTunnel(nil)
	tun.writeGate <- struct{}{}
	defer func() { <-tun.writeGate }()

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- tun.writeFrame(ctx, []byte("frame"), time.Time{})
	}()
	cancel()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("writeFrame err = %v, want context canceled", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("context cancellation did not unblock queued write")
	}
}

func TestWriteFrameDeadlineBoundsQueueWait(t *testing.T) {
	tun := testTunnel(nil)
	tun.writeGate <- struct{}{} // another writer owns the serialized stream
	defer func() { <-tun.writeGate }()

	start := time.Now()
	err := tun.WriteFrame([]byte("frame"), time.Now().Add(40*time.Millisecond))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("WriteFrame err = %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("queue deadline honored late: %v", elapsed)
	}
	select {
	case <-tun.dead:
		t.Fatal("queue timeout killed a tunnel before any bytes were written")
	default:
	}
}

func TestWriteFrameErrorKillsTunnel(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	tun := testTunnel(left)

	err := tun.WriteFrame([]byte("frame"), time.Now().Add(40*time.Millisecond))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("WriteFrame err = %v, want deadline exceeded", err)
	}
	select {
	case <-tun.dead:
	default:
		t.Fatal("socket write error did not kill the tunnel")
	}
}
