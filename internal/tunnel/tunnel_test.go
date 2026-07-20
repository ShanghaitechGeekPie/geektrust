package tunnel

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

func testTunnel(conn net.Conn) *Tunnel {
	return &Tunnel{
		conn:      conn,
		writeGate: make(chan struct{}, 1),
		dead:      make(chan struct{}),
		pending:   make(map[uint64]chan authResult),
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
