package tunnel

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type writeStartedConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func TestTCPStreamCloseSendsGracefulFrame(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	stream := &tcpTunnelConn{conn: client, reader: bufio.NewReader(client)}
	closed := make(chan error, 1)
	go func() { closed <- stream.Close() }()
	peer.SetReadDeadline(time.Now().Add(time.Second))
	var frame [4]byte
	if _, err := io.ReadFull(peer, frame[:]); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(frame[:], []byte{0x01, 0x01, 0x00, 0x00}) {
		t.Fatal("normal Close omitted the graceful close frame")
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
}

func (c *writeStartedConn) Write(b []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Write(b)
}

func TestTCPStreamCloseUnblocksStalledWrite(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	observed := &writeStartedConn{Conn: client, started: make(chan struct{})}
	stream := &tcpTunnelConn{conn: observed, reader: bufio.NewReader(observed)}
	written := make(chan error, 1)
	go func() { _, err := stream.Write([]byte("payload")); written <- err }()
	<-observed.started
	closed := make(chan error, 1)
	go func() { closed <- stream.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close waited on a stalled Write instead of closing the socket")
	}
	select {
	case err := <-written:
		if err == nil {
			t.Fatal("stalled Write did not fail after Close")
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock Write")
	}
}
