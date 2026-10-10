package tunnel

import (
	"bufio"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

type partialFrameConn struct {
	net.Conn
	failed bool
}

func (c *partialFrameConn) Write(b []byte) (int, error) {
	if !c.failed {
		c.failed = true
		n, err := c.Conn.Write(b[:min(5, len(b))])
		if err != nil {
			return n, err
		}
		return n, os.ErrDeadlineExceeded
	}
	return c.Conn.Write(b)
}

func TestTCPStreamWriteFailureClosesBrokenFrame(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	raw := &partialFrameConn{Conn: client}
	stream := &tcpTunnelConn{conn: raw, reader: bufio.NewReader(raw)}
	received := make(chan []byte, 1)
	go func() { b, _ := io.ReadAll(peer); received <- b }()
	if n, err := stream.Write([]byte("abc")); n != 1 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("partial Write = %d, %v; want the one application byte already sent", n, err)
	}
	stream.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := stream.Write([]byte("next")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("new frame accepted after a partial write: %v", err)
	}
	select {
	case b := <-received:
		if len(b) != 5 {
			t.Fatalf("broken stream received additional bytes: %d", len(b))
		}
	case <-time.After(time.Second):
		t.Fatal("partial frame failure did not close the socket")
	}
}
