package inbound

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

type earlyUDPDialer struct {
	mockDialer
	conn net.Conn
}

func (d *earlyUDPDialer) DialUDP(context.Context, string, int, string, string) (net.Conn, error) {
	return d.conn, nil
}

type observedUDPRead struct {
	net.Conn
	read chan struct{}
	once sync.Once
}

func (c *observedUDPRead) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.once.Do(func() { close(c.read) })
	}
	return n, err
}

type delayedUpgradeConn struct {
	net.Conn
	started chan struct{}
	release chan struct{}
}

func (c *delayedUpgradeConn) Write(p []byte) (int, error) {
	if bytes.HasPrefix(p, []byte("HTTP/1.1 101")) {
		close(c.started)
		<-c.release
	}
	return c.Conn.Write(p)
}

func TestConnectUDPUpgradePrecedesEarlyDatagram(t *testing.T) {
	upstream, remote := net.Pipe()
	defer remote.Close()
	defer upstream.Close()
	read := make(chan struct{})
	dialer := &earlyUDPDialer{conn: &observedUDPRead{Conn: upstream, read: read}}
	s := New(testInboundCfg(), &mockResolver{}, dialer, slog.New(slog.NewTextHandler(io.Discard, nil)))
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	wrapped := &delayedUpgradeConn{Conn: server, started: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	defer release.Do(func() { close(wrapped.release) })
	done := make(chan struct{})
	go func() { defer close(done); s.handleHTTPConnect(context.Background(), wrapped) }()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(client, "GET /.well-known/masque/udp/192.0.2.1/443/ HTTP/1.1\r\nHost: proxy\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-wrapped.started:
	case <-time.After(time.Second):
		t.Fatal("upgrade response did not start")
	}
	go remote.Write([]byte("early"))
	select {
	case <-read:
	case <-time.After(time.Second):
		t.Fatal("upstream datagram was not read")
	}
	client.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	var first [1]byte
	if n, err := client.Read(first[:]); n != 0 || err == nil {
		t.Fatalf("UDP data preceded the HTTP upgrade: %x, %v", first[:n], err)
	}
	release.Do(func() { close(wrapped.release) })
	client.SetReadDeadline(time.Now().Add(time.Second))
	reader := bufio.NewReader(client)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatal(response.Status)
	}
	kind, err := readQUICVarint(reader)
	if err != nil || kind != 0 {
		t.Fatalf("capsule kind = %d, %v", kind, err)
	}
	length, err := readQUICVarint(reader)
	if err != nil || length != 6 {
		t.Fatalf("capsule length = %d, %v", length, err)
	}
	value := make([]byte, length)
	if _, err := io.ReadFull(reader, value); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(value, append([]byte{0}, []byte("early")...)) {
		t.Fatalf("capsule = %x", value)
	}
	client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler did not stop")
	}
}
