package inbound

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestRelayPairPreservesTCPHalfClose(t *testing.T) {
	clientA, relayA := tcpPair(t)
	clientB, relayB := tcpPair(t)
	defer clientA.Close()
	defer clientB.Close()

	done := make(chan struct{})
	go func() {
		relayPair(relayA, relayB)
		close(done)
	}()

	deadline := time.Now().Add(3 * time.Second)
	clientA.SetDeadline(deadline)
	clientB.SetDeadline(deadline)
	if _, err := clientA.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := clientA.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	request, err := io.ReadAll(clientB)
	if err != nil {
		t.Fatalf("read request: %v", err)
	}
	if string(request) != "request" {
		t.Fatalf("request = %q", request)
	}

	if _, err := clientB.Write([]byte("response-after-eof")); err != nil {
		t.Fatalf("write response after EOF: %v", err)
	}
	if err := clientB.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(clientA)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if string(response) != "response-after-eof" {
		t.Fatalf("response = %q", response)
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not finish after both FINs")
	}
}

func TestRelayPairHalfCloseTimeoutTracksIdleTime(t *testing.T) {
	clientA, relayA := tcpPair(t)
	clientB, relayB := tcpPair(t)
	defer clientA.Close()
	defer clientB.Close()

	done := make(chan struct{})
	go func() {
		relayPairWithIdleTimeout(relayA, relayB, 200*time.Millisecond)
		close(done)
	}()

	deadline := time.Now().Add(3 * time.Second)
	clientA.SetDeadline(deadline)
	clientB.SetDeadline(deadline)
	if err := clientA.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(clientB); err != nil {
		t.Fatalf("read request EOF: %v", err)
	}

	for range 6 {
		if _, err := clientB.Write([]byte("x")); err != nil {
			t.Fatalf("stream response: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := clientB.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(clientA)
	if err != nil {
		t.Fatalf("read streaming response: %v", err)
	}
	if string(response) != "xxxxxx" {
		t.Fatalf("streaming response = %q", response)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not finish after streaming response")
	}
}

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan *net.TCPConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	select {
	case server := <-accepted:
		listener.Close()
		return client, server
	case err := <-acceptErr:
		listener.Close()
		client.Close()
		t.Fatal(err)
	}
	return nil, nil
}
