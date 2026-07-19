package inbound

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"testing"

	"geektrust/internal/config"
	"geektrust/internal/resolver"
)

// mockDialer echoes everything it receives, proving end-to-end relay.
type mockDialer struct {
	dialErr error
}

func (m *mockDialer) Dial(ctx context.Context, ip string, port int) (net.Conn, error) {
	if m.dialErr != nil {
		return nil, m.dialErr
	}
	a, b := net.Pipe()
	go func() {
		// Echo on the mock end: bytes the handler writes to b are read
		// from a and written back to a, which the handler reads from b.
		io.Copy(a, a)
		a.Close()
	}()
	return b, nil
}

type mockResolver struct {
	m       map[string]string
	failAll bool
}

func (m *mockResolver) Resolve(ctx context.Context, host string) (string, string, error) {
	if m.failAll {
		return "", "", fmt.Errorf("%w: %s", resolver.ErrUnresolvable, host)
	}
	if ip, ok := m.m[host]; ok {
		return ip, "app-id", nil
	}
	return host, "app-id", nil
}
func testInboundCfg() config.Inbound { return config.Inbound{} }

func TestSOCKS5ConnectRelay(t *testing.T) {
	s := New(testInboundCfg(), &mockResolver{m: map[string]string{"library.example": "10.15.45.163"}},
		&mockDialer{}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	client, srv := net.Pipe()
	go s.handleSOCKS5(context.Background(), srv)

	// Greeting: no-auth.
	if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(client, greet); err != nil || greet[0] != 0x05 || greet[1] != 0x00 {
		t.Fatalf("greeting reply = %x, %v", greet, err)
	}

	// CONNECT to library.example:443 (domain atyp).
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len("library.example"))}
	req = append(req, "library.example"...)
	req = append(req, 0x01, 0xBB) // port 443
	if _, err := client.Write(req); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("connect reply code = 0x%02x", reply[1])
	}

	// Echo through the relay.
	if _, err := client.Write([]byte("ping-over-tunnel")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	if _, err := io.ReadFull(client, buf); err != nil || string(buf) != "ping-over-tunnel" {
		t.Fatalf("echo = %q, %v", buf, err)
	}
}

func TestSOCKS5ReplyCodes(t *testing.T) {
	cases := []struct {
		name     string
		req      []byte
		resolver Resolver
		dialer   Dialer
		wantCode byte
	}{
		{
			name:     "unsupported command (BIND)",
			req:      []byte{0x05, 0x02, 0x00, 0x01, 1, 2, 3, 4, 0x01, 0xBB},
			wantCode: 0x07,
		},
		{
			name:     "unsupported atyp (IPv6)",
			req:      append([]byte{0x05, 0x01, 0x00, 0x04}, make([]byte, 18)...),
			wantCode: 0x08,
		},
		{
			name:     "unresolvable host",
			req:      []byte{0x05, 0x01, 0x00, 0x03, 7, 'n', 'o', '.', 's', 'u', 'c', 'h', 0x01, 0xBB},
			resolver: &mockResolver{failAll: true},
			wantCode: 0x04,
		},
		{
			name:     "dial refused",
			req:      []byte{0x05, 0x01, 0x00, 0x01, 10, 15, 45, 163, 0x01, 0xBB},
			dialer:   &mockDialer{dialErr: errors.New("refused")},
			wantCode: 0x05,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := tc.resolver
			if res == nil {
				res = &mockResolver{}
			}
			dial := tc.dialer
			if dial == nil {
				dial = &mockDialer{}
			}
			s := New(testInboundCfg(), res, dial, slog.New(slog.NewTextHandler(io.Discard, nil)))
			client, srv := net.Pipe()
			go s.handleSOCKS5(context.Background(), srv)

			client.Write([]byte{0x05, 0x01, 0x00})
			greet := make([]byte, 2)
			io.ReadFull(client, greet)
			// Async: on early replies the handler leaves request bytes
			// unread, which would block a synchronous net.Pipe write.
			go client.Write(tc.req)
			reply := make([]byte, 10)
			if _, err := io.ReadFull(client, reply); err != nil {
				t.Fatal(err)
			}
			if reply[1] != tc.wantCode {
				t.Errorf("reply code = 0x%02x, want 0x%02x", reply[1], tc.wantCode)
			}
			client.Close()
		})
	}
}

func TestHTTPConnectRelay(t *testing.T) {
	s := New(testInboundCfg(), &mockResolver{m: map[string]string{"library.example": "10.15.45.163"}},
		&mockDialer{}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	client, srv := net.Pipe()
	go s.handleHTTPConnect(context.Background(), srv)

	if _, err := client.Write([]byte("CONNECT library.example:443 HTTP/1.1\r\nHost: library.example:443\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	// Read the 200 response header.
	buf := make([]byte, 64)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if want := "HTTP/1.1 200"; string(buf[:n])[:len(want)] != want {
		t.Fatalf("status = %q", buf[:n])
	}

	if _, err := client.Write([]byte("tls-client-hello-bytes")); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, 22)
	if _, err := io.ReadFull(client, echo); err != nil || string(echo) != "tls-client-hello-bytes" {
		t.Fatalf("echo = %q, %v", echo, err)
	}
}

func TestHTTPRejectsNonConnect(t *testing.T) {
	s := New(testInboundCfg(), &mockResolver{}, &mockDialer{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	client, srv := net.Pipe()
	go s.handleHTTPConnect(context.Background(), srv)

	client.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	buf := make([]byte, 64)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if want := "HTTP/1.1 405"; string(buf[:n])[:len(want)] != want {
		t.Fatalf("status = %q", buf[:n])
	}
}

// TestSOCKS5MethodRejection: a client offering no acceptable method gets
// 0xFF (RFC 1928), not a method it never offered.
func TestSOCKS5MethodRejection(t *testing.T) {
	s := New(testInboundCfg(), &mockResolver{}, &mockDialer{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	client, srv := net.Pipe()
	go s.handleSOCKS5(context.Background(), srv)

	// Offer only GSSAPI (0x01).
	if _, err := client.Write([]byte{0x05, 0x01, 0x01}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if reply[0] != 0x05 || reply[1] != 0xFF {
		t.Errorf("method reply = %x, want 05 FF", reply)
	}
}
