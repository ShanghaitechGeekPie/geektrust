package inbound

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"geektrust/internal/config"
	"geektrust/internal/resolver"
)

// mockDialer echoes everything it receives, proving end-to-end relay.
type mockDialer struct {
	dialErr error
	calls   chan dialCall
}

type dialCall struct {
	ip, appID, domain string
	port              int
}

func (m *mockDialer) Dial(ctx context.Context, ip string, port int, appID, domain string) (net.Conn, error) {
	if m.calls != nil {
		m.calls <- dialCall{ip: ip, port: port, appID: appID, domain: domain}
	}
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

func (m *mockDialer) DialUDP(ctx context.Context, ip string, port int, appID, domain string) (net.Conn, error) {
	return m.Dial(ctx, ip, port, appID, domain)
}

type mockResolver struct {
	m       map[string]string
	result  *resolver.Resolution
	failAll bool
}

func (m *mockResolver) Resolve(ctx context.Context, host string, port int) (resolver.Resolution, error) {
	if m.failAll {
		return resolver.Resolution{}, fmt.Errorf("%w: %s", resolver.ErrUnresolvable, host)
	}
	if m.result != nil {
		return *m.result, nil
	}
	if ip, ok := m.m[host]; ok {
		return resolver.Resolution{IP: ip, AppID: "app-id"}, nil
	}
	return resolver.Resolution{IP: host, AppID: "app-id"}, nil
}

func (m *mockResolver) ResolveUDP(ctx context.Context, host string, port int) (resolver.Resolution, error) {
	return m.Resolve(ctx, host, port)
}
func testInboundCfg() config.Inbound { return config.Inbound{} }

func TestSOCKS5ConnectRelay(t *testing.T) {
	resolved := resolver.Resolution{
		IP: "10.15.45.163", AppID: "electronic-resource", Domain: "library.example",
	}
	dialer := &mockDialer{calls: make(chan dialCall, 1)}
	s := New(testInboundCfg(), &mockResolver{result: &resolved},
		dialer, slog.New(slog.NewTextHandler(io.Discard, nil)))

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
	call := <-dialer.calls
	if call.ip != resolved.IP || call.port != 443 || call.appID != resolved.AppID || call.domain != resolved.Domain {
		t.Fatalf("dial call = %+v", call)
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

type directUDPDialer struct{}

func (*directUDPDialer) Dial(context.Context, string, int, string, string) (net.Conn, error) {
	return nil, errors.New("unexpected TCP dial")
}

func (*directUDPDialer) DialUDP(ctx context.Context, ip string, port int, _, _ string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "udp4", net.JoinHostPort(ip, strconv.Itoa(port)))
}

func startUDPEcho(t *testing.T) *net.UDPAddr {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, client, err := conn.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(buffer[:n], client)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr)
}

func startTCPHandler(t *testing.T, handle func(net.Conn)) net.Conn {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err == nil {
			handle(conn)
			conn.Close()
		}
	}()
	client, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		client.Close()
		listener.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("proxy handler did not stop")
		}
	})
	return client
}

func TestSOCKS5UDPAssociateRelay(t *testing.T) {
	echo := startUDPEcho(t)
	server := New(testInboundCfg(), &mockResolver{m: map[string]string{"echo.test": "127.0.0.1"}},
		&directUDPDialer{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	control := startTCPHandler(t, func(conn net.Conn) {
		server.handleSOCKS5(context.Background(), conn)
	})
	_ = control.SetDeadline(time.Now().Add(3 * time.Second))

	if _, err := control.Write([]byte{socksVersion, 1, 0}); err != nil {
		t.Fatal(err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(control, greeting); err != nil || !bytes.Equal(greeting, []byte{socksVersion, 0}) {
		t.Fatalf("greeting = %x, %v", greeting, err)
	}
	if _, err := control.Write([]byte{socksVersion, socksCmdUDPAssociate, 0, socksAtypIPv4, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	replyHead := make([]byte, 4)
	if _, err := io.ReadFull(control, replyHead); err != nil {
		t.Fatal(err)
	}
	if replyHead[1] != socksReplySuccess {
		t.Fatalf("UDP ASSOCIATE reply = %x", replyHead)
	}
	bound, err := readSOCKSAddress(control, replyHead[3])
	if err != nil {
		t.Fatal(err)
	}

	udpClient, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udpClient.Close()
	_ = udpClient.SetDeadline(time.Now().Add(3 * time.Second))
	datagram, err := marshalSOCKSUDPDatagram(udpTarget{host: "echo.test", port: echo.Port}, []byte("socks-udp"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := udpClient.WriteToUDP(datagram, &net.UDPAddr{IP: net.ParseIP(bound.host), Port: bound.port}); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 2048)
	n, _, err := udpClient.ReadFromUDP(response)
	if err != nil {
		t.Fatal(err)
	}
	target, payload, err := parseSOCKSUDPDatagram(response[:n])
	if err != nil {
		t.Fatal(err)
	}
	if target.host != "echo.test" || target.port != echo.Port || string(payload) != "socks-udp" {
		t.Fatalf("UDP response target=%s payload=%q", target.key(), payload)
	}
}

func TestSOCKS5UDPRejectsFragmentsAndIPv6Targets(t *testing.T) {
	target := udpTarget{host: "127.0.0.1", port: 53}
	packet, err := marshalSOCKSUDPDatagram(target, []byte("dns"))
	if err != nil {
		t.Fatal(err)
	}
	packet[2] = 1
	if _, _, err := parseSOCKSUDPDatagram(packet); err == nil {
		t.Fatal("fragmented SOCKS5 UDP datagram was accepted")
	}
	ipv6, err := appendSOCKSAddress([]byte{0, 0, 0}, "2001:db8::1", 53)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := parseSOCKSUDPDatagram(ipv6); !errors.Is(err, errSOCKSAtypUnsupported) {
		t.Fatalf("IPv6 UDP target error = %v", err)
	}
}

func TestHTTPConnectUDPRelay(t *testing.T) {
	echo := startUDPEcho(t)
	server := New(testInboundCfg(), &mockResolver{m: map[string]string{"echo.test": "127.0.0.1"}},
		&directUDPDialer{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	client := startTCPHandler(t, func(conn net.Conn) {
		server.handleHTTPConnect(context.Background(), conn)
	})
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	request := fmt.Sprintf(
		"GET http://proxy.example/.well-known/masque/udp/echo.test/%d/ HTTP/1.1\r\n"+
			"Host: proxy.example\r\nConnection: keep-alive, Upgrade\r\n"+
			"Upgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n\r\n", echo.Port)
	if _, err := client.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(client)
	var response strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		response.WriteString(line)
		if line == "\r\n" {
			break
		}
	}
	if !strings.HasPrefix(response.String(), "HTTP/1.1 101 Switching Protocols\r\n") ||
		!strings.Contains(response.String(), "Capsule-Protocol: ?1\r\n") {
		t.Fatalf("CONNECT-UDP response = %q", response.String())
	}

	unknown, _ := appendQUICVarint(nil, 42)
	unknown, _ = appendQUICVarint(unknown, 3)
	unknown = append(unknown, "old"...)
	if _, err := client.Write(unknown); err != nil {
		t.Fatal(err)
	}

	roundTrip := func(payload []byte) {
		t.Helper()
		capsule, _ := appendQUICVarint(nil, 0)
		capsule, _ = appendQUICVarint(capsule, uint64(len(payload)+1))
		capsule = append(capsule, 0)
		capsule = append(capsule, payload...)
		if _, err := client.Write(capsule); err != nil {
			t.Fatal(err)
		}
		capsuleType, err := readQUICVarint(reader)
		if err != nil {
			t.Fatal(err)
		}
		length, err := readQUICVarint(reader)
		if err != nil {
			t.Fatal(err)
		}
		value := make([]byte, int(length))
		if _, err := io.ReadFull(reader, value); err != nil {
			t.Fatal(err)
		}
		if capsuleType != 0 || len(value) != len(payload)+1 || value[0] != 0 || !bytes.Equal(value[1:], payload) {
			t.Fatalf("DATAGRAM capsule type=%d value=%x", capsuleType, value)
		}
	}
	roundTrip([]byte("http-udp"))
	roundTrip(nil)
}

func TestHTTPConnectUDPRejectsMalformedUpgrade(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet,
		"http://proxy.example/.well-known/masque/udp/127.0.0.1/53/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Upgrade", "connect-udp")
	if _, err := parseConnectUDPRequest(req); err == nil {
		t.Fatal("CONNECT-UDP without Connection: Upgrade was accepted")
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Content-Length", "0")
	if _, err := parseConnectUDPRequest(req); err == nil {
		t.Fatal("CONNECT-UDP with Content-Length was accepted")
	}
}

func TestHTTPConnectUDPRejectsContentLengthOnWire(t *testing.T) {
	server := New(testInboundCfg(), &mockResolver{}, &mockDialer{},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	client, peer := net.Pipe()
	defer client.Close()
	go server.handleHTTPConnect(context.Background(), peer)
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := client.Write([]byte(
		"GET http://proxy.example/.well-known/masque/udp/127.0.0.1/53/ HTTP/1.1\r\n" +
			"Host: proxy.example\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\n" +
			"Content-Length: 0\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 64)
	n, err := client.Read(response)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(response[:n]), "HTTP/1.1 400") {
		t.Fatalf("status = %q", response[:n])
	}
}

func TestQUICVarintRoundTrip(t *testing.T) {
	values := []uint64{0, 63, 64, 16383, 16384, 1<<30 - 1, 1 << 30, 1<<62 - 1}
	for _, value := range values {
		encoded, err := appendQUICVarint(nil, value)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := readQUICVarint(bytes.NewReader(encoded))
		if err != nil || decoded != value {
			t.Errorf("QUIC varint %d decoded as %d, %v", value, decoded, err)
		}
	}
}
