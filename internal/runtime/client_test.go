package runtime

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/ShanghaitechGeekPie/geektrust/auth"
	"github.com/ShanghaitechGeekPie/geektrust/internal/storage"
)

type testGatewayPins struct {
	mu   sync.Mutex
	pins map[string][]byte
}

func (s *testGatewayPins) CheckOrEnroll(_ context.Context, id GatewayIdentity, pin [32]byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pins == nil {
		s.pins = make(map[string][]byte)
	}
	key := id.ControllerURL + "|" + id.Address + "|" + id.ServerName
	if old := s.pins[key]; old != nil {
		return string(old) == string(pin[:]), nil
	}
	s.pins[key] = append([]byte(nil), pin[:]...)
	return true, nil
}

func TestValidateOptions(t *testing.T) {
	for _, url := range []string{"http://vpn.example", "https://user:secret@vpn.example", "https://vpn.example/?token=x"} {
		if _, err := New(Options{ControllerURL: url, DeviceID: "0123456789ABCDEF0123456789ABCDEF", Auth: AuthOptions{Identity: identityFunc(func(context.Context, *http.Client, auth.IdentityRequest) error { return nil })}}); err == nil {
			t.Fatal("invalid options accepted")
		}
	}
}
func TestClosedClient(t *testing.T) {
	id, _ := NewDeviceID()
	c, err := New(Options{ControllerURL: "https://vpn.example", DeviceID: id, Auth: AuthOptions{Identity: identityFunc(func(context.Context, *http.Client, auth.IdentityRequest) error {
		t.Error("closed client authenticated")
		return nil
	})}})
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = c.DialContext(context.Background(), "tcp", "192.0.2.1:443"); err != ErrClosed {
		t.Fatal("closed client accepted dial")
	}
	if _, err = c.Connect(context.Background()); err != ErrClosed {
		t.Fatal("closed client accepted connect")
	}
	if _, err = c.LookupContextHost(context.Background(), "example.com"); err != ErrClosed {
		t.Fatal("closed client accepted lookup")
	}
}

func TestECNULiveAccess(t *testing.T) {
	if os.Getenv("GEEKTRUST_LIVE_TESTS") != "1" {
		t.Skip("online tests require explicit GEEKTRUST_LIVE_TESTS=1")
	}
	path := os.Getenv("GEEKTRUST_ECNU_KEYSTORE")
	if path == "" {
		t.Skip("explicit live credential required")
	}
	id, _ := NewDeviceID()
	identity, err := auth.NewPasskey(storage.CredentialFile(path))
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(Options{Logger: slog.New(stageHandler{t}), ControllerURL: "https://vpn.ecnu.edu.cn", DeviceID: id, Auth: AuthOptions{Identity: identity}, Network: NetworkOptions{GatewayTLS: GatewayTLSOptions{Mode: VerifyCAOrTOFU, PinStore: &testGatewayPins{}}}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	info, err := c.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.OpenTransport(ctx); err != nil {
		t.Fatalf("authenticated gateway: %v", err)
	}
	for _, network := range []string{"udp", "tcp"} {
		succeeded := false
		for _, server := range info.DNS {
			conn, e := c.DialContext(ctx, network, net.JoinHostPort(server, "53"))
			if e != nil {
				t.Logf("tunnel DNS dial: %v", e)
				continue
			}
			conn.SetDeadline(time.Now().Add(8 * time.Second))
			name, _ := dnsmessage.NewName("ecnu.edu.cn.")
			query, _ := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 1234, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}).Pack()
			if network == "tcp" {
				query = append(binary.BigEndian.AppendUint16(nil, uint16(len(query))), query...)
			}
			_, e = conn.Write(query)
			if e != nil {
				conn.Close()
				continue
			}
			b := make([]byte, 4096)
			n := 0
			if network == "tcp" {
				var size [2]byte
				_, e = io.ReadFull(conn, size[:])
				if e == nil {
					n = int(binary.BigEndian.Uint16(size[:]))
					if n > len(b) {
						e = io.ErrShortBuffer
					} else {
						_, e = io.ReadFull(conn, b[:n])
					}
				}
			} else {
				n, e = conn.Read(b)
			}
			conn.Close()
			if e != nil {
				t.Logf("tunnel DNS read: %v", e)
				continue
			}
			var answer dnsmessage.Message
			if answer.Unpack(b[:n]) == nil && answer.ID == 1234 && answer.Response {
				t.Logf("authorized %s DNS round trip succeeded", network)
				succeeded = true
				break
			}
		}
		if !succeeded {
			t.Fatalf("no authorized %s DNS round trip", network)
		}
	}
	if os.Getenv("GEEKTRUST_TEST_HTTP") == "1" {
		transport := &http.Transport{DialContext: c.DialContext}
		defer transport.CloseIdleConnections()
		h := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		req, _ := http.NewRequestWithContext(ctx, "GET", "https://www.ecnu.edu.cn/", nil)
		resp, err := h.Do(req)
		if err != nil {
			t.Fatalf("authorized HTTP request: %v", err)
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		t.Logf("authorized HTTPS response: %d", resp.StatusCode)
	}
	icmpTarget := ""
	for _, r := range info.Resources {
		if net.ParseIP(r.Address).To4() != nil && (r.Protocol == "icmp" || r.Protocol == "all" || r.Protocol == "") && r.PortMin == 0 {
			icmpTarget = r.Address
			break
		}
	}
	if os.Getenv("GEEKTRUST_TEST_ICMP") == "1" && icmpTarget == "" {
		t.Log("ICMP not exercised: no authorized exact-IP Echo target")
	}
	if os.Getenv("GEEKTRUST_TEST_ICMP") == "1" && icmpTarget != "" {
		packet := make([]byte, 32)
		packet[0], packet[8], packet[9], packet[20] = 0x45, 64, 1, 8
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		copy(packet[12:16], net.IPv4(192, 0, 2, 1).To4())
		copy(packet[16:20], net.ParseIP(icmpTarget).To4())
		copy(packet[24:], []byte{1, 2, 0, 1, 't', 'e', 's', 't'})
		checksum := func(b []byte) uint16 {
			var sum uint32
			for len(b) >= 2 {
				sum += uint32(binary.BigEndian.Uint16(b))
				b = b[2:]
			}
			if len(b) > 0 {
				sum += uint32(b[0]) << 8
			}
			for sum>>16 != 0 {
				sum = sum&65535 + sum>>16
			}
			return ^uint16(sum)
		}
		binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:20]))
		binary.BigEndian.PutUint16(packet[22:24], checksum(packet[20:]))
		reply, err := c.ExchangeICMPEcho(ctx, packet)
		if err != nil {
			t.Fatalf("authorized ICMP exchange: %v", err)
		}
		if len(reply) < 28 || reply[20] != 0 {
			t.Fatal("missing ICMP Echo reply")
		}
		t.Log("authorized ICMP Echo round trip succeeded")
	}

}

type stageHandler struct{ t *testing.T }

func (h stageHandler) Enabled(context.Context, slog.Level) bool      { return true }
func (h stageHandler) Handle(_ context.Context, r slog.Record) error { h.t.Log(r.Message); return nil }
func (h stageHandler) WithAttrs([]slog.Attr) slog.Handler            { return h }
func (h stageHandler) WithGroup(string) slog.Handler                 { return h }
