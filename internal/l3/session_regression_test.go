package l3

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ShanghaitechGeekPie/geektrust/internal/frame"
	"github.com/ShanghaitechGeekPie/geektrust/internal/sdpc"
	"github.com/ShanghaitechGeekPie/geektrust/internal/session"
	"github.com/ShanghaitechGeekPie/geektrust/internal/tunnel"
)

type flowSessionProvider struct {
	current atomic.Pointer[session.Credential]
}

func (p *flowSessionProvider) Credential(ctx context.Context) (*session.Credential, error) {
	return p.current.Load(), ctx.Err()
}
func (*flowSessionProvider) InvalidateIfCurrent(*session.Credential) bool { return false }

// Rotate the session while the gateway is authenticating the first tunnel,
// then record the real per-flow authorization sent on the replacement tunnel.
func newRotatingFlowGateway(t *testing.T) (*Dialer, <-chan authRequestIP) {
	t.Helper()
	certServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	cert := certServer.Certificate()
	certificates := certServer.TLS.Certificates
	certServer.Close()
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: certificates})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	p := &flowSessionProvider{}
	p.current.Store(&session.Credential{
		SID: "old-session", DeviceID: "test-device", Gateways: []string{listener.Addr().String()},
		Policy: &sdpc.Resource{IPRules: []sdpc.IPRule{{
			IP: net.ParseIP("10.0.0.53"), AppID: "test-app", Port: sdpc.PortRange{Min: 0, Max: 65535},
		}}},
	})
	requests := make(chan authRequestIP, 1)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				br := bufio.NewReader(conn)
				method := make([]byte, 3)
				if _, err := io.ReadFull(br, method); err != nil {
					return
				}
				reader := frame.NewReaderBuf(br)
				auth, err := reader.ReadFrame()
				if err != nil || auth.Cmd != frame.CmdSFrame {
					return
				}
				vipRequest := make([]byte, 10)
				if _, err := io.ReadFull(br, vipRequest); err != nil {
					return
				}
				var login struct {
					SID string `json:"sid"`
				}
				if json.Unmarshal(auth.Payload, &login) != nil {
					return
				}
				if login.SID == "old-session" {
					updated := *p.current.Load()
					updated.SID = "new-session"
					p.current.Store(&updated)
				}
				body := []byte(`{"code":0,"data":{"deviceId":"test-device"}}`)
				reply := []byte{5, 0xd0, 0x53, 0}
				reply = binary.BigEndian.AppendUint16(reply, uint16(len(body)))
				reply = append(reply, body...)
				reply = append(reply, 5, 0, 0, 1, 10, 0, 0, 2, 0, 0)
				if _, err := conn.Write(reply); err != nil {
					return
				}
				request, err := reader.ReadFrame()
				if err != nil || request.Cmd != frame.CmdAuthRequest {
					return
				}
				var flow authRequestIP
				if json.Unmarshal(request.Payload, &flow) != nil {
					return
				}
				requests <- flow
				body, _ = json.Marshal(map[string]any{
					"code": 10000005, "data": map[string]any{"conntrackHash": flow.ConntrackHash},
				})
				reply = []byte{5, frame.CmdAuthResponse, 0x82}
				reply = binary.BigEndian.AppendUint16(reply, uint16(len(body)))
				reply = append(reply, body...)
				conn.Write(reply)
				io.Copy(io.Discard, br)
			}()
		}
	}()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := tunnel.NewManager(p, logger)
	m.MaxAttempts = 1
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	m.GatewayTLSConfig = &tls.Config{RootCAs: roots}
	t.Cleanup(m.Close)
	return &Dialer{Manager: m, Provider: p, Logger: logger}, requests
}

func TestFlowAuthorizationUsesAuthenticatedSession(t *testing.T) {
	for _, protocol := range []int{protocolTCP, protocolUDP, protocolICMP} {
		name, _ := protocolName(protocol)
		t.Run(name, func(t *testing.T) {
			d, requests := newRotatingFlowGateway(t)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			var err error
			if protocol == protocolICMP {
				packet := make([]byte, 28)
				packet[0], packet[8], packet[9], packet[20] = 0x45, 64, protocolICMP, icmpEchoRequest
				binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
				copy(packet[12:16], net.ParseIP("192.0.2.1").To4())
				copy(packet[16:20], net.ParseIP("10.0.0.53").To4())
				fixChecksum(packet[:20], 10)
				fixChecksum(packet[20:], 2)
				_, err = d.ExchangePacket(ctx, packet)
			} else {
				_, err = d.authorizeFlow(ctx, "10.0.0.53", 53, "test-app", "", protocol)
			}
			var rejected *AuthRejectedError
			if !errors.As(err, &rejected) || rejected.Code != 10000005 {
				t.Fatalf("gateway response: %v", err)
			}
			select {
			case request := <-requests:
				if request.Sid != "new-session" || request.IP.Protocol != protocol {
					t.Fatalf("authorization SID=%s protocol=%d", request.Sid, request.IP.Protocol)
				}
			default:
				t.Fatal("gateway did not receive flow authorization")
			}
		})
	}
}
