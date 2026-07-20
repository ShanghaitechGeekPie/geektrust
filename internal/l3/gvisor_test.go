package l3

import (
	"encoding/binary"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

type sendCall struct {
	token    string
	deadline time.Time
	packets  [][]byte
}

type fakeDataSender struct {
	mu    sync.Mutex
	calls []sendCall
}

func (f *fakeDataSender) SendData(token string, deadline time.Time, packets ...[]byte) error {
	call := sendCall{token: token, deadline: deadline, packets: make([][]byte, len(packets))}
	for i, packet := range packets {
		call.packets[i] = append([]byte(nil), packet...)
	}
	f.mu.Lock()
	f.calls = append(f.calls, call)
	f.mu.Unlock()
	return nil
}

func TestLinkEndpointBatchesConsecutivePacketsByToken(t *testing.T) {
	sender := &fakeDataSender{}
	endpoint := &linkEndpoint{
		tun:    sender,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		routes: map[uint16]dataRoute{
			30001: {token: "token-a"},
			30002: {token: "token-b"},
		},
	}
	var packets stack.PacketBufferList
	for _, port := range []uint16{30001, 30001, 30002} {
		packets.PushBack(stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(testIPv4TCPPacket(port, 443)),
		}))
	}
	defer packets.DecRef()

	if sent, err := endpoint.WritePackets(packets); err != nil || sent != 3 {
		t.Fatalf("WritePackets = (%d, %v), want (3, nil)", sent, err)
	}
	if len(sender.calls) != 2 {
		t.Fatalf("SendData calls = %d, want 2", len(sender.calls))
	}
	if sender.calls[0].token != "token-a" || len(sender.calls[0].packets) != 2 {
		t.Fatalf("first call = token %q, %d packets", sender.calls[0].token, len(sender.calls[0].packets))
	}
	if sender.calls[1].token != "token-b" || len(sender.calls[1].packets) != 1 {
		t.Fatalf("second call = token %q, %d packets", sender.calls[1].token, len(sender.calls[1].packets))
	}
}

func TestLinkEndpointDoesNotBatchDifferentDeadlines(t *testing.T) {
	sender := &fakeDataSender{}
	firstDeadline := time.Now().Add(time.Second)
	secondDeadline := firstDeadline.Add(time.Second)
	endpoint := &linkEndpoint{
		tun:    sender,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		routes: map[uint16]dataRoute{
			30001: {token: "token", deadline: firstDeadline},
			30002: {token: "token", deadline: secondDeadline},
		},
	}
	var packets stack.PacketBufferList
	for _, port := range []uint16{30001, 30002} {
		packets.PushBack(stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(testIPv4TCPPacket(port, 443)),
		}))
	}
	defer packets.DecRef()

	if sent, err := endpoint.WritePackets(packets); err != nil || sent != 2 {
		t.Fatalf("WritePackets = (%d, %v), want (2, nil)", sent, err)
	}
	if len(sender.calls) != 2 ||
		!sender.calls[0].deadline.Equal(firstDeadline) ||
		!sender.calls[1].deadline.Equal(secondDeadline) {
		t.Fatalf("SendData deadlines = %+v", sender.calls)
	}
}

func TestLinkEndpointDropsExpiredRouteWithoutDroppingLaterPackets(t *testing.T) {
	sender := &fakeDataSender{}
	endpoint := &linkEndpoint{
		tun:    sender,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		routes: map[uint16]dataRoute{
			30001: {token: "expired", deadline: time.Now().Add(-time.Second)},
			30002: {token: "live"},
		},
	}
	var packets stack.PacketBufferList
	for _, port := range []uint16{30001, 39999, 30002} {
		packets.PushBack(stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(testIPv4TCPPacket(port, 443)),
		}))
	}
	defer packets.DecRef()

	if sent, err := endpoint.WritePackets(packets); err != nil || sent != 3 {
		t.Fatalf("WritePackets = (%d, %v), want (3, nil)", sent, err)
	}
	if len(sender.calls) != 1 || sender.calls[0].token != "live" {
		t.Fatalf("SendData calls = %+v, want only live route", sender.calls)
	}
}

func TestLinkEndpointConsumesUnreservedPort(t *testing.T) {
	endpoint := &linkEndpoint{
		tun:    &fakeDataSender{},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		routes: make(map[uint16]dataRoute),
	}
	var packets stack.PacketBufferList
	packets.PushBack(stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(testIPv4TCPPacket(30001, 443)),
	}))
	defer packets.DecRef()

	if sent, err := endpoint.WritePackets(packets); err != nil || sent != 1 {
		t.Fatalf("WritePackets = (%d, %v), want (1, nil)", sent, err)
	}
}

func TestLinkEndpointClosePreventsRouteResurrection(t *testing.T) {
	endpoint := &linkEndpoint{
		tun:    &fakeDataSender{},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		routes: map[uint16]dataRoute{30001: {}},
	}
	ports := endpoint.closeRoutes()
	if len(ports) != 1 || ports[0] != 30001 {
		t.Fatalf("closed routes = %v, want [30001]", ports)
	}
	if endpoint.addRoute(30002) {
		t.Fatal("route added after endpoint close")
	}
	if endpoint.updateRoute(30001, dataRoute{token: "stale"}) {
		t.Fatal("route updated after endpoint close")
	}
}

func TestTCPSourcePortValidatesIPv4TCPHeader(t *testing.T) {
	packet := testIPv4TCPPacket(32123, 993)
	if port, ok := tcpSourcePort(packet); !ok || port != 32123 {
		t.Fatalf("tcpSourcePort = (%d, %v), want (32123, true)", port, ok)
	}
	packet[9] = 17
	if _, ok := tcpSourcePort(packet); ok {
		t.Fatal("UDP packet accepted as TCP")
	}
	if _, ok := tcpSourcePort(packet[:10]); ok {
		t.Fatal("truncated packet accepted")
	}
}

func testIPv4TCPPacket(srcPort, dstPort uint16) []byte {
	packet := make([]byte, 40)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 6
	copy(packet[12:16], []byte{10, 19, 240, 43})
	copy(packet[16:20], []byte{10, 15, 45, 163})
	binary.BigEndian.PutUint16(packet[20:22], srcPort)
	binary.BigEndian.PutUint16(packet[22:24], dstPort)
	packet[32] = 5 << 4
	return packet
}
