package l3

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/ShanghaitechGeekPie/geektrust/internal/tunnel"
)

const (
	icmpEchoReply   = 0
	icmpEchoRequest = 8
)

var ErrPacketUnsupported = errors.New("only unfragmented IPv4 ICMP Echo requests are supported")

// ExchangePacket forwards one Echo request and returns the actual gateway reply.
// The caller owns the local interface; only the protocol's virtual source address
// and multiplexing identifier are substituted while the packet is in flight.
func (d *Dialer) ExchangePacket(ctx context.Context, packet []byte) ([]byte, error) {
	ihl, err := validateEcho(packet, icmpEchoRequest)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	cred, err := d.Provider.Credential(ctx)
	if err != nil {
		return nil, err
	}
	if cred.Policy == nil {
		return nil, errors.New("missing resource policy")
	}
	destination := net.IP(packet[16:20])
	app := cred.Policy.AppIDForProtocol(destination, 0, "", "icmp")
	if app == "" {
		return nil, errors.New("ICMP target is not authorized")
	}
	manager, err := d.Manager.ForApp(ctx, app)
	if err != nil {
		return nil, err
	}
	tun, err := manager.Tunnel(ctx)
	if err != nil {
		return nil, err
	}
	sink := &echoSink{packets: make(chan []byte, 1)}
	id, err := tun.ReserveConn(sink)
	if err != nil {
		return nil, err
	}
	defer tun.UnregisterConn(id)
	authID := tun.NextAuthID()
	// ICMP has no transport ports; only the Echo identifier is rewritten below.
	body, err := buildAuthRequestIP(tun.SID(), app, cred.DeviceID, destination.String(), 0, tun.VIP(), 0, authID, "", protocolICMP, cred.ProcessIdentity)
	if err != nil {
		return nil, err
	}
	auth, err := tun.RequestAuth(ctx, authID, body)
	if err != nil {
		return nil, fmt.Errorf("ICMP authorization: %w", err)
	}
	if auth.Code != 0 {
		if auth.ShouldSwitchLine() {
			manager.SwitchLine()
		}
		return nil, &AuthRejectedError{Code: auth.Code, SwitchLine: auth.ShouldSwitchLine()}
	}
	if auth.ConnectToken == "" {
		return nil, errors.New("missing ICMP authorization token")
	}
	d.Logger.Debug("ICMP flow authorized")
	request := append([]byte(nil), packet...)
	copy(request[12:16], tun.VIP().To4())
	binary.BigEndian.PutUint16(request[ihl+4:ihl+6], id)
	fixChecksum(request[:ihl], 10)
	fixChecksum(request[ihl:], 2)
	deadline, _ := ctx.Deadline()
	if err := tun.SendData(auth.ConnectToken, deadline, request); err != nil {
		return nil, err
	}
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-tun.Dead():
			return nil, tunnel.ErrTunnelDead
		case reply := <-sink.packets:
			rh, err := validateEcho(reply, icmpEchoReply)
			if err != nil || !bytes.Equal(reply[12:16], packet[16:20]) ||
				!bytes.Equal(reply[16:20], tun.VIP().To4()) ||
				binary.BigEndian.Uint16(reply[rh+4:rh+6]) != id ||
				!bytes.Equal(reply[rh+6:], packet[ihl+6:]) {
				continue
			}
			copy(reply[16:20], packet[12:16])
			copy(reply[rh+4:rh+6], packet[ihl+4:ihl+6])
			fixChecksum(reply[:rh], 10)
			fixChecksum(reply[rh:], 2)
			return reply, nil
		}
	}
}

type echoSink struct{ packets chan []byte }

func (s *echoSink) DeliverPacket(packet []byte) {
	select {
	case s.packets <- append([]byte(nil), packet...):
	default:
	}
}

func validateEcho(packet []byte, kind byte) (int, error) {
	if len(packet) < 28 || packet[0]>>4 != 4 || packet[9] != protocolICMP {
		return 0, ErrPacketUnsupported
	}
	ihl := int(packet[0]&15) * 4
	if ihl < 20 || len(packet) < ihl+8 || int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) ||
		binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 || packet[ihl] != kind || packet[ihl+1] != 0 {
		return 0, ErrPacketUnsupported
	}
	if internetChecksum(packet[:ihl]) != 0 || internetChecksum(packet[ihl:]) != 0 {
		return 0, errors.New("invalid ICMP packet checksum")
	}
	return ihl, nil
}

func fixChecksum(b []byte, offset int) {
	b[offset], b[offset+1] = 0, 0
	binary.BigEndian.PutUint16(b[offset:offset+2], internetChecksum(b))
}

func internetChecksum(b []byte) uint16 {
	var sum uint32
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b[:2]))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
