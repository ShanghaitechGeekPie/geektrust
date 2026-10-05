package client

import (
	"context"
	"errors"
	"net/netip"
)

// PacketTransport is optional and owns no system interfaces. ExchangePacket
// returns a real response or an error; it never synthesizes Echo success.
// Currently only authorized, unfragmented IPv4 ICMP Echo is supported.
type PacketTransport interface {
	ExchangePacket(context.Context, []byte) ([]byte, error)
}

func (c *Client) ExchangePacket(parent context.Context, packet []byte) ([]byte, error) {
	if c.isClosed() {
		return nil, ErrClosed
	}
	if c.checkTarget != nil {
		if len(packet) < 20 || packet[0]>>4 != 4 {
			return nil, errors.New("invalid IPv4 packet")
		}
		ip := netip.AddrFrom4([4]byte(packet[16:20]))
		if err := c.checkTarget(ip); err != nil {
			return nil, err
		}
	}
	ctx, done := c.operation(parent)
	defer done()
	return c.dialer.ExchangePacket(ctx, packet)
}
