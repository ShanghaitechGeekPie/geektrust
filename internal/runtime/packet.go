package runtime

import (
	"context"
	"errors"
	"net/netip"
)

func (c *Runtime) ExchangeICMPEcho(parent context.Context, packet []byte) ([]byte, error) {
	if c.isClosed() {
		return nil, ErrClosed
	}
	ctx, done := c.operation(parent)
	defer done()
	if e := c.prepare(ctx); e != nil {
		return nil, e
	}
	if c.checkTarget != nil {
		if len(packet) < 20 || packet[0]>>4 != 4 {
			return nil, errors.New("invalid IPv4 packet")
		}
		ip := netip.AddrFrom4([4]byte(packet[16:20]))
		if err := c.checkTarget(ctx, Target{Generation: c.currentGeneration(), Network: "icmp", IP: ip}); err != nil {
			return nil, err
		}
	}
	return c.dialer.ExchangePacket(ctx, packet)
}
