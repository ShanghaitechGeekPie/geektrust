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
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return nil, errors.New("invalid IPv4 packet")
	}
	ctx, done := c.operation(parent)
	defer done()
	if e := c.prepare(ctx); e != nil {
		return nil, e
	}
	cred, err := c.provider.Credential(ctx)
	if err != nil {
		return nil, err
	}
	ctx, releaseSession := bindSession(ctx, cred)
	defer releaseSession()
	if c.checkTarget != nil {
		ip := netip.AddrFrom4([4]byte(packet[16:20]))
		if err := c.checkTarget(ctx, Target{Generation: cred.Generation, Network: "icmp", IP: ip}); err != nil {
			return nil, err
		}
	}
	return c.dialer.ExchangePacket(ctx, packet)
}
