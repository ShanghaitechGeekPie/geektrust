package runtime

import (
	"context"
	"net"
	"net/netip"
)

type checkedDNSDialer struct{ c *Runtime }

func (d checkedDNSDialer) check(ctx context.Context, ip string, port int, network string) error {
	if d.c.checkTarget == nil {
		return nil
	}
	a, e := netip.ParseAddr(ip)
	if e != nil {
		return e
	}
	return d.c.checkTarget(ctx, Target{Generation: d.c.currentGeneration(), IP: a.Unmap(), Port: uint16(port), Network: network, Purpose: DNSQueryTarget})
}
func (d checkedDNSDialer) Dial(ctx context.Context, ip string, port int, app, domain string) (net.Conn, error) {
	if e := d.check(ctx, ip, port, "tcp"); e != nil {
		return nil, e
	}
	return d.c.dialer.Dial(ctx, ip, port, app, domain)
}
func (d checkedDNSDialer) DialUDP(ctx context.Context, ip string, port int, app, domain string) (net.Conn, error) {
	if e := d.check(ctx, ip, port, "udp"); e != nil {
		return nil, e
	}
	return d.c.dialer.DialUDP(ctx, ip, port, app, domain)
}
