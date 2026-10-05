package runtime

import (
	"context"
	"github.com/ShanghaitechGeekPie/geektrust/internal/resolver"
	"github.com/ShanghaitechGeekPie/geektrust/internal/sdpc"
	"github.com/ShanghaitechGeekPie/geektrust/internal/session"
	"github.com/ShanghaitechGeekPie/geektrust/internal/settings"
	"net"
	"net/netip"
	"strconv"
)

// CLI hooks remain internal; the public facade does not expose protocol clients.
func (c *Runtime) Provider() *session.Provider { return c.provider }
func (c *Runtime) ConfigureCommand(s settings.Session, strategy string) {
	if s.LegacyGatewayOverride && len(s.Gateways) > 0 {
		c.provider.SetLegacyGateways(s.Gateways)
	}
	if strategy == "auto" {
		c.resolver = resolver.New(c.provider, checkedDNSDialer{c})
	}
	if strategy == "system" {
		c.resolver = resolver.NewController(c.provider, checkedDNSDialer{c}, func(ctx context.Context, h string) ([]netip.Addr, error) {
			v, e := net.DefaultResolver.LookupNetIP(ctx, "ip4", h)
			return v, e
		}, true)
	}
}
func (c *Runtime) Resolve(ctx context.Context, h string, p int) (resolver.Resolution, error) {
	v, e := c.resolver.Resolve(session.WithInteraction(ctx, false), h, p)
	return v, e
}
func (c *Runtime) ResolveUDP(ctx context.Context, h string, p int) (resolver.Resolution, error) {
	v, e := c.resolver.ResolveUDP(session.WithInteraction(ctx, false), h, p)
	return v, e
}
func (c *Runtime) Dial(ctx context.Context, ip string, p int, app, domain string) (net.Conn, error) {
	host := domain
	if host == "" {
		host = ip
	}
	return c.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(p)))
}
func (c *Runtime) DialUDP(ctx context.Context, ip string, p int, app, domain string) (net.Conn, error) {
	host := domain
	if host == "" {
		host = ip
	}
	return c.DialContext(ctx, "udp", net.JoinHostPort(host, strconv.Itoa(p)))
}
func (c *Runtime) ActiveSDPC() *sdpc.Client { return c.provider.ActiveSDPC() }
func (c *Runtime) TryForceRelogin() (func(context.Context), bool) {
	run, ok := c.provider.TryForceRelogin()
	if !ok {
		return nil, false
	}
	return func(parent context.Context) {
		ctx, done := c.withLifetime(parent)
		defer done()
		ctx = session.WithInteraction(ctx, true)
		if c.prepare(ctx) != nil {
			cancelled, cancel := context.WithCancel(ctx)
			cancel()
			run(cancelled)
			return
		}
		run(ctx)
	}, true
}
