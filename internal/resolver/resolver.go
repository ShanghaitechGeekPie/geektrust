// Package resolver maps target hosts to tunnel IPs and authorization data.
// It prefers exact domain mappings and public DNS-resolved IP policy, then
// falls back to controller-pushed split-horizon DNS through the tunnel.
package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"

	"geektrust/internal/session"
)

type TunnelDialer interface {
	Dial(ctx context.Context, ip string, port int, appID, domain string) (net.Conn, error)
	DialUDP(ctx context.Context, ip string, port int, appID, domain string) (net.Conn, error)
}

// ErrUnresolvable means the host has neither a tunnel mapping nor a DNS
// answer; inbound surfaces it as SOCKS5 host-unreachable.
var ErrUnresolvable = errors.New("host not resolvable")

// DefaultPublicDNS is used before the tunnel DNS fallback. Querying public
// resolvers directly sidesteps local fake-ip DNS for ordinary public names.
// Controller-pushed DNS is queried through the VPN for split-horizon names.
var DefaultPublicDNS = []string{"223.5.5.5", "119.29.29.29"}

// Resolver resolves targets against the live credential's routing policy.
type Resolver struct {
	provider session.CredentialProvider
	tunnel   TunnelDialer
	stages   []*net.Resolver // direct public resolvers, then the system resolver
}

// New builds a Resolver. Controller-pushed or configured DNS servers are read
// from the live credential and reached through tunnel.
func New(provider session.CredentialProvider, tunnel TunnelDialer) *Resolver {
	pool := append([]string(nil), DefaultPublicDNS...)
	var next atomic.Uint32
	custom := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			// Honor the requested network: the resolver retries truncated
			// answers over TCP, which needs the length-prefixed TCP
			// exchange, not another UDP socket.
			server := pool[(next.Add(1)-1)%uint32(len(pool))]
			return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(server, "53"))
		},
	}
	return &Resolver{provider: provider, tunnel: tunnel, stages: []*net.Resolver{custom, net.DefaultResolver}}
}

// Resolution is a resolved dial target.
type Resolution struct {
	IP    string
	AppID string
	// Domain carries the original hostname when the target is authorized
	// via a wildcard (suffix) rule: the gateway matches "*.com"-style
	// entries against the auth request's domain field, not the resolved IP.
	// Empty for IP-authorized targets.
	Domain string
}

// Resolve returns the tunnel target for host:port. Order: IP literal →
// exact domain rule → DNS + IP-policy match → TLD suffix fallback.
//
// The IP-policy match carries no domain: the gateway checks the destAddr
// against the app's address ranges. The suffix fallback does carry the
// domain: wildcard ("*.com") entries are matched against the auth
// request's domain field, and the gateway cross-checks the destAddr
// against its own resolution of that domain.
func (r *Resolver) Resolve(ctx context.Context, host string, port int) (Resolution, error) {
	cred, err := r.provider.Credential(ctx)
	if err != nil {
		return Resolution{}, err
	}

	if parsed := net.ParseIP(host); parsed != nil {
		v4 := parsed.To4()
		if v4 == nil {
			return Resolution{}, fmt.Errorf("%w: %s: IPv6 targets are not supported", ErrUnresolvable, host)
		}
		return Resolution{IP: v4.String(), AppID: cred.Policy.AppIDFor(v4, port, cred.AppID)}, nil
	}
	if rule, ok := cred.Policy.MatchDomain(host, port); ok {
		return Resolution{IP: rule.IP, AppID: rule.AppID}, nil
	}

	v4, err := r.lookupIPv4(ctx, host, cred)
	if err != nil {
		return Resolution{}, fmt.Errorf("%w: %s: %v", ErrUnresolvable, host, err)
	}
	return routeDNSResult(cred, host, port, v4), nil
}

func routeDNSResult(cred *session.Credential, host string, port int, v4 net.IP) Resolution {
	if rule, ok := cred.Policy.MatchIP(v4, port); ok {
		return Resolution{IP: v4.String(), AppID: rule.AppID}
	}
	if rule, ok := cred.Policy.MatchSuffix(host, port); ok {
		return Resolution{IP: v4.String(), AppID: rule.AppID, Domain: host}
	}
	return Resolution{IP: v4.String(), AppID: cred.AppID}
}

// lookupIPv4 first tries direct public/system resolution. If those stages
// produce no usable address, controller-pushed DNS servers are queried over
// authenticated UDP flows inside the VPN.
func (r *Resolver) lookupIPv4(ctx context.Context, host string, cred *session.Credential) (net.IP, error) {
	var lastErr error = errNoIPv4Answer
	for _, res := range r.stages {
		if v4, err := lookupIPv4With(ctx, res, host); err == nil {
			return v4, nil
		} else {
			lastErr = err
		}
	}
	if r.tunnel != nil {
		for _, server := range cred.DNS {
			res := r.tunnelResolver(cred, server)
			if v4, err := lookupIPv4With(ctx, res, host); err == nil {
				return v4, nil
			} else {
				lastErr = err
			}
		}
	}
	return nil, lastErr
}

func lookupIPv4With(ctx context.Context, res *net.Resolver, host string) (net.IP, error) {
	addrs, err := res.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		if addr.Is4() {
			v4 := net.IP(addr.AsSlice())
			if !IsFakeIP(v4) {
				return v4, nil
			}
		}
	}
	return nil, errNoIPv4Answer
}

func (r *Resolver) tunnelResolver(cred *session.Credential, server string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			ip := net.ParseIP(server).To4()
			if ip == nil {
				return nil, fmt.Errorf("invalid tunnel DNS server %q", server)
			}
			appID := cred.AppID
			if cred.Policy != nil {
				appID = cred.Policy.AppIDFor(ip, 53, appID)
			}
			if network == "tcp" || network == "tcp4" {
				return r.tunnel.Dial(ctx, ip.String(), 53, appID, "")
			}
			return r.tunnel.DialUDP(ctx, ip.String(), 53, appID, "")
		},
	}
}

var errNoIPv4Answer = errors.New("no usable IPv4 answer")

// IsFakeIP reports placeholder addresses handed out by local proxy tools in
// fake-ip mode (198.18.0.0/15, the RFC 2544 benchmarking range) instead of
// real DNS answers.
func IsFakeIP(ip net.IP) bool {
	v4 := ip.To4()
	return v4 != nil && v4[0] == 198 && (v4[1] == 18 || v4[1] == 19)
}
