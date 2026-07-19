// Package resolver maps target hostnames to tunnel-internal IPs
// (PLAN.md §2.1): the appList domain map first, public DNS as fallback.
// Resolution lives in the inbound layer so Dialer keeps "IPs only" semantics.
package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"

	"geektrust/internal/session"
)

// ErrUnresolvable means the host has neither a tunnel mapping nor a DNS
// answer; inbound surfaces it as SOCKS5 host-unreachable.
var ErrUnresolvable = errors.New("host not resolvable")

// Resolver resolves targets against the live credential's domain map.
type Resolver struct {
	provider session.CredentialProvider
	fallback *net.Resolver
}

// New builds a Resolver. dnsServers (bare IPs) override the system resolver
// for the public-DNS fallback; empty uses the system default.
func New(provider session.CredentialProvider, dnsServers []string) *Resolver {
	var fallback *net.Resolver
	if len(dnsServers) > 0 {
		var next atomic.Uint32
		servers := append([]string(nil), dnsServers...)
		fallback = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				// Honor the requested network: the resolver retries
				// truncated answers over TCP, which needs the length
				// prefixed TCP exchange, not another UDP socket.
				server := servers[next.Add(1)%uint32(len(servers))]
				return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(server, "53"))
			},
		}
	} else {
		fallback = net.DefaultResolver
	}
	return &Resolver{provider: provider, fallback: fallback}
}

// Resolve returns the tunnel-internal IP to dial for host plus the appId
// authorizing it. IP literals pass through; unmapped domains fall back to
// public DNS (the answer routes through the tunnel like any other IP).
func (r *Resolver) Resolve(ctx context.Context, host string) (ip string, appID string, err error) {
	cred, err := r.provider.Credential(ctx)
	if err != nil {
		return "", "", err
	}

	if parsed := net.ParseIP(host); parsed != nil {
		v4 := parsed.To4()
		if v4 == nil {
			return "", "", fmt.Errorf("%w: %s: IPv6 targets are not supported", ErrUnresolvable, host)
		}
		return v4.String(), appForIP(cred, v4.String()), nil
	}
	if ep, ok := cred.DomainMap[host]; ok {
		return ep.IP, ep.AppID, nil
	}

	addrs, err := r.fallback.LookupIPAddr(ctx, host)
	if err != nil {
		return "", "", fmt.Errorf("%w: %s: %v", ErrUnresolvable, host, err)
	}
	for _, a := range addrs {
		if v4 := a.IP.To4(); v4 != nil {
			return v4.String(), appForIP(cred, v4.String()), nil
		}
	}
	return "", "", fmt.Errorf("%w: %s: no IPv4 answer", ErrUnresolvable, host)
}

func appForIP(cred *session.Credential, ip string) string {
	if id, ok := cred.IPApps[ip]; ok && id != "" {
		return id
	}
	return cred.AppID
}
