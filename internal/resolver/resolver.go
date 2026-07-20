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

// DefaultPublicDNS is used when no explicit servers are configured. Querying
// public resolvers directly sidesteps local fake-ip DNS: proxy tools in
// fake-ip mode answer every system-DNS query with 198.18.0.0/15 placeholders
// that mean nothing inside the tunnel. The system resolver remains the final
// stage for environments with working local DNS.
var DefaultPublicDNS = []string{"223.5.5.5", "119.29.29.29"}

// Resolver resolves targets against the live credential's domain map.
type Resolver struct {
	provider session.CredentialProvider
	stages   []*net.Resolver // tried in order: explicit/public servers, then system
}

// New builds a Resolver. dnsServers (bare IPs) override the default public
// servers for the DNS fallback stage.
func New(provider session.CredentialProvider, dnsServers []string) *Resolver {
	servers := dnsServers
	if len(servers) == 0 {
		servers = DefaultPublicDNS
	}
	pool := append([]string(nil), servers...)
	var next atomic.Uint32
	custom := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			// Honor the requested network: the resolver retries truncated
			// answers over TCP, which needs the length-prefixed TCP
			// exchange, not another UDP socket.
			server := pool[next.Add(1)%uint32(len(pool))]
			return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(server, "53"))
		},
	}
	return &Resolver{provider: provider, stages: []*net.Resolver{custom, net.DefaultResolver}}
}

// Resolve returns the tunnel-internal IP to dial for host plus the appId
// authorizing it. IP literals pass through; unmapped domains fall back to
// DNS (the answer routes through the tunnel like any other IP).
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

	v4, err := r.lookupIPv4(ctx, host)
	if err != nil {
		return "", "", fmt.Errorf("%w: %s: %v", ErrUnresolvable, host, err)
	}
	return v4.String(), appForIP(cred, v4.String()), nil
}

// lookupIPv4 tries each resolver stage in order and returns the first usable
// IPv4 answer, skipping fake-ip placeholders.
func (r *Resolver) lookupIPv4(ctx context.Context, host string) (net.IP, error) {
	var lastErr error = errNoIPv4Answer
	for _, res := range r.stages {
		addrs, err := res.LookupIPAddr(ctx, host)
		if err != nil {
			lastErr = err
			continue
		}
		for _, a := range addrs {
			if v4 := a.IP.To4(); v4 != nil && !IsFakeIP(v4) {
				return v4, nil
			}
		}
		lastErr = errNoIPv4Answer
	}
	return nil, lastErr
}

var errNoIPv4Answer = errors.New("no usable IPv4 answer")

// IsFakeIP reports placeholder addresses handed out by local proxy tools in
// fake-ip mode (198.18.0.0/15, the RFC 2544 benchmarking range) instead of
// real DNS answers.
func IsFakeIP(ip net.IP) bool {
	v4 := ip.To4()
	return v4 != nil && v4[0] == 198 && (v4[1] == 18 || v4[1] == 19)
}

func appForIP(cred *session.Credential, ip string) string {
	if id, ok := cred.IPApps[ip]; ok && id != "" {
		return id
	}
	return cred.AppID
}
