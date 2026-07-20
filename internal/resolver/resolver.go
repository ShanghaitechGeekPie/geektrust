// Package resolver maps target hosts to tunnel IPs and authorization data.
// It prefers exact domain mappings and DNS-resolved IP policy, then falls
// back to domain wildcards when no IP rule applies.
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

// Resolver resolves targets against the live credential's routing policy.
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

	v4, err := r.lookupIPv4(ctx, host)
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
