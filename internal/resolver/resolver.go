// Package resolver maps target hosts to tunnel IPs and authorization data.
// It prefers exact domain mappings and public DNS-resolved IP policy, then
// falls back to controller-pushed split-horizon DNS through the tunnel.
package resolver

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/ShanghaitechGeekPie/geektrust/internal/session"
)

type TunnelDialer interface {
	Dial(ctx context.Context, ip string, port int, appID, domain string) (net.Conn, error)
	DialUDP(ctx context.Context, ip string, port int, appID, domain string) (net.Conn, error)
}

// ErrUnresolvable means the host has neither a tunnel mapping nor a DNS
// answer; inbound surfaces it as SOCKS5 host-unreachable.
var ErrUnresolvable = errors.New("host not resolvable")

// ErrGatewayLoop means a client tried to send a VPN gateway connection back
// through the VPN. Refusing it breaks transparent-proxy routing cycles.
var ErrGatewayLoop = errors.New("refusing to proxy a VPN gateway through its own tunnel")

// DefaultPublicDNS is used before the tunnel DNS fallback. Querying public
// resolvers directly sidesteps local fake-ip DNS for ordinary public names.
// Controller-pushed DNS is queried through the VPN for split-horizon names.
var DefaultPublicDNS = []string{"223.5.5.5", "119.29.29.29"}

// Resolver resolves targets against the live credential's routing policy.
type Resolver struct {
	provider         session.CredentialProvider
	tunnel           TunnelDialer
	stages           []lookupStage // direct public resolvers, then the system resolver
	tunnelDNS        *dnsPool
	controllerFirst  bool
	disableTunnelDNS bool
	fallback         func(context.Context, string) ([]netip.Addr, error)
}

// New builds a Resolver. Controller-pushed or configured DNS servers are read
// from the live credential and reached through tunnel.
func New(provider session.CredentialProvider, tunnel TunnelDialer) *Resolver {
	return NewWithDialer(provider, tunnel, nil)
}

// NewWithDialer allows a host to protect direct DNS traffic from tunnel routes.
func NewWithDialer(provider session.CredentialProvider, tunnel TunnelDialer, dial func(context.Context, string, string) (net.Conn, error)) *Resolver {
	return NewWithDialerOptions(provider, tunnel, dial, false)
}

// NewWithDialerOptions can omit the host system resolver when an embedding
// application has installed its own VPN DNS endpoint. This prevents recursive
// queries back into the application's Fake-IP DNS service.
func NewWithDialerOptions(provider session.CredentialProvider, tunnel TunnelDialer, dial func(context.Context, string, string) (net.Conn, error), disableSystem bool) *Resolver {
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	pool := append([]string(nil), DefaultPublicDNS...)
	publicDNS := newDNSPool()
	stages := []lookupStage{func(ctx context.Context, host string) (net.IP, error) {
		return publicDNS.lookup(ctx, host, "public", pool, dial)
	}}
	if !disableSystem {
		system := &net.Resolver{PreferGo: true, Dial: dial}
		stages = append(stages, func(ctx context.Context, host string) (net.IP, error) {
			stageCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			return lookupIPv4With(stageCtx, system, host)
		})
	}
	return &Resolver{provider: provider, tunnel: tunnel, stages: stages, tunnelDNS: newDNSPool()}
}

// Resolution is a resolved dial target.
type Resolution struct {
	Generation uint64
	Host       string
	IP         string
	AppID      string
	// Domain carries the original hostname when the target is authorized
	// via a wildcard (suffix) rule: the gateway matches "*.com"-style
	// entries against the auth request's domain field, not the resolved IP.
	// Empty for IP-authorized targets.
	Domain string
}

// Resolve returns the TCP tunnel target for host:port.
func (r *Resolver) Resolve(ctx context.Context, host string, port int) (Resolution, error) {
	return r.resolve(ctx, host, port, "tcp")
}

// ResolveUDP returns the UDP tunnel target for host:port.
func (r *Resolver) ResolveUDP(ctx context.Context, host string, port int) (Resolution, error) {
	return r.resolve(ctx, host, port, "udp")
}

// resolve uses this order: IP literal → exact domain rule → DNS + IP-policy
// match → TLD suffix fallback. IP-policy matches carry no domain because the
// gateway checks destAddr. Wildcard matches carry the original domain because
// the gateway checks that field against its own DNS result.
func (r *Resolver) resolve(ctx context.Context, host string, port int, protocol string) (result Resolution, failure error) {
	cred, err := r.provider.Credential(ctx)
	if err != nil {
		return Resolution{}, err
	}
	defer func() {
		if failure == nil {
			result.Generation = cred.Generation
			result.Host = host
		}
	}()
	if isGatewayTarget(cred, host, nil, port) {
		return Resolution{}, fmt.Errorf("%w: %s", ErrGatewayLoop, net.JoinHostPort(host, strconv.Itoa(port)))
	}

	if parsed := net.ParseIP(host); parsed != nil {
		v4 := parsed.To4()
		if v4 == nil {
			return Resolution{}, fmt.Errorf("%w: %s: IPv6 targets are not supported", ErrUnresolvable, host)
		}
		return Resolution{
			IP:    v4.String(),
			AppID: cred.Policy.AppIDForProtocol(v4, port, cred.AppID, protocol),
		}, nil
	}
	if rule, ok := cred.Policy.MatchDomainProtocol(host, port, protocol); ok {
		domain := ""
		if rule.IP == "" {
			ip, err := r.lookupIPv4(ctx, host, cred)
			if err != nil {
				return Resolution{}, err
			}
			rule.IP = ip.String()
			domain = host
		}
		if isGatewayTarget(cred, host, net.ParseIP(rule.IP), port) {
			return Resolution{}, fmt.Errorf("%w: %s", ErrGatewayLoop, net.JoinHostPort(host, strconv.Itoa(port)))
		}
		return Resolution{IP: rule.IP, AppID: rule.AppID, Domain: domain}, nil
	}

	v4, err := r.lookupIPv4(ctx, host, cred)
	if err != nil {
		return Resolution{}, fmt.Errorf("%w: %s: %w", ErrUnresolvable, host, err)
	}
	if isGatewayTarget(cred, host, v4, port) {
		return Resolution{}, fmt.Errorf("%w: %s", ErrGatewayLoop, net.JoinHostPort(host, strconv.Itoa(port)))
	}
	return routeDNSResult(cred, host, port, v4, protocol), nil
}

func routeDNSResult(cred *session.Credential, host string, port int, v4 net.IP, protocol string) Resolution {
	if rule, ok := cred.Policy.MatchIPProtocol(v4, port, protocol); ok {
		return Resolution{IP: v4.String(), AppID: rule.AppID}
	}
	if rule, ok := cred.Policy.MatchSuffixProtocol(host, port, protocol); ok {
		return Resolution{IP: v4.String(), AppID: rule.AppID, Domain: host}
	}
	return Resolution{IP: v4.String(), AppID: cred.AppID}
}

// lookupIPv4 tries public/system resolution before controller DNS. Public
// and tunnel DNS use bounded UDP queries, TCP fallback and recoverable cooldowns.
func (r *Resolver) lookupIPv4(ctx context.Context, host string, cred *session.Credential) (net.IP, error) {
	var lastErr error = errNoIPv4Answer
	for _, stage := range r.stages {
		if ip, err := stage(ctx, host); err == nil {
			return ip, nil
		} else {
			lastErr = err
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	if r.tunnel != nil && !r.disableTunnelDNS && len(cred.DNS) > 0 {
		scope := r.tunnelDNSScope(cred)
		result, lookupErr := r.tunnelDNS.lookup(ctx, host, scope, cred.DNS, func(ctx context.Context, network, address string) (net.Conn, error) {
			server, _, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			ip := net.ParseIP(server).To4()
			if ip == nil {
				return nil, fmt.Errorf("invalid tunnel DNS server %q", server)
			}
			appID := cred.AppID
			if cred.Policy != nil {
				appID = cred.Policy.AppIDForProtocol(ip, 53, appID, network)
			}
			if appID == "" {
				return nil, errors.New("DNS server is not authorized")
			}
			if network == "tcp" {
				return r.tunnel.Dial(ctx, ip.String(), 53, appID, "")
			}
			return r.tunnel.DialUDP(ctx, ip.String(), 53, appID, "")
		})
		if lookupErr == nil {
			return result, nil
		}
		var dnsErr *net.DNSError
		if errors.Is(lookupErr, errNoIPv4Answer) || (errors.As(lookupErr, &dnsErr) && dnsErr.IsNotFound) {
			return nil, lookupErr
		}
		lastErr = lookupErr
	}
	if r.fallback != nil && ctx.Err() == nil {
		answers, err := r.fallback(ctx, host)
		if err != nil {
			return nil, err
		}
		for _, ip := range answers {
			if ip.Is4() {
				return net.IP(ip.AsSlice()), nil
			}
		}
	}
	return nil, lastErr
}

// Reset tunnel health after session, configured DNS, gateway or authorization
// changes. Keep credentials out of map keys and diagnostics.
func (r *Resolver) tunnelDNSScope(cred *session.Credential) string {
	parts := []string{cred.SID, cred.AppID, strings.Join(cred.DNS, ","), strings.Join(cred.Gateways, ",")}
	if cred.Policy != nil {
		parts = append(parts, cred.Policy.MajorNodeGroup)
	}
	for _, server := range cred.DNS {
		ip := net.ParseIP(server)
		if cred.Policy != nil && ip != nil {
			for _, network := range []string{"udp", "tcp"} {
				app := cred.Policy.AppIDForProtocol(ip, 53, cred.AppID, network)
				parts = append(parts, app, cred.Policy.AppNodeGroups[app], strings.Join(cred.Policy.GatewaysForApp(app), ","), strconv.FormatBool(cred.Policy.AppTCPPreferL3[app]))
			}
		}
	}
	hash := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return string(hash[:])
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

func isGatewayTarget(cred *session.Credential, host string, resolved net.IP, port int) bool {
	host = strings.TrimSuffix(host, ".")
	for _, gateway := range cred.Gateways {
		gatewayHost, gatewayPort, err := net.SplitHostPort(gateway)
		if err != nil || gatewayPort != strconv.Itoa(port) {
			continue
		}
		gatewayHost = strings.TrimSuffix(gatewayHost, ".")
		if strings.EqualFold(host, gatewayHost) {
			return true
		}
		gatewayIP := net.ParseIP(gatewayHost)
		if gatewayIP != nil && resolved != nil && gatewayIP.Equal(resolved) {
			return true
		}
	}
	return false
}

var errNoIPv4Answer = errors.New("no usable IPv4 answer")

// IsFakeIP reports placeholder addresses handed out by local proxy tools in
// fake-ip mode (198.18.0.0/15, the RFC 2544 benchmarking range) instead of
// real DNS answers.
func IsFakeIP(ip net.IP) bool {
	v4 := ip.To4()
	return v4 != nil && v4[0] == 198 && (v4[1] == 18 || v4[1] == 19)
}

// LookupHost resolves without imposing a particular destination port.
func (r *Resolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	cred, err := r.provider.Credential(ctx)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() == nil {
			return nil, errNoIPv4Answer
		}
		return []string{ip.String()}, nil
	}
	for _, rule := range cred.Policy.DomainRules {
		if strings.EqualFold(strings.TrimSuffix(host, "."), rule.Domain) && rule.IP != "" {
			return []string{rule.IP}, nil
		}
	}
	ip, err := r.lookupIPv4(ctx, host, cred)
	if err != nil {
		return nil, err
	}
	return []string{ip.String()}, nil
}

// NewController uses only controller DNS, with an explicit host fallback.
func NewController(p session.CredentialProvider, t TunnelDialer, f func(context.Context, string) ([]netip.Addr, error), disabled bool) *Resolver {
	return &Resolver{provider: p, tunnel: t, tunnelDNS: newDNSPool(), controllerFirst: true, disableTunnelDNS: disabled, fallback: f}
}
