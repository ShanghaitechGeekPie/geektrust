package runtime

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"

	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ShanghaitechGeekPie/geektrust/auth"
	"github.com/ShanghaitechGeekPie/geektrust/deployment"
	defaults "github.com/ShanghaitechGeekPie/geektrust/internal/deployment"
	"github.com/ShanghaitechGeekPie/geektrust/internal/settings"

	"github.com/ShanghaitechGeekPie/geektrust/internal/l3"
	"github.com/ShanghaitechGeekPie/geektrust/internal/resolver"
	"github.com/ShanghaitechGeekPie/geektrust/internal/session"
	"github.com/ShanghaitechGeekPie/geektrust/internal/tunnel"
)

type Capabilities struct{ IPv4TCP, IPv4UDP, IPv4ICMPEcho, IPv6Targets, IPv6Gateway bool }
type Resource struct {
	Address, Protocol, ApplicationID, GatewayGroup string
	PortMin, PortMax                               int
}
type SessionInfo struct {
	Gateways, DNS         []string
	Resources             []Resource
	Generation            uint64
	Username, DisplayName string
}
type TransportInfo struct {
	Generation  uint64
	Gateway     string
	VirtualIPv4 string
}
type Event struct {
	Time   time.Time
	Status Status
}

var ErrClosed = errors.New("aTrust client closed")
var ErrDatagramTooLarge = errors.New("UDP datagram exceeds tunnel MTU")
var ErrDenied = errors.New("target is not authorized by controller policy")

type Runtime struct {
	ops            sync.WaitGroup
	shutdownDone   chan struct{}
	checkTarget    func(context.Context, Target) error
	provider       *session.Provider
	manager        *tunnel.Manager
	dialer         *l3.Dialer
	resolver       *resolver.Resolver
	ctx            context.Context
	cancel         context.CancelFunc
	mu             sync.Mutex
	closed         bool
	conns          map[*ownedConn]struct{}
	transport      *http.Transport
	subscribers    map[uint64]chan Event
	nextSubscriber uint64
	status         Status
	store          SessionStore
	generation     uint64
	identity       auth.IdentityProvider
	scope          SessionScope
	identityMu     sync.Mutex
	identityReady  bool
	mode           SessionMode
	profile        deployment.Profile
	dialTimeout    time.Duration
	startOnce      sync.Once
	tasksDone      chan struct{}
	forgotten      bool
}

func New(opts Options) (*Runtime, error) {
	u, err := url.Parse(opts.ControllerURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("controller must be an HTTPS origin")
	}
	if len(opts.DeviceID) != 32 || strings.Trim(opts.DeviceID, "0123456789ABCDEF") != "" {
		return nil, errors.New("persistent 32-character uppercase hexadecimal device ID required")
	}
	if opts.Auth.Identity == nil {
		return nil, errors.New("identity provider required")
	}
	if opts.Auth.Mode != BrowserMode && opts.Auth.Mode != DesktopMode {
		return nil, errors.New("invalid session mode")
	}
	if opts.Network.DialTimeout < 0 || opts.Network.HTTPTimeout < 0 {
		return nil, errors.New("invalid network timeout")
	}
	if err := opts.Deployment.Validate(); err != nil {
		return nil, err
	}
	if opts.Network.GatewayTLS.Mode != VerifyCA && opts.Network.GatewayTLS.Mode != VerifyCAOrTOFU {
		return nil, errors.New("invalid gateway trust mode")
	}
	if (opts.Network.GatewayTLS.Mode == VerifyCAOrTOFU) != (opts.Network.GatewayTLS.PinStore != nil) {
		return nil, errors.New("gateway pin store requires CA-or-TOFU mode")
	}
	if t := opts.Network.GatewayTLS.Config; t != nil && t.InsecureSkipVerify {
		return nil, errors.New("gateway certificate verification cannot be disabled")
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	resolved := defaults.Resolve(opts.ControllerURL, opts.Deployment)
	mode := "browser"
	if opts.Auth.Mode == DesktopMode {
		mode = "client"
	}
	u.Host = strings.ToLower(u.Host)
	if u.Port() == "443" {
		u.Host = u.Hostname()
		if strings.Contains(u.Host, ":") {
			u.Host = "[" + u.Host + "]"
		}
	}
	u.Path = ""
	u.RawPath = ""
	cfg := settings.Session{BaseURL: u.String(), DeviceID: opts.DeviceID, Platform: resolved.Platform, LoginDomain: opts.Auth.LoginDomain, ClientType: mode, Compatibility: resolved.Compatibility, StrictStorage: true, GatewayFilter: opts.Network.AllowedGateways != nil}
	if cfg.LoginDomain == "" {
		cfg.LoginDomain = resolved.LoginDomain
	}
	for _, address := range opts.Network.AllowedGateways {
		host, port, e := net.SplitHostPort(address)
		n, x := strconv.Atoi(port)
		if e != nil || x != nil || host == "" || n < 1 || n > 65535 {
			return nil, errors.New("allowed gateway must be host:port")
		}
	}
	if opts.Network.AllowedGateways != nil {
		cfg.Gateways = append([]string{}, opts.Network.AllowedGateways...)
	}
	cfg.DNSConfigured = opts.DNS.Servers != nil
	if opts.DNS.Servers != nil {
		cfg.DNS = make([]string, len(opts.DNS.Servers))
		for i, x := range opts.DNS.Servers {
			if !x.IsValid() {
				return nil, errors.New("invalid DNS address")
			}
			cfg.DNS[i] = x.String()
		}
	}
	mapDomains := resolved.Profile == deployment.ShanghaiTech
	cfg.DomainMapping = &mapDomains
	p := session.NewProvider(cfg, opts.Logger, nil)
	p.ChallengeHandler = opts.Auth.OnChallenge
	p.Transport = opts.Network.ControlTransport
	var owned *http.Transport
	if p.Transport == nil {
		owned = http.DefaultTransport.(*http.Transport).Clone()
		if opts.Network.DialContext != nil {
			owned.DialContext = opts.Network.DialContext
		}
		p.Transport = owned
	}
	p.HTTPTimeout = opts.Network.HTTPTimeout
	m := tunnel.NewManager(p, opts.Logger)
	m.MaxAttempts = 3
	m.DialContext = opts.Network.DialContext
	if t := opts.Network.GatewayTLS.Config; t != nil {
		m.GatewayTLSConfig = t.Clone()
		if t.RootCAs != nil {
			m.GatewayTLSConfig.RootCAs = t.RootCAs.Clone()
		}
	}
	if name := resolved.Compatibility.GatewayServerName; name != "" {
		if m.GatewayTLSConfig == nil {
			m.GatewayTLSConfig = &tls.Config{ServerName: name}
		} else if m.GatewayTLSConfig.ServerName == "" {
			m.GatewayTLSConfig.ServerName = name
		}
	}
	if opts.Network.GatewayTLS.PinStore != nil {
		m.GatewayTrustStore = pinAdapter{store: opts.Network.GatewayTLS.PinStore, controller: cfg.BaseURL, template: m.GatewayTLSConfig}
	}
	d := &l3.Dialer{Manager: m, Provider: p, Logger: opts.Logger}
	ctx, cancel := context.WithCancel(context.Background())
	c := &Runtime{checkTarget: opts.CheckTarget, provider: p, manager: m, dialer: d, transport: owned, ctx: ctx, cancel: cancel, conns: make(map[*ownedConn]struct{}), store: opts.SessionStore, status: Status{State: Idle}, identity: opts.Auth.Identity, mode: opts.Auth.Mode, profile: resolved.Profile, dialTimeout: opts.Network.DialTimeout, subscribers: make(map[uint64]chan Event), tasksDone: make(chan struct{}), shutdownDone: make(chan struct{})}
	p.Authenticate = func(ctx context.Context, h *http.Client) (string, error) {
		if e := c.prepare(ctx); e != nil {
			return "", e
		}
		if e := opts.Auth.Identity.Authenticate(ctx, h, auth.IdentityRequest{AllowInteraction: session.InteractionAllowed(ctx)}); e != nil {
			return "", e
		}
		return "", c.prepare(ctx)
	}
	c.resolver = resolver.NewController(p, checkedDNSDialer{c}, opts.DNS.FallbackLookup, opts.DNS.Servers != nil && len(opts.DNS.Servers) == 0)
	c.scope = SessionScope{ControllerURL: cfg.BaseURL, DeviceID: cfg.DeviceID, Mode: opts.Auth.Mode, LoginDomain: cfg.LoginDomain}
	p.SetStore(&stateStore{store: opts.SessionStore, client: c})
	return c, nil
}
func NewDeviceID() (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}
	return fmt.Sprintf("%X", b), nil
}

// Authenticate forces a fresh login. Concurrent requests share the provider's
// refresh; the embedding application remains responsible for connection retry.
func (c *Runtime) Authenticate(parent context.Context) (SessionInfo, error) {
	if c.isClosed() {
		return SessionInfo{}, ErrClosed
	}
	ctx, done := c.withLifetime(parent)
	defer done()
	ctx = session.WithInteraction(ctx, true)
	if err := c.prepare(ctx); err != nil {
		return SessionInfo{}, err
	}
	if _, err := c.provider.ForceLogin(ctx); err != nil {
		return SessionInfo{}, err
	}
	return c.Connect(ctx)
}
func (c *Runtime) withLifetime(parent context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancel(parent)
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		cancel()
		return ctx, func() {}
	}
	c.ops.Add(1)
	c.mu.Unlock()
	stop := context.AfterFunc(c.ctx, cancel)
	return ctx, func() { stop(); cancel(); c.ops.Done() }
}

func (c *Runtime) operation(parent context.Context) (context.Context, func()) {
	ctx, release := c.withLifetime(parent)
	ctx, cancel := context.WithTimeout(ctx, c.operationTimeout())
	return session.WithInteraction(ctx, false), func() { cancel(); release() }
}

func (c *Runtime) Connect(parent context.Context) (SessionInfo, error) {
	if c.isClosed() {
		return SessionInfo{}, ErrClosed
	}
	ctx, done := c.withLifetime(parent)
	defer done()
	ctx = session.WithInteraction(ctx, true)
	if err := c.prepare(ctx); err != nil {
		return SessionInfo{}, err
	}
	cred, err := c.provider.Credential(ctx)
	if err != nil {
		return SessionInfo{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return SessionInfo{}, ErrClosed
	}
	c.start()
	c.generation = cred.Generation
	info := SessionInfo{Gateways: append([]string(nil), cred.Gateways...), DNS: append([]string(nil), cred.DNS...), Generation: c.generation, Username: cred.Username, DisplayName: cred.DisplayName}
	for _, r := range cred.Policy.IPRules {
		address := ""
		switch {
		case r.IP != nil:
			address = r.IP.String()
		case r.Net != nil:
			address = r.Net.String()
		case r.IPMin != nil:
			address = r.IPMin.String() + "-" + r.IPMax.String()
		}
		info.Resources = append(info.Resources, Resource{Address: address, Protocol: r.Proto, ApplicationID: r.AppID, GatewayGroup: cred.Policy.AppNodeGroups[r.AppID], PortMin: r.Port.Min, PortMax: r.Port.Max})
	}
	for _, r := range cred.Policy.DomainRules {
		info.Resources = append(info.Resources, Resource{Address: r.Domain, Protocol: r.Proto, ApplicationID: r.AppID, GatewayGroup: cred.Policy.AppNodeGroups[r.AppID], PortMin: r.Port.Min, PortMax: r.Port.Max})
	}
	for _, r := range cred.Policy.SuffixRules {
		info.Resources = append(info.Resources, Resource{Address: "*" + r.Suffix, Protocol: r.Proto, ApplicationID: r.AppID, GatewayGroup: cred.Policy.AppNodeGroups[r.AppID], PortMin: r.Port.Min, PortMax: r.Port.Max})
	}
	c.status.State = Ready
	c.status.Session = &info
	c.status.LastError = nil
	c.publishLocked()
	return info, nil
}

// OpenTransport authenticates an L3 gateway without creating a system TUN or
// requesting access to any particular resource. Embedders can call it before
// advertising a connected packet-facing session.
func (c *Runtime) OpenTransport(parent context.Context) (TransportInfo, error) {
	if c.isClosed() {
		return TransportInfo{}, ErrClosed
	}
	ctx, done := c.operation(parent)
	defer done()
	if err := c.prepare(ctx); err != nil {
		return TransportInfo{}, err
	}
	t, err := c.manager.Tunnel(ctx)
	if err != nil {
		return TransportInfo{}, err
	}
	ip := t.VIP().To4()
	if ip == nil {
		return TransportInfo{}, errors.New("gateway did not assign an IPv4 virtual address")
	}
	return TransportInfo{Generation: c.currentGeneration(), Gateway: t.Addr(), VirtualIPv4: ip.String()}, nil
}

func (c *Runtime) DialContext(parent context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "udp" && network != "udp4" {
		return nil, auth.ErrUnsupported
	}
	protocol := strings.TrimSuffix(network, "4")
	host, p, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.New("target must include port")
	}
	port, err := strconv.Atoi(p)
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("invalid target port")
	}
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return nil, ErrClosed
	}
	ctx, done := c.operation(parent)
	defer done()
	if err := c.prepare(ctx); err != nil {
		return nil, err
	}
	resolve := c.resolver.Resolve
	if protocol == "udp" {
		resolve = c.resolver.ResolveUDP
	}
	target, err := resolve(ctx, host, port)
	if err != nil {
		return nil, err
	}
	return c.dialResolved(ctx, target, port, protocol)
}

// RoutePlan is an immutable decision under one credential generation.
type RoutePlan struct {
	Target       resolver.Resolution
	Port         int
	Network      string
	Gateways     []string
	GatewayGroup string
	Credential   *session.Credential
}

func (c *Runtime) dialResolved(ctx context.Context, target resolver.Resolution, port int, network string) (net.Conn, error) {
	cred, e := c.provider.Credential(ctx)
	if e != nil {
		return nil, e
	}
	if target.Generation != 0 && target.Generation != cred.Generation {
		return nil, &Error{Info: ErrorInfo{Kind: ErrorSessionReplaced, Message: "session replaced during resolution"}}
	}
	ctx = session.ExpectGeneration(ctx, cred.Generation)
	plan := RoutePlan{Target: target, Port: port, Network: network, Credential: cred, Gateways: cred.GatewaysForApp(target.AppID), GatewayGroup: cred.GatewayGroupForApp(target.AppID)}
	if target.AppID == "" {
		return nil, ErrDenied
	}
	if len(plan.Gateways) == 0 {
		return nil, tunnel.ErrNoLines
	}
	if c.checkTarget != nil {
		ip, e := netip.ParseAddr(target.IP)
		if e != nil {
			return nil, e
		}
		if e = c.checkTarget(ctx, Target{Generation: cred.Generation, Network: network, Host: target.Host, IP: ip.Unmap(), Port: uint16(port)}); e != nil {
			return nil, &Error{Info: ErrorInfo{Kind: ErrorCallerDenied, Op: "target", Message: "target rejected by caller"}, cause: sanitizedCause{e}}
		}
	}
	var conn net.Conn
	if network == "tcp" {
		conn, e = c.dialer.Dial(ctx, target.IP, port, target.AppID, target.Domain)
	} else {
		conn, e = c.dialer.DialUDP(ctx, target.IP, port, target.AppID, target.Domain)
	}
	if e != nil {
		return nil, e
	}
	if c.provider.Current() != cred {
		conn.Close()
		return nil, &Error{Info: ErrorInfo{Kind: ErrorSessionReplaced, Message: "session replaced during dial"}}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		conn.Close()
		return nil, ErrClosed
	}
	owned := &ownedConn{Conn: conn, owner: c, credential: cred, datagram: network == "udp"}
	c.conns[owned] = struct{}{}
	return owned, nil
}
func (c *Runtime) DialResolved(parent context.Context, t resolver.Resolution, p int, n string) (net.Conn, error) {
	ctx, done := c.operation(parent)
	defer done()
	if e := c.prepare(ctx); e != nil {
		return nil, e
	}
	return c.dialResolved(ctx, t, p, n)
}

func (c *Runtime) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *Runtime) LookupContextHost(parent context.Context, host string) ([]string, error) {
	if c.isClosed() {
		return nil, ErrClosed
	}
	ctx, done := c.operation(parent)
	defer done()
	if err := c.prepare(ctx); err != nil {
		return nil, err
	}
	return c.resolver.LookupHost(ctx, host)
}
func (c *Runtime) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.status.State = Closed
	c.publishLocked()
	c.cancel()
	conns := make([]*ownedConn, 0, len(c.conns))
	for conn := range c.conns {
		conns = append(conns, conn)
	}
	for id, ch := range c.subscribers {
		close(ch)
		delete(c.subscribers, id)
	}
	c.status.State = Closed
	c.mu.Unlock()
	for _, conn := range conns {
		conn.Close()
	}
	c.startOnce.Do(func() { close(c.tasksDone) })
	c.provider.Close()
	c.manager.Close()
	if c.transport != nil {
		c.transport.CloseIdleConnections()
	}
	go func() { <-c.tasksDone; c.ops.Wait(); close(c.shutdownDone) }()
	return nil
}

type ownedConn struct {
	net.Conn
	datagram   bool
	credential *session.Credential
	owner      *Runtime
	once       sync.Once
	err        error
}

func (c *ownedConn) Read(b []byte) (int, error) {
	if c.owner.provider.Current() != c.credential {
		c.Close()
		return 0, &Error{Info: ErrorInfo{Kind: ErrorSessionReplaced, Message: "session replaced"}}
	}
	return c.Conn.Read(b)
}
func (c *ownedConn) Write(b []byte) (int, error) {
	if c.owner.provider.Current() != c.credential {
		c.Close()
		return 0, &Error{Info: ErrorInfo{Kind: ErrorSessionReplaced, Message: "session replaced"}}
	}
	if c.datagram && len(b) > 1372 {
		return 0, ErrDatagramTooLarge
	}
	return c.Conn.Write(b)
}
func (c *ownedConn) Close() error {
	c.once.Do(func() { c.err = c.Conn.Close(); c.owner.mu.Lock(); delete(c.owner.conns, c); c.owner.mu.Unlock() })
	return c.err
}
func (c *ownedConn) CloseWrite() error {
	if w, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return w.CloseWrite()
	}
	return errors.New("half-close unavailable")
}
