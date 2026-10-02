// Package client embeds aTrust authentication and transport without starting
// listeners, changing system networking, or depending on a configuration file.
package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
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
	"unicode"

	"github.com/ShanghaitechGeekPie/geektrust/auth"
	"github.com/ShanghaitechGeekPie/geektrust/deployment"
	"github.com/ShanghaitechGeekPie/geektrust/internal/config"
	"github.com/ShanghaitechGeekPie/geektrust/internal/idsauth"
	"github.com/ShanghaitechGeekPie/geektrust/internal/l3"
	"github.com/ShanghaitechGeekPie/geektrust/internal/resolver"
	"github.com/ShanghaitechGeekPie/geektrust/internal/session"
	"github.com/ShanghaitechGeekPie/geektrust/internal/tunnel"
)

// BlobStore is scoped to a single identity/deployment by the embedding application.
// Save must be atomic and durable. Implementations must protect the secret bytes.
type BlobStore interface {
	Load(context.Context) ([]byte, error)
	Save(context.Context, []byte) error
}

// GatewayTrustStore persists SHA-256 SPKI pins for private-CA gateways.
// An empty LoadPin result enrolls the first observed public key.
type GatewayTrustStore interface {
	LoadPin(context.Context, string) ([]byte, error)
	SavePin(context.Context, string, []byte) error
}
type Authenticator interface {
	Authenticate(context.Context, *http.Client) (string, error)
}
type AuthenticatorFunc func(context.Context, *http.Client) (string, error)

func (f AuthenticatorFunc) Authenticate(ctx context.Context, h *http.Client) (string, error) {
	return f(ctx, h)
}

// PasskeyAuthenticator supports ECNU and ShanghaiTech binary keystores.
// Use one instance/store owner per credential to serialize signature counters.
type PasskeyAuthenticator struct {
	Store BlobStore
	once  sync.Once
	gate  chan struct{}
}

func (p *PasskeyAuthenticator) Authenticate(ctx context.Context, h *http.Client) (string, error) {
	p.once.Do(func() { p.gate = make(chan struct{}, 1) })
	select {
	case p.gate <- struct{}{}:
		defer func() { <-p.gate }()
	case <-ctx.Done():
		return "", ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if p.Store == nil {
		return "", errors.New("credential store required")
	}
	b, err := p.Store.Load(ctx)
	if err != nil {
		return "", errors.New("cannot load credential")
	}
	k, err := idsauth.ParseKeystore(b, func(b []byte) error { return p.Store.Save(ctx, b) })
	if err != nil {
		return "", errors.New("invalid passkey credential")
	}
	if err = idsauth.NewClient(k, h).Login(ctx); err != nil {
		return "", err
	}
	return k.Username(), nil
}

type PasskeyInfo struct {
	Kind     string
	Username string
	Origin   string
}

// InspectPasskey validates a credential and exposes only non-secret metadata.
func InspectPasskey(b []byte) (PasskeyInfo, error) {
	k, err := idsauth.ParseKeystore(b, nil)
	if err != nil {
		return PasskeyInfo{}, errors.New("invalid passkey credential")
	}
	return PasskeyInfo{Kind: k.Kind(), Username: k.Username(), Origin: k.BaseURL()}, nil
}

// ValidatePasskey validates an imported credential without authenticating it.
func ValidatePasskey(b []byte) error {
	_, err := InspectPasskey(b)
	return err
}

type Options struct {
	// CheckTarget may reject a resolved IPv4 destination before transport opens.
	// It is called concurrently and cannot grant access outside controller policy.
	CheckTarget           func(netip.Addr) error
	Compatibility         deployment.Compatibility
	Gateways              []string
	DNS                   []string
	ControllerURL         string
	DeviceID              string
	Platform              string
	LoginDomain           string
	ClientMode            bool
	Authenticator         Authenticator
	ControllerLogin       auth.ControllerLogin
	ChallengeHandler      auth.Handler
	SessionStore          BlobStore
	Transport             http.RoundTripper
	DialContext           func(context.Context, string, string) (net.Conn, error)
	DisableSystemResolver bool
	GatewayTLSConfig      *tls.Config
	GatewayTrustStore     GatewayTrustStore
	Logger                *slog.Logger
}

type Capabilities struct{ IPv4TCP, IPv4UDP, IPv4ICMP, IPv6Targets, IPv6Gateway bool }
type Resource struct {
	Address, Protocol, ApplicationID, GatewayGroup string
	PortMin, PortMax                               int
}
type Info struct {
	Gateways, DNS []string
	Resources     []Resource
	// Implemented describes library support, not negotiated or authorized access.
	Implemented Capabilities
}
type TransportInfo struct {
	Gateway     string
	VirtualIPv4 string
}
type EventKind string

const (
	EventAuthenticating       EventKind = "authenticating"
	EventAuthenticated        EventKind = "authenticated"
	EventAuthenticationFailed EventKind = "authentication_failed"
	EventSessionInvalidated   EventKind = "session_invalidated"
)

type Event struct {
	Kind EventKind
	Time time.Time
}

var ErrClosed = errors.New("aTrust client closed")
var ErrDatagramTooLarge = errors.New("UDP datagram exceeds tunnel MTU")
var ErrDenied = errors.New("target is not authorized by controller policy")

type Client struct {
	checkTarget func(netip.Addr) error
	provider    *session.Provider
	manager     *tunnel.Manager
	dialer      *l3.Dialer
	resolver    *resolver.Resolver
	ctx         context.Context
	cancel      context.CancelFunc
	mu          sync.Mutex
	closed      bool
	conns       map[*ownedConn]struct{}
	transport   *http.Transport
	events      chan Event
}

func New(opts Options) (*Client, error) {
	u, err := url.Parse(opts.ControllerURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("controller must be an HTTPS origin")
	}
	if len(opts.DeviceID) != 32 || strings.Trim(opts.DeviceID, "0123456789ABCDEF") != "" {
		return nil, errors.New("persistent 32-character uppercase hexadecimal device ID required")
	}
	if opts.Authenticator == nil && opts.ControllerLogin == nil {
		return nil, errors.New("authenticator required")
	}
	if opts.Platform == "" {
		opts.Platform = "Mac"
	}
	if len(opts.Platform) > 64 || strings.IndexFunc(opts.Platform, unicode.IsControl) >= 0 {
		return nil, errors.New("platform must be at most 64 bytes without control characters")
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	mode := "browser"
	if opts.ClientMode {
		mode = "client"
	}
	cfg := &config.Config{BaseURL: strings.TrimRight(opts.ControllerURL, "/"), DeviceID: opts.DeviceID, Platform: opts.Platform, LoginDomain: opts.LoginDomain, ClientType: mode, Compatibility: opts.Compatibility.Clone(), Gateways: append([]string(nil), opts.Gateways...), DNS: append([]string(nil), opts.DNS...)}
	if err := cfg.Compatibility.Validate(); err != nil {
		return nil, err
	}
	p := session.NewProvider(cfg, opts.Logger, nil)
	if opts.Authenticator != nil {
		p.Authenticate = opts.Authenticator.Authenticate
	}
	p.ControllerLogin = opts.ControllerLogin
	p.ChallengeHandler = opts.ChallengeHandler
	p.Transport = opts.Transport
	var ownedTransport *http.Transport
	if p.Transport == nil {
		ownedTransport = http.DefaultTransport.(*http.Transport).Clone()
		if opts.DialContext != nil {
			ownedTransport.DialContext = opts.DialContext
		}
		p.Transport = ownedTransport
	}
	p.SetStore(&stateStore{store: opts.SessionStore})
	m := tunnel.NewManager(p, opts.Logger)
	m.MaxAttempts = 3
	m.DialContext = opts.DialContext
	m.GatewayTLSConfig = opts.GatewayTLSConfig
	if name := cfg.GatewayServerName(); name != "" {
		if m.GatewayTLSConfig == nil {
			m.GatewayTLSConfig = &tls.Config{ServerName: name}
		} else if m.GatewayTLSConfig.ServerName == "" {
			m.GatewayTLSConfig = m.GatewayTLSConfig.Clone()
			m.GatewayTLSConfig.ServerName = name
		}
	}
	m.GatewayTrustStore = opts.GatewayTrustStore
	d := &l3.Dialer{Manager: m, Provider: p, Logger: opts.Logger}
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{checkTarget: opts.CheckTarget, transport: ownedTransport, provider: p, manager: m, dialer: d, resolver: resolver.NewWithDialerOptions(p, d, opts.DialContext, opts.DisableSystemResolver), ctx: ctx, cancel: cancel, conns: make(map[*ownedConn]struct{}), events: make(chan Event, 16)}
	p.AddObserver(clientObserver{c})
	go p.CheckLoop(ctx, 5*time.Minute)
	return c, nil
}

func NewDeviceID() (string, error) { return config.GenerateDeviceID() }

// Authenticate forces a fresh login. Concurrent requests share the provider's
// refresh; the embedding application remains responsible for connection retry.
func (c *Client) Authenticate(parent context.Context) (Info, error) {
	if c.isClosed() {
		return Info{}, ErrClosed
	}
	ctx, done := c.withLifetime(parent)
	defer done()
	if _, err := c.provider.ForceLogin(ctx); err != nil {
		return Info{}, err
	}
	return c.Connect(ctx)
}
func (c *Client) withLifetime(parent context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(c.ctx, cancel)
	return ctx, func() { stop(); cancel() }
}

func (c *Client) operation(parent context.Context) (context.Context, func()) {
	ctx, release := c.withLifetime(parent)
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	return ctx, func() { cancel(); release() }
}

func (c *Client) Connect(parent context.Context) (Info, error) {
	if c.isClosed() {
		return Info{}, ErrClosed
	}
	ctx, done := c.withLifetime(parent)
	defer done()
	cred, err := c.provider.Credential(ctx)
	if err != nil {
		return Info{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return Info{}, ErrClosed
	}
	info := Info{Gateways: append([]string(nil), cred.Gateways...), DNS: append([]string(nil), cred.DNS...), Implemented: Capabilities{IPv4TCP: true, IPv4UDP: true, IPv4ICMP: true, IPv6Gateway: true}}
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
	return info, nil
}

// OpenTransport authenticates an L3 gateway without creating a system TUN or
// requesting access to any particular resource. Embedders can call it before
// advertising a connected packet-facing session.
func (c *Client) OpenTransport(parent context.Context) (TransportInfo, error) {
	if c.isClosed() {
		return TransportInfo{}, ErrClosed
	}
	ctx, done := c.operation(parent)
	defer done()
	t, err := c.manager.Tunnel(ctx)
	if err != nil {
		return TransportInfo{}, err
	}
	ip := t.VIP().To4()
	if ip == nil {
		return TransportInfo{}, errors.New("gateway did not assign an IPv4 virtual address")
	}
	return TransportInfo{Gateway: t.Addr(), VirtualIPv4: ip.String()}, nil
}

func (c *Client) DialContext(parent context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "udp" && network != "udp4" {
		return nil, errors.New("unsupported target network")
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
	resolve := c.resolver.Resolve
	if protocol == "udp" {
		resolve = c.resolver.ResolveUDP
	}
	target, err := resolve(ctx, host, port)
	if err != nil {
		return nil, err
	}
	if target.AppID == "" {
		return nil, ErrDenied
	}
	if c.checkTarget != nil {
		ip, err := netip.ParseAddr(target.IP)
		if err != nil {
			return nil, err
		}
		if err := c.checkTarget(ip.Unmap()); err != nil {
			return nil, err
		}
	}
	var conn net.Conn
	if protocol == "tcp" {
		conn, err = c.dialer.Dial(ctx, target.IP, port, target.AppID, target.Domain)
	} else {
		conn, err = c.dialer.DialUDP(ctx, target.IP, port, target.AppID, target.Domain)
	}
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		conn.Close()
		return nil, ErrClosed
	}
	owned := &ownedConn{Conn: conn, owner: c, datagram: protocol == "udp"}
	c.conns[owned] = struct{}{}
	return owned, nil
}

func (c *Client) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *Client) LookupContextHost(parent context.Context, host string) ([]string, error) {
	if c.isClosed() {
		return nil, ErrClosed
	}
	ctx, done := c.operation(parent)
	defer done()
	return c.resolver.LookupHost(ctx, host)
}
func (c *Client) Events() <-chan Event { return c.events }
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.cancel()
	conns := make([]*ownedConn, 0, len(c.conns))
	for conn := range c.conns {
		conns = append(conns, conn)
	}
	close(c.events)
	c.mu.Unlock()
	for _, conn := range conns {
		conn.Close()
	}
	c.provider.CloseObservers()
	c.manager.Close()
	if c.transport != nil {
		c.transport.CloseIdleConnections()
	}
	return nil
}

type ownedConn struct {
	net.Conn
	datagram bool
	owner    *Client
	once     sync.Once
	err      error
}

func (c *ownedConn) Write(b []byte) (int, error) {
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

type stateStore struct{ store BlobStore }

func (s *stateStore) Load(parent context.Context) (*session.State, error) {
	if s.store == nil {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	b, err := s.store.Load(ctx)
	if err != nil || len(b) == 0 {
		return nil, err
	}
	var st session.State
	if json.Unmarshal(b, &st) != nil {
		return nil, errors.New("invalid stored session")
	}
	return &st, nil
}
func (s *stateStore) Save(parent context.Context, st *session.State) error {
	if s.store == nil {
		return nil
	}
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	return s.store.Save(ctx, b)
}

type clientObserver struct{ client *Client }

func (o clientObserver) OnSessionEvent(event session.Event) {
	kind := map[session.EventKind]EventKind{
		session.EventLoginStart:   EventAuthenticating,
		session.EventLoginSuccess: EventAuthenticated,
		session.EventRestoreOK:    EventAuthenticated,
		session.EventLoginFailed:  EventAuthenticationFailed,
		session.EventInvalidated:  EventSessionInvalidated,
	}[event.Kind]
	if kind == "" {
		return
	}
	c := o.client
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	select {
	case c.events <- Event{Kind: kind, Time: event.Time}:
	default:
	}
}
