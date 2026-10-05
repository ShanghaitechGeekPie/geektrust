// Package client is the public facade for the shared aTrust runtime.
package client

import (
	"context"
	"github.com/ShanghaitechGeekPie/geektrust/internal/runtime"
	"net"
)

type Client struct{ core *runtime.Runtime }

func New(o Options) (*Client, error) {
	r, e := runtime.New(o)
	if e != nil {
		return nil, runtime.ConfigError(e)
	}
	return &Client{core: r}, nil
}
func NewDeviceID() (string, error)          { return runtime.NewDeviceID() }
func ImplementedCapabilities() Capabilities { return runtime.ImplementedCapabilities() }

type Options = runtime.Options
type AuthOptions = runtime.AuthOptions
type SessionMode = runtime.SessionMode
type NetworkOptions = runtime.NetworkOptions
type GatewayTLSOptions = runtime.GatewayTLSOptions
type GatewayTrustMode = runtime.GatewayTrustMode
type GatewayIdentity = runtime.GatewayIdentity
type GatewayPinStore = runtime.GatewayPinStore
type DNSOptions = runtime.DNSOptions
type Target = runtime.Target
type TargetPurpose = runtime.TargetPurpose
type SessionScope = runtime.SessionScope
type SessionStore = runtime.SessionStore
type Capabilities = runtime.Capabilities
type Resource = runtime.Resource
type SessionInfo = runtime.SessionInfo
type TransportInfo = runtime.TransportInfo
type Event = runtime.Event
type Status = runtime.Status
type SessionState = runtime.SessionState
type Error = runtime.Error
type ErrorInfo = runtime.ErrorInfo
type ErrorKind = runtime.ErrorKind
type TrustedDevice = runtime.TrustedDevice
type TrustedDeviceList = runtime.TrustedDeviceList

const (
	BrowserMode                 = runtime.BrowserMode
	DesktopMode                 = runtime.DesktopMode
	VerifyCA                    = runtime.VerifyCA
	VerifyCAOrTOFU              = runtime.VerifyCAOrTOFU
	ApplicationTarget           = runtime.ApplicationTarget
	DNSQueryTarget              = runtime.DNSQueryTarget
	Idle                        = runtime.Idle
	Authenticating              = runtime.Authenticating
	Ready                       = runtime.Ready
	InteractionRequired         = runtime.InteractionRequired
	Failed                      = runtime.Failed
	Closed                      = runtime.Closed
	ErrorConfig                 = runtime.ErrorConfig
	ErrorInteractionRequired    = runtime.ErrorInteractionRequired
	ErrorIdentityChanged        = runtime.ErrorIdentityChanged
	ErrorAuthenticationRejected = runtime.ErrorAuthenticationRejected
	ErrorControllerDenied       = runtime.ErrorControllerDenied
	ErrorCallerDenied           = runtime.ErrorCallerDenied
	ErrorTLS                    = runtime.ErrorTLS
	ErrorDNS                    = runtime.ErrorDNS
	ErrorNetwork                = runtime.ErrorNetwork
	ErrorUnsupported            = runtime.ErrorUnsupported
	ErrorSessionReplaced        = runtime.ErrorSessionReplaced
	ErrorDatagramTooLarge       = runtime.ErrorDatagramTooLarge
	ErrorStorage                = runtime.ErrorStorage
	ErrorClosed                 = runtime.ErrorClosed
)

var (
	ErrClosed           = runtime.ErrClosed
	ErrDatagramTooLarge = runtime.ErrDatagramTooLarge
	ErrDenied           = runtime.ErrDenied
)

func (c *Client) Connect(ctx context.Context) (SessionInfo, error) {
	v, e := c.core.Connect(ctx)
	return v, runtime.PublicError("connect", e)
}
func (c *Client) Authenticate(ctx context.Context) (SessionInfo, error) {
	v, e := c.core.Authenticate(ctx)
	return v, runtime.PublicError("authenticate", e)
}
func (c *Client) OpenTransport(ctx context.Context) (TransportInfo, error) {
	v, e := c.core.OpenTransport(ctx)
	return v, runtime.PublicError("open_transport", e)
}
func (c *Client) DialContext(ctx context.Context, n, a string) (net.Conn, error) {
	v, e := c.core.DialContext(ctx, n, a)
	return v, runtime.PublicError("dial", e)
}
func (c *Client) LookupContextHost(ctx context.Context, h string) ([]string, error) {
	v, e := c.core.LookupContextHost(ctx, h)
	return v, runtime.PublicError("lookup", e)
}
func (c *Client) ExchangeICMPEcho(ctx context.Context, p []byte) ([]byte, error) {
	v, e := c.core.ExchangeICMPEcho(ctx, p)
	return v, runtime.PublicError("icmp", e)
}
func (c *Client) ForgetSession(ctx context.Context) error {
	return runtime.PublicError("forget_session", c.core.ForgetSession(ctx))
}
func (c *Client) Status() Status                             { return c.core.Status() }
func (c *Client) Subscribe(ctx context.Context) <-chan Event { return c.core.Subscribe(ctx) }
func (c *Client) Close() error                               { return c.core.Close() }
func (c *Client) Shutdown(ctx context.Context) error         { return c.core.Shutdown(ctx) }
func (c *Client) TrustedDevices(ctx context.Context) (TrustedDeviceList, error) {
	v, e := c.core.TrustedDevices(ctx)
	return v, runtime.PublicError("trusted_devices", e)
}
func (c *Client) TrustCurrentDevice(ctx context.Context) error {
	return runtime.PublicError("trust_device", c.core.TrustCurrentDevice(ctx))
}
func (c *Client) UntrustDevices(ctx context.Context, ids []string) error {
	return runtime.PublicError("untrust_devices", c.core.UntrustDevices(ctx, ids))
}
func (c *Client) LogoutDevice(ctx context.Context, id string) error {
	return runtime.PublicError("logout_device", c.core.LogoutDevice(ctx, id))
}
