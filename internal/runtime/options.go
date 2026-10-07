package runtime

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/ShanghaitechGeekPie/geektrust/auth"
	"github.com/ShanghaitechGeekPie/geektrust/compatibility"
)

type Options struct {
	ControllerURL string
	DeviceID      string
	Compatibility compatibility.Options
	Auth          AuthOptions
	SessionStore  SessionStore
	Network       NetworkOptions
	DNS           DNSOptions
	CheckTarget   func(context.Context, Target) error
	Logger        *slog.Logger
}

type AuthOptions struct {
	Identity    auth.IdentityProvider
	OnChallenge auth.Handler
	Mode        SessionMode
	LoginDomain string
}

type SessionMode uint8

const (
	BrowserMode SessionMode = iota
	DesktopMode
)

type NetworkOptions struct {
	DialContext      func(context.Context, string, string) (net.Conn, error)
	ControlTransport http.RoundTripper
	GatewayTLS       GatewayTLSOptions
	AllowedGateways  []string
	DialTimeout      time.Duration
	HTTPTimeout      time.Duration
}

type GatewayTLSOptions struct {
	Config   *tls.Config
	Mode     GatewayTrustMode
	PinStore GatewayPinStore
}

type GatewayTrustMode uint8

const (
	VerifyCA GatewayTrustMode = iota
	VerifyCAOrTOFU
)

type GatewayIdentity struct {
	ControllerURL string
	Address       string
	ServerName    string
}

type GatewayPinStore interface {
	CheckOrEnroll(context.Context, GatewayIdentity, [32]byte) (bool, error)
}

type DNSOptions struct {
	Servers        []netip.Addr
	FallbackLookup func(context.Context, string) ([]netip.Addr, error)
}

type Target struct {
	Generation uint64
	Network    string
	Host       string
	IP         netip.Addr
	Port       uint16
	Purpose    TargetPurpose
}

type TargetPurpose uint8

const (
	ApplicationTarget TargetPurpose = iota
	DNSQueryTarget
)

type SessionScope struct {
	ControllerURL   string
	IdentityIssuer  string
	IdentitySubject string
	IdentityKind    string
	DeviceID        string
	Mode            SessionMode
	LoginDomain     string
}

type SessionStore interface {
	Load(context.Context, SessionScope) ([]byte, error)
	Save(context.Context, SessionScope, []byte) error
	Delete(context.Context, SessionScope) error
}
