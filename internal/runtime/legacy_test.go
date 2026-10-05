package runtime

// These adapters migrate old regression fixtures to the new API; no legacy engine is used.
import (
	"context"
	"crypto/tls"
	"encoding/json"
	"github.com/ShanghaitechGeekPie/geektrust/auth"
	"github.com/ShanghaitechGeekPie/geektrust/deployment"
	"github.com/ShanghaitechGeekPie/geektrust/internal/settings"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
)

type BlobStore interface {
	Load(context.Context) ([]byte, error)
	Save(context.Context, []byte) error
}
type AuthenticatorFunc func(context.Context, *http.Client) (string, error)

func (f AuthenticatorFunc) Authenticate(c context.Context, h *http.Client) (string, error) {
	return f(c, h)
}

type legacyIdentity struct{ f AuthenticatorFunc }

func (l legacyIdentity) Info(context.Context) (auth.IdentityInfo, error) {
	return auth.IdentityInfo{Issuer: "fixture", Subject: "fixture", Kind: "fixture"}, nil
}
func (l legacyIdentity) Authenticate(c context.Context, h *http.Client, _ auth.IdentityRequest) error {
	if l.f == nil {
		return nil
	}
	_, e := l.f(c, h)
	return e
}

type legacyOptions struct {
	CheckTarget                                    func(netip.Addr) error
	Compatibility                                  settings.Compatibility
	Gateways, DNS                                  []string
	ControllerURL, DeviceID, Platform, LoginDomain string
	ClientMode                                     bool
	Authenticator                                  AuthenticatorFunc
	ChallengeHandler                               auth.Handler
	SessionStore                                   BlobStore
	Transport                                      http.RoundTripper
	DialContext                                    func(context.Context, string, string) (net.Conn, error)
	DisableSystemResolver                          bool
	GatewayTLSConfig                               *tls.Config
	GatewayTrustStore                              interface {
		LoadPin(context.Context, string) ([]byte, error)
		SavePin(context.Context, string, []byte) error
	}
	Logger *slog.Logger
}
type fixtureSession struct{ old BlobStore }

func (f fixtureSession) Load(ctx context.Context, s SessionScope) ([]byte, error) {
	b, e := f.old.Load(ctx)
	if e != nil || len(b) == 0 {
		return b, e
	}
	var v map[string]any
	if e = json.Unmarshal(b, &v); e != nil {
		return nil, e
	}
	v["version"] = 1
	v["controller_url"] = s.ControllerURL
	v["identity_issuer"] = s.IdentityIssuer
	v["identity_subject"] = s.IdentitySubject
	v["identity_kind"] = s.IdentityKind
	v["login_domain"] = s.LoginDomain
	return json.Marshal(v)
}
func (f fixtureSession) Save(c context.Context, _ SessionScope, b []byte) error {
	return f.old.Save(c, b)
}
func (f fixtureSession) Delete(context.Context, SessionScope) error { return nil }

type legacyPins struct {
	old interface {
		LoadPin(context.Context, string) ([]byte, error)
		SavePin(context.Context, string, []byte) error
	}
}

func (p legacyPins) CheckOrEnroll(c context.Context, i GatewayIdentity, b [32]byte) (bool, error) {
	v, e := p.old.LoadPin(c, i.Address)
	if e != nil {
		return false, e
	}
	if len(v) == 0 {
		return true, p.old.SavePin(c, i.Address, b[:])
	}
	return string(v) == string(b[:]), nil
}
func newLegacy(o legacyOptions) (*Runtime, error) {
	opts := Options{ControllerURL: o.ControllerURL, DeviceID: o.DeviceID, Logger: o.Logger, Auth: AuthOptions{Identity: legacyIdentity{o.Authenticator}, LoginDomain: o.LoginDomain, OnChallenge: o.ChallengeHandler}, Deployment: deployment.Options{Profile: deployment.Generic, Protocol: deployment.ProtocolOptions{ControllerPlatform: o.Platform}, Fallbacks: &deployment.Fallbacks{ApplicationID: o.Compatibility.FallbackAppID, Gateways: append([]string(nil), o.Compatibility.FallbackGateways...), MissingGatewayGroup: o.Compatibility.MissingGatewayGroupFallback, StreamToL3: o.Compatibility.TCPToL3Fallback}}, Network: NetworkOptions{ControlTransport: o.Transport, DialContext: o.DialContext, GatewayTLS: GatewayTLSOptions{Config: o.GatewayTLSConfig}}}
	if o.ClientMode {
		opts.Auth.Mode = DesktopMode
	}
	if o.SessionStore != nil {
		opts.SessionStore = fixtureSession{o.SessionStore}
	}
	if o.GatewayTrustStore != nil {
		opts.Network.GatewayTLS.Mode = VerifyCAOrTOFU
		opts.Network.GatewayTLS.PinStore = legacyPins{o.GatewayTrustStore}
	}
	if o.Compatibility.GatewayServerName != "" {
		if opts.Network.GatewayTLS.Config == nil {
			opts.Network.GatewayTLS.Config = &tls.Config{}
		} else {
			opts.Network.GatewayTLS.Config = opts.Network.GatewayTLS.Config.Clone()
		}
		opts.Network.GatewayTLS.Config.ServerName = o.Compatibility.GatewayServerName
	}
	if o.CheckTarget != nil {
		opts.CheckTarget = func(_ context.Context, t Target) error { return o.CheckTarget(t.IP) }
	}
	if p := o.Compatibility.ProcessIdentity; p != nil {
		opts.Deployment.Protocol.Process = &deployment.ProcessMetadata{Name: p.Name, Platform: p.Platform, Path: p.Path}
	}
	for _, s := range o.DNS {
		a, e := netip.ParseAddr(s)
		if e != nil {
			return nil, e
		}
		opts.DNS.Servers = append(opts.DNS.Servers, a)
	}
	if len(o.Gateways) > 0 {
		opts.Deployment.Fallbacks.Gateways = append([]string(nil), o.Gateways...)
	}
	c, e := New(opts)
	if e == nil {

	}
	return c, e
}
