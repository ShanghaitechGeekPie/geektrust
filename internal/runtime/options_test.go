package runtime

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/ShanghaitechGeekPie/geektrust/auth"
	"github.com/ShanghaitechGeekPie/geektrust/compatibility"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

type controllerTransport func(*http.Request) (*http.Response, error)

func (f controllerTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type fixtureTransport struct{}

func (fixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	body := `{"code":0,"data":{}}`
	switch r.URL.Path {
	case "/passport/v1/user/onlineInfo":
		body = `{"code":0,"data":{"isOnline":true}}`
	case "/controller/v1/user/clientResource":
	default:
		return nil, errors.New("unexpected controller request")
	}
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
}

type identityFunc func(context.Context, *http.Client, auth.IdentityRequest) error

func (f identityFunc) Info(context.Context) (auth.IdentityInfo, error) {
	return auth.IdentityInfo{Issuer: "fixture", Subject: "account", Kind: "passkey"}, nil
}
func (f identityFunc) Authenticate(c context.Context, h *http.Client, r auth.IdentityRequest) error {
	return f(c, h, r)
}

func TestCustomDefaultHTTPTransportCanRestoreSession(t *testing.T) {
	previous := http.DefaultTransport
	http.DefaultTransport = fixtureTransport{}
	defer func() { http.DefaultTransport = previous }()
	opts := contractOptions(&contractIdentity{subject: "account"}, &contractStore{state: validState()})
	opts.Network.ControlTransport = nil
	c, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestOptionsRejectIPv6TunnelDNS(t *testing.T) {
	opts := contractOptions(&contractIdentity{subject: "account"}, &contractStore{})
	opts.DNS.Servers = []netip.Addr{netip.MustParseAddr("2001:db8::53")}
	if c, err := New(opts); err == nil {
		c.Close()
		t.Fatal("IPv6-only tunnel DNS accepted by the IPv4 data plane")
	}
}

func TestOptionsCopiedAndProfileDefaults(t *testing.T) {
	s := validState()
	s.LoginDomain = "custom-domain"
	o := contractOptions(&contractIdentity{subject: "account"}, &contractStore{state: s})
	o.Auth.LoginDomain = "custom-domain"
	o.Compatibility.Fallbacks.ApplicationID = "custom-app"
	o.Compatibility.Fallbacks.Gateways = []string{"configured.example:441"}
	o.DNS.Servers = []netip.Addr{netip.MustParseAddr("10.0.0.53")}
	template := &tls.Config{ServerName: "gateway.example"}
	o.Network.GatewayTLS.Config = template
	c, e := New(o)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	o.Compatibility.Fallbacks.Gateways[0] = "mutated.example:441"
	template.ServerName = "mutated"
	info, e := c.Connect(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if info.Gateways[0] != "configured.example:441" || info.DNS[0] != "10.0.0.53" {
		t.Fatal("caller mutated active routing")
	}
	target, e := c.resolver.Resolve(context.Background(), "192.0.2.1", 443)
	if e != nil || target.AppID != "custom-app" {
		t.Fatal("application fallback lost")
	}
	_, sc := c.provider.ActiveSession()
	if c.manager.GatewayTLSConfig.ServerName != "gateway.example" || sc.LoginDomain != "custom-domain" {
		t.Fatal("TLS/login settings lost")
	}
}
func TestAuthenticationUsesCallerDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	want, _ := ctx.Deadline()
	called := false
	o := contractOptions(&contractIdentity{subject: "account"}, &contractStore{})
	o.SessionStore = nil
	o.Auth.Identity = identityFunc(func(ctx context.Context, _ *http.Client, r auth.IdentityRequest) error {
		called = true
		got, _ := ctx.Deadline()
		if got != want || !r.AllowInteraction {
			t.Error("caller authentication context changed")
		}
		return errors.New("fixture stop")
	})
	c, e := New(o)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if _, e = c.Connect(ctx); e == nil || !called {
		t.Fatal("real authentication was not called")
	}
}
func TestCacheCannotRestoreRemovedFallbacks(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		state := validState()
		state.Gateways = []string{"stale.example:441"}
		o := contractOptions(&contractIdentity{subject: "account"}, &contractStore{state: state})
		if !enabled {
			o.Compatibility.Fallbacks = &compatibility.Fallbacks{}
		}
		c, e := New(o)
		if e != nil {
			t.Fatal(e)
		}
		_, e = c.Connect(context.Background())
		if enabled && e != nil {
			t.Fatal(e)
		}
		if !enabled && e == nil {
			t.Fatal("cache revived a removed gateway fallback")
		}
		c.Close()
	}
}
