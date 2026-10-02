package client

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/ShanghaitechGeekPie/geektrust/auth"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ShanghaitechGeekPie/geektrust/deployment"
	"github.com/ShanghaitechGeekPie/geektrust/internal/config"
)

type compatibilityStore string

func (s compatibilityStore) Load(context.Context) ([]byte, error) { return []byte(s), nil }
func (s compatibilityStore) Save(context.Context, []byte) error   { return nil }

type compatibilityTransport struct{}

func (compatibilityTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	body := `{"code":0,"data":{}}`
	switch r.URL.Path {
	case "/passport/v1/user/onlineInfo":
		body = `{"code":0,"data":{"isOnline":true}}`
	case "/controller/v1/user/clientResource":
	default:
		return nil, errors.New("unexpected controller request")
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
}

func TestExplicitCompatibilityOptions(t *testing.T) {
	template := &tls.Config{}
	options := Options{
		Compatibility: deployment.Compatibility{FallbackAppID: "custom-app", GatewayServerName: "gateway.example"},
		LoginDomain:   "custom-domain",
		ControllerURL: config.DefaultBaseURL,
		DeviceID:      "0123456789ABCDEF0123456789ABCDEF",
		Gateways:      []string{"override:441"}, DNS: []string{"10.0.0.53"},
		GatewayTLSConfig: template, Transport: compatibilityTransport{},
		SessionStore:  compatibilityStore(`{"sid":"synthetic-session","device_id":"0123456789ABCDEF0123456789ABCDEF","client_type":"browser","cookies":[{"name":"sid","value":"synthetic-session"}]}`),
		Authenticator: AuthenticatorFunc(func(context.Context, *http.Client) (string, error) { return "", errors.New("unexpected full login") }),
	}
	c, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	options.Gateways[0] = "mutated"
	info, err := c.Connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Gateways) != 1 || info.Gateways[0] != "override:441" || len(info.DNS) != 1 || info.DNS[0] != "10.0.0.53" {
		t.Fatal("configured routing overrides lost")
	}
	target, err := c.resolver.Resolve(context.Background(), "192.0.2.1", 443)
	if err != nil || target.AppID != "custom-app" {
		t.Fatal("legacy application fallback lost")
	}
	if c.provider.ActiveSDPC().LoginDomain != "custom-domain" {
		t.Fatal("legacy CAS domain lost")
	}
	if c.manager.GatewayTLSConfig.ServerName != "gateway.example" || template.ServerName != "" {
		t.Fatal("gateway certificate identity missing or caller TLS config mutated")
	}
}

func TestAuthenticationUsesCallerDeadline(t *testing.T) {
	parent, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	want, _ := parent.Deadline()
	called := false
	c, err := New(Options{ControllerURL: config.DefaultBaseURL, DeviceID: "0123456789ABCDEF0123456789ABCDEF", Authenticator: AuthenticatorFunc(func(ctx context.Context, _ *http.Client) (string, error) {
		called = true
		got, ok := ctx.Deadline()
		if !ok || !got.Equal(want) {
			t.Errorf("authentication deadline shortened: %v", got)
		}
		return "", errors.New("synthetic stop before network login")
	})})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Connect(parent); err == nil || !called {
		t.Fatal("authentication fixture not exercised")
	}
}

type controllerTransport func(*http.Request) (*http.Response, error)

func (f controllerTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestCustomControllerLogin(t *testing.T) {
	calls := 0
	transport := controllerTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/passport/v1/public/authConfig" {
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"code":0,"data":{"security":{"csrfToken":"synthetic"},"authServerInfoList":[{"authType":"auth/cas","loginDomain":"a"},{"authType":"auth/cas","loginDomain":"b"}]}}`))}, nil
		}
		return (compatibilityTransport{}).RoundTrip(r)
	})
	c, err := New(Options{
		ControllerURL: "https://controller.example", DeviceID: "0123456789ABCDEF0123456789ABCDEF",
		Transport: transport, Compatibility: deployment.Compatibility{FallbackGateways: []string{"gateway.example:441"}},
		ControllerLogin: func(ctx context.Context, httpClient *http.Client, request auth.ControllerRequest) error {
			calls++
			if request.URL != "https://controller.example" || request.LoginDomain != "" || request.CSRFToken != "synthetic" {
				t.Fatal("custom authentication received implicit CAS configuration")
			}
			origin, _ := url.Parse(request.URL)
			httpClient.Jar.SetCookies(origin, []*http.Cookie{{Name: "sid", Value: "synthetic"}})
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	info, err := c.Connect(context.Background())
	if err != nil || calls != 1 {
		t.Fatalf("custom login calls=%d err=%v", calls, err)
	}
	if !info.Implemented.IPv4ICMP || info.Implemented.IPv6Targets || len(info.Resources) != 0 {
		t.Fatal("implementation and authorization were conflated")
	}
}

func TestRestoredSessionUsesCurrentCompatibility(t *testing.T) {
	state := compatibilityStore(`{"sid":"synthetic","device_id":"0123456789ABCDEF0123456789ABCDEF","client_type":"browser","cookies":[{"name":"sid","value":"synthetic"}],"gateways":["stale.example:441"]}`)
	for _, enabled := range []bool{true, false} {
		options := Options{ControllerURL: config.DefaultBaseURL, DeviceID: "0123456789ABCDEF0123456789ABCDEF", Transport: compatibilityTransport{}, SessionStore: state,
			Authenticator: AuthenticatorFunc(func(context.Context, *http.Client) (string, error) { return "", errors.New("synthetic no fresh login") }),
		}
		if enabled {
			options.Compatibility = deployment.Compatibility{FallbackAppID: "app", FallbackGateways: []string{"configured.example:441"}, TCPToL3Fallback: true}
		}
		c, err := New(options)
		if err != nil {
			t.Fatal(err)
		}
		if enabled {
			options.Compatibility.FallbackGateways[0] = "mutated.example:441"
		}
		info, err := c.Connect(context.Background())
		if enabled {
			if err != nil || len(info.Gateways) != 1 || info.Gateways[0] != "configured.example:441" {
				t.Fatalf("configured fallback lost: %v", err)
			}
			cred, err := c.provider.Credential(context.Background())
			if err != nil || !cred.AllowTCPFallback || cred.MissingGatewayGroupFallback {
				t.Fatal("independent compatibility switches not preserved")
			}
		} else if err == nil {
			t.Fatal("cached gateways re-enabled a removed compatibility setting")
		}
		c.Close()
	}
}
