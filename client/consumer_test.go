package client_test

import (
	"context"
	"github.com/ShanghaitechGeekPie/geektrust/auth"
	"github.com/ShanghaitechGeekPie/geektrust/client"
	"net/http"
	"testing"
)

type identity struct{}

func (identity) Info(context.Context) (auth.IdentityInfo, error) {
	return auth.IdentityInfo{Issuer: "test", Subject: "test", Kind: "test"}, nil
}
func (identity) Authenticate(context.Context, *http.Client, auth.IdentityRequest) error { return nil }
func TestPublicClientConstructionAndClose(t *testing.T) {
	c, e := client.New(client.Options{ControllerURL: "https://controller.example", DeviceID: "0123456789ABCDEF0123456789ABCDEF", Auth: client.AuthOptions{Identity: identity{}}})
	if e != nil {
		t.Fatal(e)
	}
	if c.Status().State != client.Idle {
		t.Fatal("constructor started authentication")
	}
	if e = c.Shutdown(context.Background()); e != nil {
		t.Fatal(e)
	}
	if client.ImplementedCapabilities().IPv6Targets {
		t.Fatal("unsupported IPv6 targets advertised")
	}
}
