package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"github.com/ShanghaitechGeekPie/geektrust/auth"
	"github.com/ShanghaitechGeekPie/geektrust/compatibility"
	"github.com/ShanghaitechGeekPie/geektrust/internal/config"
	"github.com/ShanghaitechGeekPie/geektrust/internal/runtime"
	"github.com/ShanghaitechGeekPie/geektrust/internal/session"
	"github.com/ShanghaitechGeekPie/geektrust/internal/storage"
	"log/slog"
	"net/netip"
	"os"
)

// Every command owns file paths and input; the same runtime owns all network work.
func commandClient(cfg *config.Config, logger *slog.Logger) (*runtime.Runtime, error) {
	if e := cfg.ValidateListeners(); e != nil {
		return nil, e
	}
	if e := cfg.EnsureDeviceID(); e != nil {
		return nil, e
	}
	identity, e := auth.NewPasskey(storage.CredentialFile{Path: cfg.Keystore, StrictPermissions: cfg.StrictPermissions})
	if e != nil {
		return nil, e
	}
	o := runtime.Options{ControllerURL: cfg.BaseURL, DeviceID: cfg.DeviceID, Logger: logger, Auth: runtime.AuthOptions{Identity: identity, LoginDomain: cfg.LoginDomain, OnChallenge: func(ctx context.Context, c auth.Challenge) (string, error) {
		if c.Info.Method != auth.SMS {
			return "", auth.ErrUnsupported
		}
		return smsPrompt(ctx)
	}}, Compatibility: compatibility.Options{Profile: cfg.Compatibility, Protocol: compatibility.ProtocolOptions{ControllerPlatform: cfg.Platform}, Fallbacks: &cfg.Fallbacks}, SessionStore: commandSessionStore{session.NewStore(cfg.StateFile, cfg.StrictPermissions)}}
	if cfg.ClientType == "client" {
		o.Auth.Mode = runtime.DesktopMode
	}
	if cfg.GatewayTLSName != "" {
		o.Network.GatewayTLS.Config = &tls.Config{ServerName: cfg.GatewayTLSName}
	}
	if cfg.CAFile != "" {
		b, e := os.ReadFile(cfg.CAFile)
		if e != nil {
			return nil, e
		}
		pool, e := x509.SystemCertPool()
		if e != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(b) {
			return nil, errors.New("invalid gateway CA file")
		}
		if o.Network.GatewayTLS.Config == nil {
			o.Network.GatewayTLS.Config = &tls.Config{}
		}
		o.Network.GatewayTLS.Config.RootCAs = pool
	}
	if cfg.Version == 2 {
		o.Network.AllowedGateways = cfg.Gateways
	}
	for _, s := range cfg.DNS {
		a, e := netip.ParseAddr(s)
		if e != nil {
			return nil, e
		}
		o.DNS.Servers = append(o.DNS.Servers, a)
	}
	c, e := runtime.New(o)
	if e != nil {
		return nil, e
	}
	c.ConfigureCommand(cfg.SessionOptions(), cfg.DNSStrategy)
	return c, nil
}

type commandSessionStore struct{ store *session.Store }

func (s commandSessionStore) Load(ctx context.Context, _ runtime.SessionScope) ([]byte, error) {
	return s.store.LoadBytes(ctx)
}
func (s commandSessionStore) Save(ctx context.Context, _ runtime.SessionScope, b []byte) error {
	return s.store.SaveBytes(ctx, b)
}
func (s commandSessionStore) Delete(ctx context.Context, _ runtime.SessionScope) error {
	return s.store.Delete(ctx)
}
