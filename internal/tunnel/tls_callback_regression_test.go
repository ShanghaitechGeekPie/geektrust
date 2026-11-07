package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCAOrTOFUCallbacksReceiveVerifiedChains(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	addr := strings.TrimPrefix(server.URL, "https://")
	for _, kind := range []string{"peer", "connection"} {
		t.Run(kind, func(t *testing.T) {
			config := &tls.Config{RootCAs: roots}
			called := false
			if kind == "peer" {
				config.VerifyPeerCertificate = func(_ [][]byte, chains [][]*x509.Certificate) error {
					called = true
					if len(chains) == 0 {
						return errors.New("missing verified certificate chain")
					}
					return nil
				}
			} else {
				config.VerifyConnection = func(state tls.ConnectionState) error {
					called = true
					if len(state.VerifiedChains) == 0 {
						return errors.New("missing verified certificate chain")
					}
					return nil
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			pins := &testPinStore{pins: map[string][]byte{}}
			conn, err := probeGatewayTLSWithDialer(ctx, addr, nil, config, pins)
			if err != nil {
				t.Fatal(err)
			}
			conn.Close()
			if !called {
				t.Fatal("custom certificate check was skipped")
			}
			if len(pins.pins) != 0 {
				t.Fatal("CA-verified connection should not enroll a fallback pin")
			}
		})
	}
}

func TestCallbackRejectionDoesNotEnrollGatewayPin(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	rejected := errors.New("caller rejected certificate")
	for _, skip := range []bool{false, true} {
		config := &tls.Config{InsecureSkipVerify: skip, VerifyConnection: func(tls.ConnectionState) error { return rejected }}
		pins := &testPinStore{pins: map[string][]byte{}}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		conn, err := probeGatewayTLSWithDialer(ctx, strings.TrimPrefix(server.URL, "https://"), nil, config, pins)
		cancel()
		if err == nil {
			conn.Close()
			t.Fatal("caller rejection was ignored")
		} else if !errors.Is(err, rejected) {
			t.Fatalf("callback error = %v", err)
		}
		if len(pins.pins) != 0 {
			t.Fatal("a caller-rejected certificate was enrolled")
		}
	}
}

func TestCAOrTOFUResumptionKeepsCallbackSemantics(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.TLS = &tls.Config{MaxVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	peerCalls, connectionCalls := 0, 0
	resumed := false
	config := &tls.Config{RootCAs: roots, ClientSessionCache: tls.NewLRUClientSessionCache(1),
		VerifyPeerCertificate: func(_ [][]byte, chains [][]*x509.Certificate) error {
			peerCalls++
			if len(chains) == 0 {
				return errors.New("missing verified chain")
			}
			return nil
		},
		VerifyConnection: func(state tls.ConnectionState) error {
			connectionCalls++
			resumed = state.DidResume
			if len(state.VerifiedChains) == 0 {
				return errors.New("missing verified chain")
			}
			return nil
		},
	}
	pins := &testPinStore{pins: map[string][]byte{}}
	for range 2 {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		conn, err := probeGatewayTLSWithDialer(ctx, strings.TrimPrefix(server.URL, "https://"), nil, config, pins)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		conn.Close()
	}
	if !resumed || peerCalls != 1 || connectionCalls != 2 {
		t.Fatalf("resumed=%v, peer calls=%d, connection calls=%d", resumed, peerCalls, connectionCalls)
	}
}

func TestCAOrTOFUHonorsConfiguredClock(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	future := server.Certificate().NotAfter.Add(time.Hour)
	for _, tc := range []struct {
		name       string
		tofu, skip bool
	}{
		{"CA", false, false},
		{"CA/skip", false, true},
		{"CA-or-TOFU", true, false},
		{"CA-or-TOFU/skip", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := &tls.Config{RootCAs: roots, Time: func() time.Time { return future }, InsecureSkipVerify: tc.skip}
			pins := &testPinStore{pins: map[string][]byte{}}
			var trust GatewayTrustStore
			if tc.tofu {
				trust = pins
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, err := probeGatewayTLSWithDialer(ctx, strings.TrimPrefix(server.URL, "https://"), nil, config, trust)
			if conn != nil {
				conn.Close()
			}
			if tc.skip {
				if err != nil {
					t.Fatalf("explicit certificate verification bypass failed: %v", err)
				}
			} else {
				var invalid x509.CertificateInvalidError
				if !errors.As(err, &invalid) || invalid.Reason != x509.Expired {
					t.Fatalf("expected expired certificate rejection, got %v", err)
				}
			}
			if len(pins.pins) != 0 {
				t.Fatal("expired certificate enrolled a fallback pin")
			}
		})
	}
}
