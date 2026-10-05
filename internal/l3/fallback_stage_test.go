package l3

import (
	"context"
	"github.com/ShanghaitechGeekPie/geektrust/internal/sdpc"
	"github.com/ShanghaitechGeekPie/geektrust/internal/session"
	"github.com/ShanghaitechGeekPie/geektrust/internal/tunnel"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type fallbackStageProvider struct{ cred *session.Credential }

func (p fallbackStageProvider) Credential(context.Context) (*session.Credential, error) {
	return p.cred, nil
}
func (p fallbackStageProvider) InvalidateIfCurrent(*session.Credential) bool { return false }
func TestTLSClosingDoesNotAttemptL3Fallback(t *testing.T) {
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	var calls atomic.Int32
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			calls.Add(1)
			c.Close()
		}
	}()
	addr := ln.Addr().String()
	p := fallbackStageProvider{&session.Credential{SID: "fixture", AppID: "app", DeviceID: "id", AllowTCPFallback: true, Gateways: []string{addr}, Policy: &sdpc.Resource{Gateways: []string{addr}}}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := tunnel.NewManager(p, logger)
	m.MaxAttempts = 1
	defer m.Close()
	d := &Dialer{Manager: m, Provider: p, Logger: logger}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, e = d.Dial(ctx, "192.0.2.1", 443, "app", ""); e == nil {
		t.Fatal("TLS close accepted")
	}
	if calls.Load() != 1 {
		t.Fatalf("TLS failure triggered another protocol attempt: %d", calls.Load())
	}
}
