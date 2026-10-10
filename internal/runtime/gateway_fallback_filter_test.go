package runtime

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
)

func TestAllowedGatewayCanSelectCompatibilityFallback(t *testing.T) {
	for _, filtered := range []bool{false, true} {
		name := "unfiltered"
		if filtered {
			name = "filtered"
		}
		t.Run(name, func(t *testing.T) {
			opts := contractOptions(&contractIdentity{subject: "account"}, &contractStore{state: validState()})
			if filtered {
				opts.Network.AllowedGateways = []string{"gateway.example:441"}
			}
			var dials atomic.Int32
			stop := errors.New("fixture gateway reached")
			opts.Network.DialContext = func(_ context.Context, network, address string) (net.Conn, error) {
				dials.Add(1)
				if network != "tcp" || address != "gateway.example:441" {
					t.Errorf("unexpected gateway dial: %s %s", network, address)
				}
				return nil, stop
			}
			c, err := New(opts)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if _, err := c.Connect(context.Background()); err != nil {
				t.Fatal(err)
			}
			_, err = c.DialContext(context.Background(), "tcp", "192.0.2.1:443")
			if !errors.Is(err, stop) || dials.Load() != 1 {
				t.Fatalf("fallback gateway not reached: dials=%d, error=%v", dials.Load(), err)
			}
		})
	}
}
