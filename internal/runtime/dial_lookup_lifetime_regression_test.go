package runtime

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/ShanghaitechGeekPie/geektrust/internal/session"
)

func TestTargetResolutionCancelsWithSession(t *testing.T) {
	operations := map[string]func(*Runtime, context.Context) error{
		"tcp": func(c *Runtime, ctx context.Context) error {
			conn, err := c.DialContext(ctx, "tcp", "lookup.example.invalid:443")
			if conn != nil {
				conn.Close()
			}
			return err
		},
		"udp": func(c *Runtime, ctx context.Context) error {
			conn, err := c.DialContext(ctx, "udp", "lookup.example.invalid:443")
			if conn != nil {
				conn.Close()
			}
			return err
		},
		"proxy_tcp": func(c *Runtime, ctx context.Context) error {
			_, err := c.Resolve(ctx, "lookup.example.invalid", 443)
			return err
		},
		"proxy_udp": func(c *Runtime, ctx context.Context) error {
			_, err := c.ResolveUDP(ctx, "lookup.example.invalid", 443)
			return err
		},
	}
	for name, operation := range operations {
		t.Run(name, func(t *testing.T) {
			entered := make(chan struct{})
			opts := contractOptions(&contractIdentity{subject: "account"}, &contractStore{state: validState()})
			opts.DNS.Servers = []netip.Addr{}
			opts.DNS.FallbackLookup = func(ctx context.Context, _ string) ([]netip.Addr, error) {
				close(entered)
				<-ctx.Done()
				return nil, ctx.Err()
			}
			c, err := New(opts)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if _, err := c.Connect(context.Background()); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- operation(c, ctx) }()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("resolution did not start")
			}
			c.provider.Invalidate()
			select {
			case err := <-result:
				if !errors.Is(err, session.ErrSessionReplaced) {
					t.Fatalf("result = %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("resolution continued after its session was invalidated")
			}
		})
	}
}
