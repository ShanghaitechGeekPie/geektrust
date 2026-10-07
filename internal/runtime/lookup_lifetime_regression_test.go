package runtime

import (
	"context"
	"errors"
	"github.com/ShanghaitechGeekPie/geektrust/internal/session"
	"net/netip"
	"testing"
	"time"
)

func TestLookupCancelsWhenItsSessionIsInvalidated(t *testing.T) {
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
	go func() { _, err := c.LookupContextHost(ctx, "lookup.example.invalid"); result <- err }()
	<-entered
	c.provider.Invalidate()
	select {
	case err := <-result:
		if !errors.Is(err, session.ErrSessionReplaced) {
			t.Fatalf("lookup after invalidation = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("a lookup from the invalidated session remained active")
	}
}

func TestNewRejectsControllerEmptyQueryMarker(t *testing.T) {
	options := contractOptions(&contractIdentity{subject: "account"}, &contractStore{state: validState()})
	options.ControllerURL = "https://controller.example?"
	c, err := New(options)
	if err == nil {
		c.Close()
		t.Fatal("controller URL ending in a query marker was accepted")
	}
}
