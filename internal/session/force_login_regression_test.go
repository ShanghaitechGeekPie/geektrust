package session

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestCancelledForceLoginKeepsCurrentSession(t *testing.T) {
	p := failingProvider(t)
	current := &Credential{SID: "existing"}
	p.cur = current
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.ForceLogin(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled force login = %v", err)
	}
	if p.Current() != current {
		t.Fatal("a cancelled operation invalidated the current session")
	}
}

func TestConcurrentForceLoginSharesAuthentication(t *testing.T) {
	p := failingProvider(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	rejected := errors.New("fixture authentication rejected")
	p.Authenticate = func(context.Context, *http.Client) (string, error) {
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-release
		return "", rejected
	}
	first, second := make(chan error, 1), make(chan error, 1)
	go func() { _, err := p.ForceLogin(context.Background()); first <- err }()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	joined := signalJoin(ctx)
	go func() { _, err := p.ForceLogin(joined); second <- err }()
	waitForJoiner(t, joined)
	close(release)
	for _, result := range []<-chan error{first, second} {
		if err := <-result; !errors.Is(err, rejected) {
			t.Fatalf("force login result = %v", err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("concurrent force login made %d authentication attempts, want 1", calls.Load())
	}
}

func TestForceLoginWaitsForRestoreThenAuthenticates(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	p := newRestoreFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/passport/v1/user/onlineInfo" {
			close(entered)
			<-release
		}
		restoreHandler(w, r)
	})
	rejected := errors.New("forced authentication reached")
	p.Authenticate = func(context.Context, *http.Client) (string, error) { return "", rejected }
	ordinary := make(chan error, 1)
	go func() { _, err := p.Credential(context.Background()); ordinary <- err }()
	<-entered
	forced := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	joined := signalJoin(ctx)
	go func() { _, err := p.ForceLogin(joined); forced <- err }()
	waitForJoiner(t, joined)
	close(release)
	if err := <-ordinary; err != nil {
		t.Fatal(err)
	}
	if err := <-forced; !errors.Is(err, rejected) {
		t.Fatalf("forced login reused a restore: %v", err)
	}
}

func TestForcedJoinerRetriesCancelledLeader(t *testing.T) {
	p := failingProvider(t)
	entered := make(chan struct{})
	var calls atomic.Int32
	rejected := errors.New("live caller authenticated")
	p.Authenticate = func(ctx context.Context, _ *http.Client) (string, error) {
		if calls.Add(1) == 1 {
			close(entered)
			<-ctx.Done()
			return "", ctx.Err()
		}
		return "", rejected
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first, second := make(chan error, 1), make(chan error, 1)
	go func() { _, err := p.ForceLogin(ctx); first <- err }()
	<-entered
	live, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	joined := signalJoin(live)
	go func() { _, err := p.ForceLogin(joined); second <- err }()
	waitForJoiner(t, joined)
	cancel()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatalf("leader = %v", err)
	}
	if err := <-second; !errors.Is(err, rejected) {
		t.Fatalf("live joiner = %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("authentication attempts = %d", calls.Load())
	}
}
