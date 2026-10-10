package session

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestRestoreJoinerSurvivesLeaderCancellation(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "deadline"}[deadline], func(t *testing.T) {
			entered := make(chan struct{})
			var probes, logins atomic.Int32
			p := newRestoreFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/passport/v1/user/onlineInfo" && probes.Add(1) == 1 {
					close(entered)
					<-r.Context().Done()
					return
				}
				restoreHandler(w, r)
			})
			p.Authenticate = func(ctx context.Context, _ *http.Client) (string, error) {
				logins.Add(1)
				return "", ctx.Err()
			}
			var ctx context.Context
			var cancel context.CancelFunc
			if deadline {
				ctx, cancel = context.WithTimeout(context.Background(), 150*time.Millisecond)
			} else {
				ctx, cancel = context.WithCancel(context.Background())
			}
			defer cancel()
			first := make(chan error, 1)
			go func() { _, err := p.Credential(ctx); first <- err }()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("restore did not start")
			}
			secondCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			second := make(chan error, 1)
			joined := signalJoin(secondCtx)
			go func() {
				cred, err := p.Credential(joined)
				if err == nil && (cred == nil || cred.SID == "") {
					err = errors.New("restore returned no credential")
				}
				second <- err
			}()
			waitForJoiner(t, joined)
			if !deadline {
				cancel()
			}
			if err := <-first; !errors.Is(err, ctx.Err()) {
				t.Fatalf("canceled leader: %v", err)
			}
			if err := <-second; err != nil {
				t.Fatalf("live restore waiter: %v", err)
			}
			if logins.Load() != 0 {
				t.Fatal("canceled restore attempted full login")
			}
		})
	}
}

func TestCredentialJoinerDoesNotRetryIndependentTimeout(t *testing.T) {
	p := failingProvider(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	var logins atomic.Int32
	p.Authenticate = func(ctx context.Context, _ *http.Client) (string, error) {
		if logins.Add(1) == 1 {
			close(entered)
			<-release
		}
		return "", context.DeadlineExceeded
	}
	first := make(chan error, 1)
	go func() { _, err := p.Credential(context.Background()); first <- err }()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	second := make(chan error, 1)
	joined := signalJoin(ctx)
	go func() { _, err := p.Credential(joined); second <- err }()
	waitForJoiner(t, joined)
	close(release)
	for _, result := range []<-chan error{first, second} {
		if err := <-result; !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("intrinsic timeout: %v", err)
		}
	}
	if logins.Load() != 1 {
		t.Fatal("an intrinsic timeout triggered repeated login attempts")
	}
}
