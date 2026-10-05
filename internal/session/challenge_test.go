package session

import (
	"context"
	"errors"
	"github.com/ShanghaitechGeekPie/geektrust/auth"
	"github.com/ShanghaitechGeekPie/geektrust/internal/sdpc"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestChallengeResendLifecycleAndSilentLogin(t *testing.T) {
	var sends atomic.Int32
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("action") == "sendsms" {
			sends.Add(1)
			io.WriteString(w, `{"code":0,"data":{}}`)
		} else {
			io.WriteString(w, `{"code":0,"data":{"sidTicket":"fixture"}}`)
		}
	}))
	defer controller.Close()
	var old func(context.Context) (auth.ChallengeInfo, error)
	p := &Provider{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), ChallengeHandler: func(ctx context.Context, c auth.Challenge) (string, error) {
		old = c.Resend
		if _, e := c.Resend(ctx); e != nil {
			t.Fatal(e)
		}
		return "123456", nil
	}}
	sc := sdpc.NewClient(controller.URL, "Mac", "id", controller.Client())
	ticket, e := p.smsFlow(context.Background(), sc)
	if e != nil || ticket != "fixture" || sends.Load() != 2 {
		t.Fatalf("SMS round trip: %v", e)
	}
	if _, e = old(context.Background()); !errors.Is(e, auth.ErrChallengeClosed) {
		t.Fatal("old resend callback remained usable")
	}
	if _, e = p.smsFlow(WithInteraction(context.Background(), false), sc); !errors.Is(e, auth.ErrInteractionRequired) || sends.Load() != 2 {
		t.Fatal("silent operation sent SMS")
	}
}
