package session

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ShanghaitechGeekPie/geektrust/auth"
	"github.com/ShanghaitechGeekPie/geektrust/internal/sdpc"
)

func TestMissingChallengeHandlerReturnsTypedError(t *testing.T) {
	p := &Provider{}
	_, err := p.smsFlow(context.Background(), nil)
	var required *auth.RequiredError
	if !errors.Is(err, auth.ErrInteractionRequired) || !errors.As(err, &required) || required.Challenge.Info.Method != auth.SMS {
		t.Fatalf("unexpected challenge error: %v", err)
	}
}

func TestCancelledChallengeDoesNotSubmitAnswer(t *testing.T) {
	var submissions atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("action") == "checkcode" {
			submissions.Add(1)
		}
		io.WriteString(w, `{"code":0,"data":{}}`)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	p := &Provider{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), ChallengeHandler: func(ctx context.Context, challenge auth.Challenge) (string, error) {
		deadline, ok := ctx.Deadline()
		if !ok || !deadline.Equal(challenge.Info.Deadline) || time.Until(deadline) > time.Minute {
			t.Fatal("challenge missing bounded lifetime")
		}
		cancel()
		return "synthetic-answer", nil
	}}
	_, err := p.smsFlow(ctx, sdpc.NewClient(server.URL, "Mac", "device", server.Client()))
	if !errors.Is(err, context.Canceled) || submissions.Load() != 0 {
		t.Fatalf("err=%v submissions=%d", err, submissions.Load())
	}
}
