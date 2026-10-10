package session

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/ShanghaitechGeekPie/geektrust/auth"
	"github.com/ShanghaitechGeekPie/geektrust/internal/sdpc"
)

type smsLifetimeTransport struct{ sends int }

func (s *smsLifetimeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	body := `{"code":0,"data":{"sidTicket":"fixture"}}`
	if r.URL.Query().Get("action") == "sendsms" {
		s.sends++
		body = `{"code":0,"data":{}}`
	}
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
}

func TestSMSChallengeUsesCallerLifetime(t *testing.T) {
	for _, lifetime := range []time.Duration{0, 5 * time.Minute, 30 * time.Second} {
		t.Run(lifetime.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx := context.Background()
				if lifetime != 0 {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, lifetime)
					defer cancel()
				}
				transport := &smsLifetimeTransport{}
				sc := sdpc.NewClient("https://controller.example", "Mac", "id", &http.Client{Transport: transport})
				p := &Provider{ChallengeHandler: func(call context.Context, c auth.Challenge) (string, error) {
					// The first code expired; the caller is still allowed to request another.
					time.Sleep(61 * time.Second)
					if err := call.Err(); err != nil {
						return "", err
					}
					info, err := c.Resend(call)
					if err != nil {
						return "", err
					}
					deadline, _ := ctx.Deadline()
					if !info.Deadline.Equal(deadline) {
						t.Errorf("challenge deadline = %v, caller deadline = %v", info.Deadline, deadline)
					}
					return "123456", nil
				}}
				ticket, err := p.smsFlow(ctx, sc)
				if lifetime == 30*time.Second {
					if !errors.Is(err, context.DeadlineExceeded) || transport.sends != 1 {
						t.Fatalf("caller timeout: sends=%d, error=%v", transport.sends, err)
					}
				} else if err != nil || ticket != "fixture" || transport.sends != 2 {
					t.Fatalf("resend after first code expires: sends=%d, ticket=%q, error=%v", transport.sends, ticket, err)
				}
			})
		})
	}
}
