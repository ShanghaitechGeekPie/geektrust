package session

import (
	"context"
	"errors"
	"fmt"
	"github.com/ShanghaitechGeekPie/geektrust/auth"
	"github.com/ShanghaitechGeekPie/geektrust/internal/sdpc"
	"sync"
	"sync/atomic"
	"time"
)

var challengeSequence atomic.Uint64

func (p *Provider) challengeFlow(ctx context.Context, sc *sdpc.Client, deadline time.Time) (string, error) {
	info := auth.ChallengeInfo{ID: challengeSequence.Add(1), Method: auth.SMS, Deadline: deadline}
	for {
		var mu sync.Mutex
		active := true
		resend := func(parent context.Context) (auth.ChallengeInfo, error) {
			mu.Lock()
			defer mu.Unlock()
			if !active || ctx.Err() != nil {
				return auth.ChallengeInfo{}, auth.ErrChallengeClosed
			}
			call, cancel := context.WithCancel(parent)
			stop := context.AfterFunc(ctx, cancel)
			defer func() { stop(); cancel() }()
			e := sc.SendSMS(call)
			if sdpc.IsSessionExpired(e) {
				return auth.ChallengeInfo{}, fmt.Errorf("%w: %w", errSMSAuthSessionExpired, e)
			}
			return info, e
		}
		code, e := p.ChallengeHandler(ctx, auth.Challenge{Info: info, Resend: resend})
		mu.Lock()
		active = false
		mu.Unlock()
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		if e != nil {
			return "", e
		}
		ticket, e := sc.CheckSMSCode(ctx, code)
		if e == nil {
			return ticket, nil
		}
		if sdpc.IsSessionExpired(e) {
			return "", fmt.Errorf("%w: %w", errSMSAuthSessionExpired, e)
		}
		var api *sdpc.APIError
		if !errors.As(e, &api) {
			return "", e
		}
		info.LastFailure = &auth.ChallengeFailure{Code: int(api.Code), Message: "verification rejected"}
	}
}
