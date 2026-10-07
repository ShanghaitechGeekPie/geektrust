package session

import (
	"context"
	"errors"
	"github.com/ShanghaitechGeekPie/geektrust/auth"
	"github.com/ShanghaitechGeekPie/geektrust/internal/sdpc"
	"time"
)

type interactionKey struct{}

func WithInteraction(ctx context.Context, allow bool) context.Context {
	return context.WithValue(ctx, interactionKey{}, allow)
}
func InteractionAllowed(ctx context.Context) bool {
	v, ok := ctx.Value(interactionKey{}).(bool)
	return !ok || v
}
func (p *Provider) SetIdentity(i auth.IdentityInfo) {
	p.mu.Lock()
	p.cfg.IdentityIssuer = i.Issuer
	p.cfg.IdentitySubject = i.Subject
	p.cfg.IdentityKind = i.Kind
	p.mu.Unlock()
}
func (p *Provider) httpTimeout() time.Duration {
	if p.HTTPTimeout == 0 {
		return 30 * time.Second
	}
	return p.HTTPTimeout
}

func (p *Provider) SetLegacyGateways(v []string) {
	p.mu.Lock()
	p.cfg.Gateways = append([]string(nil), v...)
	p.cfg.GatewayFilter = false
	p.cfg.LegacyGatewayOverride = true
	p.mu.Unlock()
}
func (p *Provider) Current() *Credential { p.mu.Lock(); defer p.mu.Unlock(); return p.cur }

func (p *Provider) Close() {
	p.mu.Lock()
	p.closed = true
	p.revision++
	if p.cancelSession != nil {
		p.cancelSession()
		p.cancelSession = nil
	}
	p.cur = nil
	p.mu.Unlock()
	p.CloseObservers()
}

type expectedGenerationKey struct{}

var ErrSessionReplaced = errors.New("session replaced")

func ExpectGeneration(ctx context.Context, g uint64) context.Context {
	return context.WithValue(ctx, expectedGenerationKey{}, g)
}

type acquisitionKey struct{}

func withAcquisition(ctx context.Context, revision uint64) context.Context {
	return context.WithValue(ctx, acquisitionKey{}, revision)
}
func (p *Provider) CheckAcquisition(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.checkAcquisitionLocked(ctx)
}

func (p *Provider) checkAcquisitionLocked(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.closed {
		return context.Canceled
	}
	if revision, ok := ctx.Value(acquisitionKey{}).(uint64); ok && revision != p.revision {
		return ErrSessionReplaced
	}
	return nil
}

// ActiveSession returns the credential and controller from one acquisition.
func (p *Provider) ActiveSession() (*Credential, *sdpc.Client) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cur == nil {
		return nil, nil
	}
	return p.cur, p.cur.controller
}
