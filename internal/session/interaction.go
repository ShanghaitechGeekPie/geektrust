package session

import (
	"context"
	"errors"
	"github.com/ShanghaitechGeekPie/geektrust/auth"
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
	p.cur = nil
	p.mu.Unlock()
	p.CloseObservers()
}

type expectedGenerationKey struct{}

var ErrSessionReplaced = errors.New("session replaced")

func ExpectGeneration(ctx context.Context, g uint64) context.Context {
	return context.WithValue(ctx, expectedGenerationKey{}, g)
}
