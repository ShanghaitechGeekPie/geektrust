package auth

import (
	"context"
	"errors"
	"github.com/ShanghaitechGeekPie/geektrust/internal/idsauth"
	"net/http"
)

type Passkey struct {
	store CredentialStore
	gate  chan struct{}
}

func NewPasskey(s CredentialStore) (*Passkey, error) {
	if s == nil {
		return nil, ErrCredentialStore
	}
	return &Passkey{store: s, gate: make(chan struct{}, 1)}, nil
}
func (p *Passkey) Info(ctx context.Context) (IdentityInfo, error) {
	b, e := p.store.Load(ctx)
	if e != nil {
		return IdentityInfo{}, storeError(e)
	}
	return InspectPasskey(b)
}
func InspectPasskey(b []byte) (IdentityInfo, error) {
	k, e := idsauth.ParseKeystore(b, nil)
	if e != nil {
		return IdentityInfo{}, ErrInvalidCredential
	}
	return IdentityInfo{Issuer: k.BaseURL(), Subject: k.Username(), Kind: k.Kind()}, nil
}
func (p *Passkey) Authenticate(ctx context.Context, h *http.Client, _ IdentityRequest) error {
	select {
	case p.gate <- struct{}{}:
		defer func() { <-p.gate }()
	case <-ctx.Done():
		return ctx.Err()
	}
	if locker, ok := p.store.(interface {
		Lock(context.Context) (func(), error)
	}); ok {
		unlock, e := locker.Lock(ctx)
		if e != nil {
			return storeError(e)
		}
		defer unlock()
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	b, e := p.store.Load(ctx)
	if e != nil {
		return storeError(e)
	}
	k, e := idsauth.ParseKeystore(b, func(b []byte) error {
		if e := p.store.Save(ctx, b); e != nil {
			return storeError(e)
		}
		return nil
	})
	if e != nil {
		return ErrInvalidCredential
	}
	return idsauth.NewClient(k, h).Login(ctx)
}
func storeError(e error) error {
	if errors.Is(e, context.Canceled) {
		return errors.Join(ErrCredentialStore, context.Canceled)
	}
	if errors.Is(e, context.DeadlineExceeded) {
		return errors.Join(ErrCredentialStore, context.DeadlineExceeded)
	}
	return ErrCredentialStore
}
