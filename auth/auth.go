package auth

import (
	"context"
	"errors"
	"net/http"
	"time"
)

type IdentityInfo struct {
	Issuer  string
	Subject string
	Kind    string
}

type IdentityProvider interface {
	Info(context.Context) (IdentityInfo, error)
	Authenticate(context.Context, *http.Client, IdentityRequest) error
}

type IdentityRequest struct {
	AllowInteraction bool
}

type CredentialStore interface {
	Load(context.Context) ([]byte, error)
	Save(context.Context, []byte) error
}

type Method string

const SMS Method = "sms"

var ErrInteractionRequired = errors.New("authentication interaction required")
var ErrUnsupported = errors.New("unsupported authentication method")
var ErrChallengeClosed = errors.New("authentication challenge closed")
var ErrInvalidCredential = errors.New("invalid credential")
var ErrCredentialStore = errors.New("credential store failure")

type ChallengeFailure struct {
	Code    int
	Message string
}

type ChallengeInfo struct {
	ID              uint64
	Method          Method
	Deadline        time.Time
	ServerExpiresAt time.Time
	LastFailure     *ChallengeFailure
}

type Challenge struct {
	Info   ChallengeInfo
	Resend func(context.Context) (ChallengeInfo, error)
}

type Handler func(context.Context, Challenge) (string, error)

type UnsupportedError struct{ Method string }

func (e *UnsupportedError) Error() string { return ErrUnsupported.Error() }
func (e *UnsupportedError) Unwrap() error { return ErrUnsupported }

type RequiredError struct{ Challenge Challenge }

func (e *RequiredError) Error() string { return ErrInteractionRequired.Error() }
func (e *RequiredError) Unwrap() error { return ErrInteractionRequired }
