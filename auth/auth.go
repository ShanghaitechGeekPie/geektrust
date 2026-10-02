// Package auth defines the authentication boundary shared by embedders and the
// controller. It contains no terminal, storage, or school-specific behavior.
package auth

import (
	"context"
	"errors"
	"net/http"
	"time"
)

var ErrUnsupported = errors.New("unsupported authentication method")
var ErrRequired = errors.New("authentication input required")

type UnsupportedError struct{ Method string }

func (e *UnsupportedError) Error() string { return ErrUnsupported.Error() }
func (e *UnsupportedError) Unwrap() error { return ErrUnsupported }

type Challenge struct {
	Method    string
	ExpiresAt time.Time
}

type RequiredError struct{ Challenge Challenge }

func (e *RequiredError) Error() string { return ErrRequired.Error() }
func (e *RequiredError) Unwrap() error { return ErrRequired }

// Handler waits for user input using ctx. The caller owns how the prompt is
// displayed; the SDK never includes the submitted answer in an event or log.
type Handler func(context.Context, Challenge) (string, error)

type ControllerRequest struct {
	URL, DeviceID, Platform, ClientType, LoginDomain string
	// CSRFToken comes from the initial controller authConfig response.
	CSRFToken string
}

// ControllerLogin replaces the built-in identity-to-CAS authentication chain.
// On success it leaves the authenticated controller cookies in http.Client.Jar.
// The SDK checks onlineInfo and fetches policy before accepting the session.
type ControllerLogin func(context.Context, *http.Client, ControllerRequest) error
