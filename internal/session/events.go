package session

import (
	"context"
	"regexp"
	"time"

	"geektrust/internal/sdpc"
)

// EventKind identifies a session lifecycle event.
type EventKind string

const (
	EventLoginStart   EventKind = "login_start"
	EventLoginSuccess EventKind = "login_success"
	EventRestoreOK    EventKind = "restore_success"
	EventLoginFailed  EventKind = "login_failed"
	EventInvalidated  EventKind = "invalidated"
)

// SessionInfo is the credential-redacted session snapshot handed to
// observers. It never contains SID, cookies or CSRF tokens.
type SessionInfo struct {
	Username    string
	DisplayName string
	ClientIP    string
	DeviceID    string
	ClientType  string
	Gateways    []string // effective values (clientResource/config/default)
	DNS         []string // effective values
}

// Event is the JSON-safe history unit delivered to observers. It must never
// carry functions, credentials or raw error objects.
type Event struct {
	Kind    EventKind
	Time    time.Time
	Message string // sanitized, see SanitizeErrorText
	Session *SessionInfo
	// Dropped is the dispatcher's cumulative drop count before this event,
	// stamped at dequeue time.
	Dropped uint64
}

// Observer receives session lifecycle events. Implementations must return
// quickly; the dispatcher never holds its queue lock while invoking them.
type Observer interface{ OnSessionEvent(Event) }

// SMSHandler prompts for the SMS verification code with resend capability.
// resend stays valid until Prompt returns.
type SMSHandler interface {
	Prompt(ctx context.Context, resend func(context.Context) error) (string, error)
}

// newSessionInfo assembles the redacted snapshot: user fields from
// onlineInfo, device/routing effective values from the credential, and the
// login mode from configuration.
func newSessionInfo(info *sdpc.OnlineInfo, cred *Credential, clientType string) *SessionInfo {
	return &SessionInfo{
		Username:    info.Username,
		DisplayName: info.DisplayName,
		ClientIP:    info.ClientIP,
		DeviceID:    cred.DeviceID,
		ClientType:  clientType,
		Gateways:    append([]string(nil), cred.Gateways...),
		DNS:         append([]string(nil), cred.DNS...),
	}
}

// sensitiveParamRE matches URL query parameters whose values are credentials.
// The CAS chain can put ?ticket=ST-... into wrapped network errors.
var sensitiveParamRE = regexp.MustCompile(`(?i)([?&](?:ticket|sid|code|password)=)[^&\s"']+`)

// SanitizeErrorText redacts credential-bearing URL parameters and truncates
// the message to at most 300 runes (ellipsis included) before it enters
// events or API responses. Truncation is rune-based so multi-byte UTF-8 is
// never split.
func SanitizeErrorText(s string) string {
	s = sensitiveParamRE.ReplaceAllString(s, "${1}***")
	const maxRunes = 300
	if r := []rune(s); len(r) > maxRunes {
		s = string(r[:maxRunes-1]) + "…"
	}
	return s
}
