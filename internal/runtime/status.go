package runtime

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"github.com/ShanghaitechGeekPie/geektrust/auth"
	"github.com/ShanghaitechGeekPie/geektrust/compatibility"
	"github.com/ShanghaitechGeekPie/geektrust/internal/resolver"
	"github.com/ShanghaitechGeekPie/geektrust/internal/sdpc"
	"github.com/ShanghaitechGeekPie/geektrust/internal/session"
	"time"
)

type SessionState string

const (
	Idle                SessionState = "idle"
	Authenticating      SessionState = "authenticating"
	InteractionRequired SessionState = "interaction_required"
	Ready               SessionState = "ready"
	Failed              SessionState = "failed"
	Closed              SessionState = "closed"
)

type Status struct {
	Revision      uint64
	Generation    uint64
	State         SessionState
	Compatibility compatibility.Profile
	Session       *SessionInfo
	LastError     *ErrorInfo
}

type ErrorKind string

const (
	ErrorConfig                 ErrorKind = "config"
	ErrorInteractionRequired    ErrorKind = "interaction_required"
	ErrorIdentityChanged        ErrorKind = "identity_changed"
	ErrorAuthenticationRejected ErrorKind = "authentication_rejected"
	ErrorControllerDenied       ErrorKind = "controller_denied"
	ErrorCallerDenied           ErrorKind = "caller_denied"
	ErrorTLS                    ErrorKind = "tls"
	ErrorDNS                    ErrorKind = "dns"
	ErrorNetwork                ErrorKind = "network"
	ErrorUnsupported            ErrorKind = "unsupported"
	ErrorSessionReplaced        ErrorKind = "session_replaced"
	ErrorDatagramTooLarge       ErrorKind = "datagram_too_large"
	ErrorStorage                ErrorKind = "storage"
	ErrorClosed                 ErrorKind = "closed"
)

type ErrorInfo struct {
	Kind    ErrorKind
	Op      string
	Code    int
	Message string
}

type TrustedDevice struct {
	ID, Name, Platform, OS, OSVersion string
	LastLoginIP, LastLoginAddress     string
	NetworkZones                      []string
	Online                            bool
}

type TrustedDeviceList struct {
	Devices            []TrustedDevice
	CurrentDeviceID    string
	CurrentTrustStatus int
	TrustEnabled       bool
}

type Error struct {
	Info  ErrorInfo
	cause error
}

func (e *Error) Error() string        { return e.Info.Message }
func (e *Error) Unwrap() error        { return e.cause }
func (e *Error) Is(target error) bool { return errors.Is(e.cause, target) }
func safeError(op string, e error) error {
	if e == nil {
		return nil
	}
	var existing *Error
	if errors.As(e, &existing) {
		return e
	}
	kind := ErrorNetwork
	cause := error(sanitizedCause{e})
	msg := "network operation failed"
	switch {
	case errors.Is(e, context.Canceled):
		cause = context.Canceled
		msg = "operation canceled"
	case errors.Is(e, context.DeadlineExceeded):
		cause = context.DeadlineExceeded
		msg = "operation deadline exceeded"
	case errors.Is(e, auth.ErrInteractionRequired):
		kind = ErrorInteractionRequired
		cause = auth.ErrInteractionRequired
		msg = "authentication interaction required"
	case errors.Is(e, auth.ErrCredentialStore):
		kind = ErrorStorage
		cause = auth.ErrCredentialStore
		msg = "credential storage failed"
	case errors.Is(e, auth.ErrInvalidCredential):
		kind = ErrorConfig
		cause = auth.ErrInvalidCredential
		msg = "invalid identity credential"
	case errors.Is(e, session.ErrIdentityAuthentication):
		kind = ErrorAuthenticationRejected
		msg = "identity authentication failed"
	case errors.Is(e, auth.ErrUnsupported):
		kind = ErrorUnsupported
		cause = auth.ErrUnsupported
		msg = "unsupported operation"
	case errors.Is(e, resolver.ErrUnresolvable):
		kind = ErrorDNS
		msg = "target DNS resolution failed"
	case errors.Is(e, session.ErrSessionReplaced):
		kind = ErrorSessionReplaced
		cause = session.ErrSessionReplaced
		msg = "session replaced"
	case errors.Is(e, ErrClosed):
		kind = ErrorClosed
		cause = ErrClosed
		msg = ErrClosed.Error()
	case errors.Is(e, ErrDenied):
		kind = ErrorControllerDenied
		cause = ErrDenied
		msg = ErrDenied.Error()
	case errors.Is(e, ErrDatagramTooLarge):
		kind = ErrorDatagramTooLarge
		cause = ErrDatagramTooLarge
		msg = ErrDatagramTooLarge.Error()
	}
	var certificate *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	var host x509.HostnameError
	var invalid x509.CertificateInvalidError
	if errors.As(e, &certificate) || errors.As(e, &unknown) || errors.As(e, &host) || errors.As(e, &invalid) {
		kind = ErrorTLS
		msg = "gateway certificate verification failed"
	}
	var api *sdpc.APIError
	code := 0
	if errors.As(e, &api) {
		kind = ErrorControllerDenied
		code = int(api.Code)
		msg = "controller rejected operation"
	}
	return &Error{Info: ErrorInfo{Kind: kind, Op: op, Code: code, Message: msg}, cause: cause}
}
func ImplementedCapabilities() Capabilities {
	return Capabilities{IPv4TCP: true, IPv4UDP: true, IPv4ICMPEcho: true, IPv6Gateway: true}
}
func (c *Runtime) operationTimeout() time.Duration {
	if c.dialTimeout == 0 {
		return 45 * time.Second
	}
	return c.dialTimeout
}
func (c *Runtime) currentGeneration() uint64 {
	if v := c.provider.Current(); v != nil {
		return v.Generation
	}
	return 0
}
func (c *Runtime) prepare(ctx context.Context) error {
	if c.isClosed() {
		return ErrClosed
	}
	select {
	case c.identityGate <- struct{}{}:
		defer func() { <-c.identityGate }()
	case <-ctx.Done():
		return ctx.Err()
	}
	info, e := c.identity.Info(ctx)
	if e != nil {
		return e
	}
	if info.Issuer == "" || info.Subject == "" || info.Kind == "" {
		return errors.New("identity metadata required")
	}
	if c.identityReady {
		if c.scope.IdentityIssuer != info.Issuer || c.scope.IdentitySubject != info.Subject || c.scope.IdentityKind != info.Kind {
			return &Error{Info: ErrorInfo{Kind: ErrorIdentityChanged, Op: "identity", Message: "identity changed; create a new client"}}
		}
		return nil
	}
	if c.isClosed() {
		return ErrClosed
	}
	c.scope.IdentityIssuer = info.Issuer
	c.scope.IdentitySubject = info.Subject
	c.scope.IdentityKind = info.Kind
	c.identityReady = true
	c.provider.SetIdentity(info)
	c.provider.AddObserver(clientObserver{c})
	return nil
}
func (c *Runtime) start() {
	c.startOnce.Do(func() { go func() { defer close(c.tasksDone); c.provider.CheckLoop(c.ctx, 5*time.Minute) }() })
}
func (c *Runtime) Status() Status { c.mu.Lock(); defer c.mu.Unlock(); return cloneStatus(c.status) }
func cloneStatus(s Status) Status {
	if s.Session != nil {
		v := cloneSession(*s.Session)
		s.Session = &v
	}
	if s.LastError != nil {
		v := *s.LastError
		s.LastError = &v
	}
	return s
}
func (c *Runtime) Subscribe(ctx context.Context) <-chan Event {
	ch := make(chan Event, 1)
	c.mu.Lock()
	if c.closed {
		close(ch)
		c.mu.Unlock()
		return ch
	}
	c.nextSubscriber++
	id := c.nextSubscriber
	c.subscribers[id] = ch
	ch <- Event{Time: time.Now(), Status: cloneStatus(c.status)}
	c.mu.Unlock()
	go func() {
		select {
		case <-ctx.Done():
		case <-c.ctx.Done():
		}
		c.mu.Lock()
		if _, ok := c.subscribers[id]; ok {
			delete(c.subscribers, id)
			close(ch)
		}
		c.mu.Unlock()
	}()
	return ch
}
func (c *Runtime) publishLocked() {
	c.status.Revision++
	c.status.Compatibility = c.profile
	now := time.Now()
	for _, ch := range c.subscribers {
		ev := Event{Time: now, Status: cloneStatus(c.status)}
		select {
		case ch <- ev:
		default:
			select {
			case <-ch:
			default:
			}
			ch <- ev
		}
	}
}
func (c *Runtime) Shutdown(ctx context.Context) error {
	// Closing a socket can wait for a protocol close write. The caller's
	// deadline bounds the wait while cleanup continues to completion.
	go c.Close()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.shutdownDone:
		return nil
	}
}
func (c *Runtime) ForgetSession(parent context.Context) error {
	ctx, done := c.operation(parent)
	defer done()
	if e := c.prepare(ctx); e != nil {
		return e
	}
	if err := c.cache.lock(ctx); err != nil {
		return err
	}
	defer c.cache.unlock()
	c.mu.Lock()
	if err := ctx.Err(); err != nil {
		c.mu.Unlock()
		return err
	}
	c.forgotten = true
	c.mu.Unlock()
	c.provider.Invalidate()
	c.resetConnections()
	if c.cache.store == nil {
		return nil
	}
	if err := c.cache.store.Delete(ctx, c.scope); err != nil {
		return &Error{Info: ErrorInfo{Kind: ErrorStorage, Op: "forget_session", Message: "session storage delete failed"}, cause: sanitizedCause{err}}
	}
	return nil
}

func (c *Runtime) resetConnections() {
	c.mu.Lock()
	conns := make([]*ownedConn, 0, len(c.conns))
	for x := range c.conns {
		conns = append(conns, x)
	}
	c.mu.Unlock()
	for _, x := range conns {
		x.Close()
	}
	c.manager.Reset()
}

type clientObserver struct{ client *Runtime }

func (o clientObserver) OnSessionEvent(e session.Event) {
	c := o.client

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	current := c.provider.Current()
	if current != nil && (e.Kind == session.EventLoginStart || e.Kind == session.EventLoginFailed || e.Kind == session.EventInteractionRequired || e.Kind == session.EventInvalidated) {
		return
	}
	if e.Kind == session.EventLoginSuccess || e.Kind == session.EventRestoreOK {
		if e.Session == nil || current == nil || e.Session.Generation != current.Generation {
			return
		}
	}
	if e.Session != nil && current != nil && e.Session.Generation != current.Generation {
		return
	}
	if e.Session != nil && c.status.State == Ready && c.status.Session != nil && c.status.Session.Generation == e.Session.Generation {
		return
	}
	switch e.Kind {
	case session.EventLoginStart:
		c.status.State = Authenticating
	case session.EventLoginSuccess, session.EventRestoreOK:
		c.status.State = Ready
		c.status.Generation = current.Generation
		v := sessionInfo(current)
		c.status.Session = &v
		c.status.LastError = nil
	case session.EventInteractionRequired:
		c.status.State = InteractionRequired
		c.status.LastError = &ErrorInfo{Kind: ErrorInteractionRequired, Op: "authentication", Message: "authentication interaction required"}
	case session.EventLoginFailed:
		c.status.State = Failed
		c.status.LastError = &ErrorInfo{Kind: ErrorAuthenticationRejected, Op: "authentication", Message: "authentication failed"}
	case session.EventInvalidated:
		c.status.State = Idle
		c.status.Session = nil
		c.status.LastError = nil
	default:
		return
	}
	c.publishLocked()
}

type stateStore struct {
	gate   chan struct{}
	store  SessionStore
	client *Runtime
}

func (s *stateStore) Load(ctx context.Context) (*session.State, error) {
	if err := s.lock(ctx); err != nil {
		return nil, err
	}
	defer s.unlock()
	if s.store == nil {
		return nil, nil
	}
	s.client.mu.Lock()
	forgot := s.client.forgotten
	s.client.mu.Unlock()
	if forgot {
		return nil, nil
	}
	b, e := s.store.Load(ctx, s.client.scope)
	if e != nil {
		return nil, &Error{Info: ErrorInfo{Kind: ErrorStorage, Message: "session storage load failed"}, cause: sanitizedCause{e}}
	}
	if len(b) == 0 {
		return nil, nil
	}
	var st session.State
	if json.Unmarshal(b, &st) != nil {
		return nil, &Error{Info: ErrorInfo{Kind: ErrorStorage, Message: "invalid session record"}}
	}
	if st.Version == 0 {
		return nil, nil
	}
	if st.Version != 1 {
		return nil, &Error{Info: ErrorInfo{Kind: ErrorStorage, Message: "invalid session record"}}
	}
	return &st, nil
}
func (s *stateStore) Save(ctx context.Context, st *session.State) error {
	if err := s.lock(ctx); err != nil {
		return err
	}
	defer s.unlock()
	if err := s.client.provider.CheckAcquisition(ctx); err != nil {
		return err
	}
	if s.store == nil {
		return nil
	}
	b, e := json.Marshal(st)
	if e != nil {
		return e
	}
	if e = s.store.Save(ctx, s.client.scope, b); e != nil {
		return &Error{Info: ErrorInfo{Kind: ErrorStorage, Message: "session storage save failed"}, cause: sanitizedCause{e}}
	}
	if err := s.client.provider.CheckAcquisition(ctx); err != nil {
		return err
	}
	s.client.mu.Lock()
	s.client.forgotten = false
	s.client.mu.Unlock()
	return nil
}

// The tunnel performs CA validation first. Unknown CA enrollment is one atomic store operation.
type pinAdapter struct {
	store      GatewayPinStore
	controller string
}

func (p pinAdapter) CheckOrEnroll(ctx context.Context, address, serverName string, pin [32]byte) (bool, error) {
	ok, err := p.store.CheckOrEnroll(ctx, GatewayIdentity{ControllerURL: p.controller, Address: address, ServerName: serverName}, pin)
	if err != nil {
		return false, &Error{Info: ErrorInfo{Kind: ErrorStorage, Message: "gateway pin storage failed"}, cause: sanitizedCause{err}}
	}
	return ok, nil
}

func PublicError(op string, e error) error { return safeError(op, e) }

type sanitizedCause struct{ original error }

func (s sanitizedCause) Error() string   { return "operation failed" }
func (s sanitizedCause) Is(e error) bool { return errors.Is(s.original, e) }

func ConfigError(e error) error {
	if e == nil {
		return nil
	}
	return &Error{Info: ErrorInfo{Kind: ErrorConfig, Op: "new", Message: e.Error()}}
}

func cloneSession(s SessionInfo) SessionInfo {
	s.Gateways = append([]string(nil), s.Gateways...)
	s.DNS = append([]string(nil), s.DNS...)
	s.Resources = append([]Resource(nil), s.Resources...)
	return s
}

func (s *stateStore) lock(ctx context.Context) error {
	select {
	case s.gate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (s *stateStore) unlock() { <-s.gate }
