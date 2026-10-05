package session

import (
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"sync"
	"time"

	"github.com/ShanghaitechGeekPie/geektrust/auth"
	"github.com/ShanghaitechGeekPie/geektrust/internal/idsauth"
	"github.com/ShanghaitechGeekPie/geektrust/internal/sdpc"
	"github.com/ShanghaitechGeekPie/geektrust/internal/settings"
)

// errSMSAuthSessionExpired marks an expiration discovered after the user has
// entered the SMS wait. login catches it and rebuilds the whole IDS/controller
// authentication chain instead of publishing a terminal login failure.
var ErrIdentityAuthentication = errors.New("identity authentication rejected")

var ErrStateStorage = errors.New("session storage failure")

var errSMSAuthSessionExpired = errors.New("SMS authentication session expired")

// Credential is everything the tunnel and resolver need from a live session.
type Credential struct {
	Generation            uint64
	LegacyGatewayOverride bool
	ProcessIdentity       *settings.ProcessIdentity
	// AppID is the legacy fallback; matched resource rules always take priority.
	AppID                       string
	MissingGatewayGroupFallback bool
	GatewayOverride             bool
	AllowTCPFallback            bool
	Original                    *Credential
	SID                         string
	DeviceID                    string
	Username                    string
	DisplayName                 string
	ConnectionID                string
	CsrfToken                   string
	Cookies                     []*http.Cookie
	Gateways                    []string
	DNS                         []string
	// Policy is the full routing policy (domain/IP/CIDR × port → appId)
	// from clientResource.
	Policy *sdpc.Resource
}

// SMSPrompter asks the user for the SMS verification code. It runs whenever
// the controller demands SMS — the first login of a new device_id, or a
// later full login the server refuses to waive. With a nil prompt, such a
// login fails.
type SMSPrompter func(ctx context.Context) (string, error)

// CredentialProvider is the login↔tunnel contract: consumers (tunnel,
// resolver, l3) only ever ask for valid credentials; the provider hides
// restoration, refresh and silent re-login.
type CredentialProvider interface {
	// Credential returns current valid credentials, re-logging in if needed.
	Credential(ctx context.Context) (*Credential, error)
	// InvalidateIfCurrent drops the cached credential only when expected is
	// still current, so a stale rejection cannot erase a newer login.
	InvalidateIfCurrent(expected *Credential) bool
}

// Provider implements CredentialProvider: it returns valid session
// credentials, restoring a persisted session or re-logging in silently
// when the controller does not request SMS.
type Provider struct {
	cfg              *settings.Session
	logger           *slog.Logger
	prompt           SMSPrompter
	smsHandler       SMSHandler // set by SetSMSHandler during web wiring
	store            StateStore
	Authenticate     func(context.Context, *http.Client) (string, error)
	ChallengeHandler auth.Handler
	Transport        http.RoundTripper
	HTTPTimeout      time.Duration

	mu         sync.Mutex
	cur        *Credential
	sdpc       *sdpc.Client // last client, for liveness checks
	refreshing *refreshCall
	generation uint64
	closed     bool
	forceLogin bool // set by Invalidate; skips restore on the next refresh

	dispMu      sync.Mutex
	dispCond    *sync.Cond // lazily created on first AddObserver
	dispQueue   []Event
	dispDropped uint64
	observers   []Observer
	dispClosed  bool
	dispStarted bool
}

// refreshCall is one in-flight restore/login shared by every concurrent
// caller: all waiters block on done and then read the same result.
type refreshCall struct {
	done   chan struct{} // closed once cred/err are populated
	cred   *Credential
	err    error
	leader context.Context
}

// NewProvider builds a credential provider. prompt may be nil; a login that
// requires SMS then returns an error.
func NewProvider(source interface{ SessionOptions() settings.Session }, logger *slog.Logger, prompt SMSPrompter) *Provider {
	normalized := source.SessionOptions()
	normalized.Compatibility = normalized.Compatibility.Clone()
	cfg := &normalized
	return &Provider{
		cfg:    cfg,
		logger: logger,
		prompt: prompt,
		store:  NewStore(cfg.StateFile),
	}
}

// SDPCClient returns the controller client from the last successful login,
// or nil if no session has been established. Callers must not cache it: a
// re-login may replace it at any time.
func (p *Provider) SDPCClient() *sdpc.Client {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sdpc
}

// ActiveSDPC returns the controller client only while a credential is
// active. Invalidate clears cur but keeps the last client, so SDPCClient
// can be stale; this method cannot.
func (p *Provider) ActiveSDPC() *sdpc.Client {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cur == nil {
		return nil
	}
	return p.sdpc
}

// SetSMSHandler replaces the simple SMSPrompter with a resend-capable
// handler. Called during web wiring, before the first Credential.
func (p *Provider) SetSMSHandler(h SMSHandler) { p.smsHandler = h }

// AddObserver registers a lifecycle observer and starts the event drainer
// on first call. Observers must be registered during wiring, before the
// first Credential; the slice is read-only afterwards.
func (p *Provider) AddObserver(o Observer) {
	p.dispMu.Lock()
	defer p.dispMu.Unlock()
	p.observers = append(p.observers, o)
	if !p.dispStarted {
		p.dispStarted = true
		p.dispCond = sync.NewCond(&p.dispMu)
		go p.drainEvents()
	}
}

// emit queues ev and returns immediately. It never invokes observers, so it
// is safe to call while holding p.mu. Without observers it is a no-op.
func (p *Provider) emit(ev Event) {
	p.dispMu.Lock()
	defer p.dispMu.Unlock()
	if p.dispClosed || len(p.observers) == 0 {
		return
	}
	ev.Time = time.Now()
	const maxQueue = 256
	if len(p.dispQueue) >= maxQueue {
		p.dispQueue = p.dispQueue[1:]
		p.dispDropped++
	}
	p.dispQueue = append(p.dispQueue, ev)
	p.dispCond.Signal()
}

// drainEvents is the single drainer goroutine: strictly FIFO, stamps the
// drop count at dequeue, and never holds the queue lock across callbacks
// (holding it could deadlock against p.mu in an observer that calls back
// into the provider).
func (p *Provider) drainEvents() {
	for {
		p.dispMu.Lock()
		for len(p.dispQueue) == 0 && !p.dispClosed {
			p.dispCond.Wait()
		}
		if p.dispClosed {
			p.dispMu.Unlock()
			return
		}
		ev := p.dispQueue[0]
		p.dispQueue[0] = Event{}
		p.dispQueue = p.dispQueue[1:]
		if len(p.dispQueue) == 0 {
			p.dispQueue = nil
		}
		ev.Dropped = p.dispDropped
		observers := append([]Observer(nil), p.observers...)
		p.dispMu.Unlock()
		for _, o := range observers {
			o.OnSessionEvent(ev)
		}
	}
}

// Credential returns current valid credentials. Concurrent callers share one
// in-flight restore/login.
func (p *Provider) Credential(ctx context.Context) (*Credential, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, context.Canceled
		}
		if p.cur != nil {
			if g, ok := ctx.Value(expectedGenerationKey{}).(uint64); ok && g != p.cur.Generation {
				p.mu.Unlock()
				return nil, ErrSessionReplaced
			}
			cred := p.cur
			p.mu.Unlock()
			return cred, nil
		}
		if _, ok := ctx.Value(expectedGenerationKey{}).(uint64); ok {
			p.mu.Unlock()
			return nil, ErrSessionReplaced
		}
		call := p.refreshing
		if call == nil {
			call = &refreshCall{done: make(chan struct{}), leader: ctx}
			p.refreshing = call
			p.mu.Unlock()

			cred, session, restored, err := p.acquire(ctx, false)
			p.finishRefresh(call, cred, session, restored, err)
			return cred, err
		}
		p.mu.Unlock()
		select {
		case <-call.done:
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			// A restore/login still belongs to its initiating caller (including
			// interactive SMS). A live joiner retries under its own context only
			// when that caller canceled the acquisition, not on ordinary failures.
			if call.err != nil && call.leader != nil && call.leader.Err() != nil && errors.Is(call.err, call.leader.Err()) {
				continue
			}
			return call.cred, call.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// finishRefresh publishes the acquisition result under p.mu and only then
// queues the lifecycle event, so observers can never see "online" while
// ActiveSDPC still returns nil. Events are queued under the lock (emit
// never callbacks), then waiters are released.
func (p *Provider) finishRefresh(call *refreshCall, cred *Credential, session *SessionInfo, restored bool, err error) {
	p.mu.Lock()
	if p.closed {
		err = context.Canceled
	}
	if call.leader != nil && call.leader.Err() != nil {
		err = call.leader.Err()
	}
	if err == nil {
		p.generation++
		cred.Generation = p.generation
		session.Generation = p.generation
		p.cur = cred
		if restored {
			p.emit(Event{Kind: EventRestoreOK, Session: session, Message: "已恢复会话：" + session.DisplayName})
		} else {
			p.emit(Event{Kind: EventLoginSuccess, Session: session, Message: "会话已建立：" + session.DisplayName})
		}
	} else {
		kind := EventLoginFailed
		if errors.Is(err, auth.ErrInteractionRequired) {
			kind = EventInteractionRequired
		}
		p.emit(Event{Kind: kind, Message: SanitizeErrorText(err.Error())})
	}
	p.refreshing = nil
	p.mu.Unlock()
	call.cred, call.err = cred, err
	close(call.done)
}

// ForceLogin performs a full login, bypassing any persisted session (used by
// the `login -fresh` command). It waits out any in-flight refresh first so
// the forced acquisition cannot be shadowed by a stale restore.
func (p *Provider) ForceLogin(ctx context.Context) (*Credential, error) {
	for {
		p.mu.Lock()
		call := p.refreshing
		p.mu.Unlock()
		if call == nil {
			break
		}
		select {
		case <-call.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	p.Invalidate()
	return p.Credential(ctx)
}

// Invalidate drops the cached credential and marks the persisted session as
// rejected, so the next Credential call performs a real re-login instead of
// restoring the very session the caller declared dead.
func (p *Provider) Invalidate() {
	p.mu.Lock()
	p.invalidateLocked()
	p.mu.Unlock()
}

// InvalidateIfCurrent invalidates only when expected is still the current
// credential: comparison, clear, force flag and the invalidated event happen
// in one p.mu critical section. Stale consumers (CheckLoop probes, tunnel
// auth rejections) cannot erase a freshly committed re-login.
func (p *Provider) InvalidateIfCurrent(expected *Credential) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if expected == nil || p.cur != expected {
		return false
	}
	p.invalidateLocked()
	return true
}

// clearSessionLocked drops the current credential and queues the
// invalidated event without touching forceLogin. Callers must hold p.mu.
func (p *Provider) clearSessionLocked() {
	p.cur = nil
	p.emit(Event{Kind: EventInvalidated, Message: "会话已失效"})
}

// invalidateLocked is clearSessionLocked plus the forceLogin flag, used by
// the unconditional/conditional invalidation paths. Callers must hold p.mu.
func (p *Provider) invalidateLocked() {
	p.clearSessionLocked()
	p.forceLogin = true
}

// TryForceRelogin atomically reserves one forced re-login: under the same
// p.mu it rejects an in-flight acquisition, clears the current session
// (queueing invalidated) and occupies the refresh slot. ok=false maps to
// HTTP 409. On ok=true the caller owns the reservation and MUST invoke the
// returned run exactly once in a background goroutine; it performs the
// forced login (skipping restore via the force argument, never the global
// flag) and publishes the result to every joined waiter. Later relogin
// requests get ok=false until the reservation completes.
func (p *Provider) TryForceRelogin() (run func(context.Context), ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.refreshing != nil {
		return nil, false
	}
	call := &refreshCall{done: make(chan struct{})}
	p.refreshing = call
	if p.cur != nil {
		p.clearSessionLocked()
	}
	return func(ctx context.Context) {
		cred, session, _, err := p.acquire(ctx, true)
		p.finishRefresh(call, cred, session, false, err)
	}, true
}

// CheckLoop periodically verifies the session with onlineInfo and re-logs
// in ahead of failure. Run in its own goroutine.
func (p *Provider) CheckLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		p.mu.Lock()
		cred, sc := p.cur, p.sdpc
		p.mu.Unlock()
		if cred == nil || sc == nil {
			continue
		}
		checkCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		info, err := sc.OnlineInfo(checkCtx)
		cancel()
		switch {
		case err != nil && !sdpc.IsSessionExpired(err):
			// Transport hiccup (DNS, timeout, 5xx): keep the session and
			// retry on the next tick instead of burning a re-login.
			p.logger.Warn("onlineInfo probe failed; retrying next tick", "err", err)
			continue
		case err == nil && info.IsOnline:
			continue
		}
		// Drop the credential only if it is still the one we probed:
		// InvalidateIfCurrent compares and clears in one critical section,
		// so a concurrent refresh that already replaced it stays untouched.
		p.logger.Warn("session no longer online, re-logging in silently", "err", err)
		if !p.InvalidateIfCurrent(cred) {
			continue
		}
		refreshCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		_, refreshErr := p.Credential(WithInteraction(refreshCtx, false))
		cancel()
		if err := refreshErr; err != nil {
			p.logger.Error("silent re-login failed", "err", err)
		} else {
			p.logger.Info("silent re-login succeeded")
		}
	}
}

// acquire restores the persisted session or performs a full login. force
// (relogin reservation) skips restore regardless of the global flag. After
// Invalidate, the restore step is skipped once: the persisted session is
// the one the caller rejected.
func (p *Provider) acquire(ctx context.Context, force bool) (*Credential, *SessionInfo, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, false, err
	}
	p.mu.Lock()
	skipRestore := force || p.forceLogin
	p.forceLogin = false
	p.mu.Unlock()

	if !skipRestore {
		if cred, session, err := p.restore(ctx); err != nil {
			if ctx.Err() != nil {
				return nil, nil, false, ctx.Err()
			}
			if p.cfg.StrictStorage && errors.Is(err, ErrStateStorage) {
				return nil, nil, false, err
			}
			p.logger.Warn("restoring persisted session failed; performing full login", "err", err)
		} else if cred != nil {
			p.logger.Info("restored persisted session", "restored", true)
			return cred, session, true, nil
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, false, err
	}
	p.emit(Event{Kind: EventLoginStart, Message: "开始完整登录"})
	cred, session, err := p.login(ctx)
	return cred, session, false, err
}

// restore validates the persisted state via onlineInfo and rebuilds the
// routing policy. Returns (nil, nil, nil) when there is nothing to restore.
func (p *Provider) restore(ctx context.Context) (*Credential, *SessionInfo, error) {
	st, err := p.store.Load(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrStateStorage, err)
	}
	if st == nil {
		return nil, nil, nil
	}
	if st.ControllerURL != p.cfg.BaseURL || st.IdentityIssuer != p.cfg.IdentityIssuer || st.IdentitySubject != p.cfg.IdentitySubject || st.IdentityKind != p.cfg.IdentityKind || st.LoginDomain != p.cfg.LoginDomain {
		return nil, nil, nil
	}
	if st.SID == "" || len(st.Cookies) == 0 {
		return nil, nil, nil
	}
	if st.DeviceID != "" && st.DeviceID != p.cfg.DeviceID {
		p.logger.Warn("persisted session belongs to another device_id; ignoring",
			"state_device", st.DeviceID, "config_device", p.cfg.DeviceID)
		return nil, nil, nil
	}
	// reportEnv sets the server-side session mode (browser vs client).
	// Legacy states predate this field and cannot be classified safely because
	// both modes were already supported; force one fresh, tagged login.
	if st.ClientType == "" {
		p.logger.Warn("persisted session has no client_type; ignoring")
		return nil, nil, nil
	}
	if st.ClientType != p.cfg.ClientType {
		p.logger.Warn("persisted session was established in a different client_type; ignoring",
			"state_type", st.ClientType, "config_type", p.cfg.ClientType)
		return nil, nil, nil
	}

	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar, Timeout: p.httpTimeout(), Transport: p.Transport}
	sc := p.newSDPC(hc)
	cookies := make([]*http.Cookie, 0, len(st.Cookies))
	for _, rec := range st.Cookies {
		cookies = append(cookies, &http.Cookie{Name: rec.Name, Value: rec.Value})
	}
	sc.SetCookies(cookies)
	sc.SetCSRF(st.CsrfToken)

	info, err := sc.OnlineInfo(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("onlineInfo: %w", err)
	}
	if !info.IsOnline || st.Username != info.Username {
		return nil, nil, nil
	}
	cred, err := p.finishLogin(ctx, sc, info.Username)
	if err != nil {
		return nil, nil, err
	}
	cred.DisplayName = info.DisplayName
	p.logger.Info("session online", "user", info.Username, "display_name", info.DisplayName)
	return cred, newSessionInfo(info, cred, p.cfg.ClientType), nil
}

// newSDPC builds a controller client honoring the configured login path
// (client_type): "browser" keeps the unsigned browser path; "client" uses
// the desktop path (clientType=SDPClient), which marks the session as client
// mode and unlocks trusted-terminal management.
func (p *Provider) newSDPC(hc *http.Client) *sdpc.Client {
	sc := sdpc.NewClient(p.cfg.BaseURL, p.cfg.Platform, p.cfg.DeviceID, hc)
	sc.LoginDomain = p.cfg.LoginDomain
	sc.DomainMapping = p.cfg.DomainMapping
	if p.cfg.ClientType == "client" {
		sc.ClientType = sdpc.ClientTypeDesktop
	}
	return sc
}

// login retries the full authentication chain when the controller expires an
// SMS authentication session while the user is waiting. Each retry is driven
// by a resend or code submission, so a broken controller cannot create a tight
// automatic retry loop.
func (p *Provider) login(ctx context.Context) (*Credential, *SessionInfo, error) {
	for {
		cred, session, err := p.loginOnce(ctx)
		if !errors.Is(err, errSMSAuthSessionExpired) {
			return cred, session, err
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, nil, ctxErr
		}
		p.logger.Warn("SMS authentication session expired; restarting full login", "err", err)
		p.emit(Event{Kind: EventLoginStart, Message: "短信验证会话已过期，正在重新建立登录会话"})
	}
}

// loginOnce runs one full sequence: IDS passkey → CAS → reportEnv → authCheck
// (→ SMS when requested) → session exchange → clientResource.
func (p *Provider) loginOnce(ctx context.Context) (*Credential, *SessionInfo, error) {
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar, Timeout: p.httpTimeout(), Transport: p.Transport}
	authenticate := p.Authenticate
	if authenticate == nil {
		authenticate = func(ctx context.Context, hc *http.Client) (string, error) {
			ks, err := idsauth.LoadKeystore(p.cfg.Keystore)
			if err != nil {
				return "", err
			}
			if err = idsauth.NewClient(ks, hc).Login(ctx); err != nil {
				return "", err
			}
			return ks.Username(), nil
		}
	}
	if _, err := authenticate(ctx, hc); err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrIdentityAuthentication, err)
	}
	sc := p.newSDPC(hc)
	ac, err := sc.AuthConfig(ctx, true)
	if err != nil {
		return nil, nil, err
	}
	casTicket, err := sc.CasTicket(ctx)
	if err != nil {
		return nil, nil, err
	}
	if err := sc.ReportEnv(ctx, casTicket, ac); err != nil {
		return nil, nil, err
	}
	needSMS, err := sc.AuthCheck(ctx)
	if err != nil {
		return nil, nil, err
	}

	var sidTicket string
	if needSMS {
		sidTicket, err = p.smsFlow(ctx, sc)
	} else {
		p.logger.Info("controller did not request SMS; device is already trusted")
		sidTicket, err = sc.TicketExchange(ctx)
	}
	if err != nil {
		return nil, nil, err
	}
	if err := sc.SessionIDExchange(ctx, sidTicket); err != nil {
		return nil, nil, err
	}
	if sc.SID() == "" {
		return nil, nil, errors.New("sessionIdExchange did not establish a sid cookie")
	}
	info, err := sc.OnlineInfo(ctx)
	if err != nil {
		return nil, nil, err
	}
	if !info.IsOnline {
		return nil, nil, errors.New("onlineInfo reports offline after session exchange")
	}
	p.logger.Info("session established", "user", info.Username, "display_name", info.DisplayName)

	cred, err := p.finishLogin(ctx, sc, info.Username)
	if err != nil {
		return nil, nil, err
	}
	cred.DisplayName = info.DisplayName
	return cred, newSessionInfo(info, cred, p.cfg.ClientType), nil
}

// smsFlow completes controller-requested SMS verification.
func (p *Provider) smsFlow(ctx context.Context, sc *sdpc.Client) (string, error) {
	if !InteractionAllowed(ctx) || (p.smsHandler == nil && p.prompt == nil && p.ChallengeHandler == nil) {
		return "", &auth.RequiredError{Challenge: auth.Challenge{Info: auth.ChallengeInfo{Method: auth.SMS}}}
	}
	if err := sc.SendSMS(ctx); err != nil {
		// 75500401: a code was already sent and is still valid — verify it
		// instead of failing (a retried login must not demand a new SMS).
		var apiErr *sdpc.APIError
		if !errors.As(err, &apiErr) || apiErr.Code != sdpc.CodeSMSStillValid {
			return "", fmt.Errorf("send sms: %w", err)
		}
		p.logger.Info("SMS code still valid from a previous attempt; reusing it")
	}
	var code string
	var promptErr error
	if p.ChallengeHandler != nil {
		challengeCtx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		ctx = challengeCtx
		expires, _ := challengeCtx.Deadline()
		return p.challengeFlow(challengeCtx, sc, expires)
	} else if p.smsHandler != nil {
		// Keep typed controller errors for the web layer. An expired auth
		// session also carries the private restart marker consumed by login.
		authenticationCtx := ctx
		resendFn := func(parent context.Context) error {
			call, cancel := context.WithCancel(parent)
			stop := context.AfterFunc(authenticationCtx, cancel)
			defer func() { stop(); cancel() }()
			err := sc.SendSMS(call)
			if sdpc.IsSessionExpired(err) {
				return fmt.Errorf("%w: resend SMS: %w", errSMSAuthSessionExpired, err)
			}
			return err
		}
		code, promptErr = p.smsHandler.Prompt(ctx, resendFn)
	} else {
		code, promptErr = p.prompt(ctx)
	}
	if promptErr != nil {
		return "", promptErr
	}
	ticket, err := sc.CheckSMSCode(ctx, code)
	if err != nil {
		if sdpc.IsSessionExpired(err) {
			return "", fmt.Errorf("%w: check sms code: %w", errSMSAuthSessionExpired, err)
		}
		return "", fmt.Errorf("check sms code: %w", err)
	}
	return ticket, nil
}

// finishLogin pulls clientResource, assembles the Credential and persists the
// state file. Routing always uses the current policy and explicit configuration.
func (p *Provider) finishLogin(ctx context.Context, sc *sdpc.Client, username string) (*Credential, error) {
	res, err := sc.ClientResource(ctx)
	if err != nil {
		return nil, fmt.Errorf("clientResource: %w", err)
	}
	p.logger.Info("resource policy loaded",
		"domain_rules", len(res.DomainRules), "suffix_rules", len(res.SuffixRules), "ip_rules", len(res.IPRules))
	gateways := p.cfg.Gateways
	if !p.cfg.GatewayFilter && !p.cfg.LegacyGatewayOverride {
		gateways = res.Gateways
	}
	if len(gateways) == 0 && !p.cfg.GatewayFilter {
		gateways = append([]string(nil), p.cfg.Compatibility.FallbackGateways...)
	}
	if len(gateways) == 0 {
		return nil, fmt.Errorf("controller supplied no gateway addresses")
	}
	if p.cfg.GatewayFilter {
		candidates := res.Gateways
		if len(candidates) == 0 {
			candidates = p.cfg.Compatibility.FallbackGateways
		}
		gateways = nil
		for _, candidate := range candidates {
			for _, allowed := range p.cfg.Gateways {
				if candidate == allowed {
					gateways = append(gateways, candidate)
					break
				}
			}
		}
	}
	dns := p.cfg.DNS
	if !p.cfg.DNSConfigured && len(dns) == 0 {
		dns = res.DNS
	}

	cred := &Credential{
		LegacyGatewayOverride:       p.cfg.LegacyGatewayOverride,
		ProcessIdentity:             p.cfg.Compatibility.ProcessIdentity,
		AppID:                       p.cfg.Compatibility.FallbackAppID,
		MissingGatewayGroupFallback: p.cfg.Compatibility.MissingGatewayGroupFallback,
		AllowTCPFallback:            p.cfg.Compatibility.TCPToL3Fallback,
		GatewayOverride:             p.cfg.GatewayFilter,
		SID:                         sc.SID(),
		DeviceID:                    p.cfg.DeviceID,
		Username:                    username,
		ConnectionID:                fmt.Sprintf("%X-%d", md5.Sum([]byte(p.cfg.DeviceID)), time.Now().UnixMicro()),
		CsrfToken:                   sc.CSRF(),
		Cookies:                     sc.Cookies(),
		Gateways:                    gateways,
		DNS:                         dns,
		Policy:                      res,
	}

	records := make([]CookieRecord, 0, len(cred.Cookies))
	for _, ck := range cred.Cookies {
		records = append(records, CookieRecord{Name: ck.Name, Value: ck.Value})
	}
	if err := p.store.Save(ctx, &State{
		Version: 1, ControllerURL: p.cfg.BaseURL, IdentityIssuer: p.cfg.IdentityIssuer, IdentitySubject: p.cfg.IdentitySubject, IdentityKind: p.cfg.IdentityKind, LoginDomain: p.cfg.LoginDomain, Username: username,
		SID:        cred.SID,
		DeviceID:   cred.DeviceID,
		CsrfToken:  cred.CsrfToken,
		Cookies:    records,
		Gateways:   cred.Gateways,
		ClientType: p.cfg.ClientType,
	}); err != nil {
		if p.cfg.StrictStorage {
			return nil, err
		}
		// Legacy callers retain their persistence behavior.
		p.logger.Error("failed to persist session state", "err", err)
	}

	p.mu.Lock()
	p.sdpc = sc
	p.mu.Unlock()
	return cred, nil
}

// ShortSID redacts a session id for logs and command output: the sid is a
// bearer credential and must not appear in full outside the state file.
func ShortSID(sid string) string { return "[redacted]" }

// CloseObservers releases the bounded lifecycle dispatcher. Call after canceling
// the owner's network operations. Late events are ignored.
func (p *Provider) CloseObservers() {
	p.dispMu.Lock()
	defer p.dispMu.Unlock()
	p.dispClosed = true
	p.dispQueue = nil
	if p.dispCond != nil {
		p.dispCond.Broadcast()
	}
}
