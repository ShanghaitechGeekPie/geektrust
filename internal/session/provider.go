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

	"geektrust/internal/config"
	"geektrust/internal/idsauth"
	"geektrust/internal/sdpc"
)

// DefaultGateways are the well-known external gateway lines, used when
// neither config nor clientResource provides any.
var DefaultGateways = []string{"119.78.254.241:441", "59.78.171.241:441"}

// Credential is everything the tunnel and resolver need from a live session.
type Credential struct {
	SID          string
	DeviceID     string
	Username     string
	ConnectionID string
	CsrfToken    string
	Cookies      []*http.Cookie
	Gateways     []string
	DNS          []string
	// Policy is the full routing policy (domain/IP/CIDR × port → appId)
	// from clientResource.
	Policy *sdpc.Resource
	AppID  string
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
	cfg        *config.Config
	logger     *slog.Logger
	prompt     SMSPrompter
	smsHandler SMSHandler // set by SetSMSHandler during web wiring
	store      *Store

	mu         sync.Mutex
	cur        *Credential
	sdpc       *sdpc.Client // last client, for liveness checks
	refreshing *refreshCall
	forceLogin bool // set by Invalidate; skips restore on the next refresh

	dispMu      sync.Mutex
	dispCond    *sync.Cond // lazily created on first AddObserver
	dispQueue   []Event
	dispDropped uint64
	observers   []Observer
	dispStarted bool
}

// refreshCall is one in-flight restore/login shared by every concurrent
// caller: all waiters block on done and then read the same result.
type refreshCall struct {
	done    chan struct{} // closed once cred/err are populated
	cred    *Credential
	err     error
	waiters int // joined callers (observability for tests; guarded by p.mu)
}

// NewProvider builds a credential provider. prompt may be nil; a login that
// requires SMS then returns an error.
func NewProvider(cfg *config.Config, logger *slog.Logger, prompt SMSPrompter) *Provider {
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
	if len(p.observers) == 0 {
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
		for len(p.dispQueue) == 0 {
			p.dispCond.Wait()
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
	p.mu.Lock()
	if p.cur != nil {
		cred := p.cur
		p.mu.Unlock()
		return cred, nil
	}
	call := p.refreshing
	if call == nil {
		call = &refreshCall{done: make(chan struct{})}
		p.refreshing = call
		p.mu.Unlock()

		cred, session, restored, err := p.acquire(ctx, false)
		p.finishRefresh(call, cred, session, restored, err)
		return cred, err
	}
	call.waiters++
	p.mu.Unlock()
	select {
	case <-call.done:
		return call.cred, call.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// finishRefresh publishes the acquisition result under p.mu and only then
// queues the lifecycle event, so observers can never see "online" while
// ActiveSDPC still returns nil. Events are queued under the lock (emit
// never callbacks), then waiters are released.
func (p *Provider) finishRefresh(call *refreshCall, cred *Credential, session *SessionInfo, restored bool, err error) {
	p.mu.Lock()
	if err == nil {
		p.cur = cred
		if restored {
			p.emit(Event{Kind: EventRestoreOK, Session: session, Message: "已恢复会话: " + session.DisplayName})
		} else {
			p.emit(Event{Kind: EventLoginSuccess, Session: session, Message: "会话已建立: " + session.DisplayName})
		}
	} else {
		p.emit(Event{Kind: EventLoginFailed, Message: SanitizeErrorText(err.Error())})
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
	if p.refreshing != nil {
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
		if _, err := p.Credential(ctx); err != nil {
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
	p.mu.Lock()
	skipRestore := force || p.forceLogin
	p.forceLogin = false
	p.mu.Unlock()

	if !skipRestore {
		if cred, session, err := p.restore(ctx); err != nil {
			p.logger.Warn("restoring persisted session failed; performing full login", "err", err)
		} else if cred != nil {
			p.logger.Info("restored persisted session", "sid", ShortSID(cred.SID))
			return cred, session, true, nil
		}
	}
	p.emit(Event{Kind: EventLoginStart, Message: "开始完整登录"})
	cred, session, err := p.login(ctx)
	return cred, session, false, err
}

// restore validates the persisted state via onlineInfo and rebuilds the
// routing policy. Returns (nil, nil, nil) when there is nothing to restore.
func (p *Provider) restore(ctx context.Context) (*Credential, *SessionInfo, error) {
	st, err := p.store.Load()
	if err != nil || st == nil {
		return nil, nil, err
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
	hc := &http.Client{Jar: jar, Timeout: 30 * time.Second}
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
	if !info.IsOnline {
		return nil, nil, errors.New("persisted session is offline")
	}
	cred, err := p.finishLogin(ctx, sc, st.Gateways, info.Username)
	if err != nil {
		return nil, nil, err
	}
	p.logger.Info("session online", "user", info.Username, "display_name", info.DisplayName)
	return cred, newSessionInfo(info, cred, p.cfg.ClientType), nil
}

// newSDPC builds a controller client honoring the configured login path
// (client_type): "browser" keeps the unsigned browser path; "client" uses
// the desktop path (clientType=SDPClient), which marks the session as client
// mode and unlocks trusted-terminal management.
func (p *Provider) newSDPC(hc *http.Client) *sdpc.Client {
	sc := sdpc.NewClient(p.cfg.BaseURL, p.cfg.Platform, p.cfg.DeviceID, hc)
	if p.cfg.ClientType == "client" {
		sc.ClientType = sdpc.ClientTypeDesktop
	}
	return sc
}

// login runs the full sequence: IDS passkey → CAS → reportEnv → authCheck
// (→ SMS when requested) → session exchange → clientResource.
func (p *Provider) login(ctx context.Context) (*Credential, *SessionInfo, error) {
	ks, err := idsauth.LoadKeystore(p.cfg.Keystore)
	if err != nil {
		return nil, nil, err
	}
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar, Timeout: 30 * time.Second}

	p.logger.Info("logging in via IDS passkey", "user", ks.Username())
	ids := idsauth.NewClient(ks, hc)
	if err := ids.Login(ctx); err != nil {
		return nil, nil, fmt.Errorf("ids login: %w", err)
	}
	p.logger.Info("IDS passkey login ok")

	sc := p.newSDPC(hc)
	ac, err := sc.AuthConfig(ctx)
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

	// On the desktop path the session is in client mode: bind this device
	// as a trusted terminal so subsequent full logins may skip SMS. The
	// browser path cannot bind (server rejects with 75500000).
	if needSMS && sc.ClientType == sdpc.ClientTypeDesktop {
		if err := sc.TrustDevice(ctx); err != nil {
			p.logger.Warn("trust device binding failed; SMS will be required on next full login", "err", err)
		} else {
			p.logger.Info("device bound as trusted terminal")
		}
	}
	cred, err := p.finishLogin(ctx, sc, nil, info.Username)
	if err != nil {
		return nil, nil, err
	}
	return cred, newSessionInfo(info, cred, p.cfg.ClientType), nil
}

// smsFlow completes controller-requested SMS verification.
func (p *Provider) smsFlow(ctx context.Context, sc *sdpc.Client) (string, error) {
	if p.smsHandler == nil && p.prompt == nil {
		return "", errors.New("the controller requires SMS verification, but no prompt is available")
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
	if p.smsHandler != nil {
		// resendFn keeps the typed *sdpc.APIError so the web layer can map
		// 75500401 to HTTP 429.
		resendFn := func(ctx context.Context) error { return sc.SendSMS(ctx) }
		code, promptErr = p.smsHandler.Prompt(ctx, resendFn)
	} else {
		code, promptErr = p.prompt(ctx)
	}
	if promptErr != nil {
		return "", promptErr
	}
	ticket, err := sc.CheckSMSCode(ctx, code)
	if err != nil {
		return "", fmt.Errorf("check sms code: %w", err)
	}
	return ticket, nil
}

// finishLogin pulls clientResource, assembles the Credential and persists the
// state file. gatewaysOverride comes from the persisted state (if any).
func (p *Provider) finishLogin(ctx context.Context, sc *sdpc.Client, gatewaysOverride []string, username string) (*Credential, error) {
	res, err := sc.ClientResource(ctx)
	if err != nil {
		return nil, fmt.Errorf("clientResource: %w", err)
	}
	p.logger.Info("resource policy loaded",
		"domain_rules", len(res.DomainRules), "suffix_rules", len(res.SuffixRules), "ip_rules", len(res.IPRules))
	gateways := p.cfg.Gateways
	if len(gateways) == 0 {
		gateways = res.Gateways
	}
	if len(gateways) == 0 && len(gatewaysOverride) > 0 {
		gateways = gatewaysOverride
	}
	if len(gateways) == 0 {
		gateways = DefaultGateways
	}
	dns := p.cfg.DNS
	if len(dns) == 0 {
		dns = res.DNS
	}

	cred := &Credential{
		SID:          sc.SID(),
		DeviceID:     p.cfg.DeviceID,
		Username:     username,
		ConnectionID: fmt.Sprintf("%X-%d", md5.Sum([]byte(p.cfg.DeviceID)), time.Now().UnixMicro()),
		CsrfToken:    sc.CSRF(),
		Cookies:      sc.Cookies(),
		Gateways:     gateways,
		DNS:          dns,
		Policy:       res,
		AppID:        p.cfg.AppID,
	}

	records := make([]CookieRecord, 0, len(cred.Cookies))
	for _, ck := range cred.Cookies {
		records = append(records, CookieRecord{Name: ck.Name, Value: ck.Value})
	}
	if err := p.store.Save(&State{
		SID:        cred.SID,
		DeviceID:   cred.DeviceID,
		CsrfToken:  cred.CsrfToken,
		Cookies:    records,
		Gateways:   cred.Gateways,
		ClientType: p.cfg.ClientType,
	}); err != nil {
		// Credentials are live; persistence failure should not abort the login.
		p.logger.Error("failed to persist session state", "err", err)
	}

	p.mu.Lock()
	p.sdpc = sc
	p.mu.Unlock()
	return cred, nil
}

// ShortSID redacts a session id for logs and command output: the sid is a
// bearer credential and must not appear in full outside the state file.
func ShortSID(sid string) string {
	if len(sid) > 12 {
		return sid[:12] + "…"
	}
	return sid
}
