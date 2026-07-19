package session

import (
	"context"
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

// DefaultGateways are the well-known external gateway lines
// (TECHNICAL.md §2.1), used when neither config nor clientResource provides
// any.
var DefaultGateways = []string{"119.78.254.241:441", "59.78.171.241:441"}

// Credential is everything the tunnel and resolver need from a live session.
type Credential struct {
	SID       string
	DeviceID  string
	CsrfToken string
	Cookies   []*http.Cookie
	Gateways  []string
	DNS       []string
	DomainMap map[string]sdpc.AppEndpoint
	IPApps    map[string]string
	AppID     string
}

// SMSPrompter asks the user for the SMS verification code. It is only invoked
// on the first login of a new device_id (PLAN.md §4).
type SMSPrompter func(ctx context.Context) (string, error)

// CredentialProvider is the login↔tunnel contract (PLAN.md §2.1): consumers
// (tunnel, resolver, l3) only ever ask for valid credentials; the provider
// hides restoration, refresh and silent re-login.
type CredentialProvider interface {
	// Credential returns current valid credentials, re-logging in if needed.
	Credential(ctx context.Context) (*Credential, error)
	// Invalidate drops the cached credentials so the next call re-logs in.
	Invalidate()
}

// Provider implements the CredentialProvider contract (PLAN.md §2.1): it
// returns valid session credentials, restoring a persisted session or
// re-logging in silently (passkey; trusted devices need no SMS).
type Provider struct {
	cfg    *config.Config
	logger *slog.Logger
	prompt SMSPrompter
	store  *Store

	mu         sync.Mutex
	cur        *Credential
	sdpc       *sdpc.Client // last client, for liveness checks
	refreshing *refreshCall
	forceLogin bool // set by Invalidate; skips restore on the next refresh
}

// refreshCall is one in-flight restore/login shared by every concurrent
// caller: all waiters block on done and then read the same result.
type refreshCall struct {
	done chan struct{} // closed once cred/err are populated
	cred *Credential
	err  error
}

// NewProvider builds a credential provider. prompt may be nil only if SMS
// will never be needed (an already-trusted device_id).
func NewProvider(cfg *config.Config, logger *slog.Logger, prompt SMSPrompter) *Provider {
	return &Provider{
		cfg:    cfg,
		logger: logger,
		prompt: prompt,
		store:  NewStore(cfg.StateFile),
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

		cred, err := p.acquire(ctx)

		p.mu.Lock()
		if err == nil {
			p.cur = cred
		}
		p.refreshing = nil
		p.mu.Unlock()
		call.cred, call.err = cred, err
		close(call.done)
		return cred, err
	}
	p.mu.Unlock()
	select {
	case <-call.done:
		return call.cred, call.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// ForceLogin performs a full login, bypassing any persisted session (used by
// the `login -fresh` command). It joins the single-flight refresh so
// concurrent callers never trigger two logins.
func (p *Provider) ForceLogin(ctx context.Context) (*Credential, error) {
	p.Invalidate()
	return p.Credential(ctx)
}

// Invalidate drops the cached credential and marks the persisted session as
// rejected, so the next Credential call performs a real re-login instead of
// restoring the very session the caller declared dead.
func (p *Provider) Invalidate() {
	p.mu.Lock()
	p.cur = nil
	p.forceLogin = true
	p.mu.Unlock()
}

// CheckLoop periodically verifies the session with onlineInfo and re-logs in
// ahead of failure (PLAN.md §6.2). Run in its own goroutine.
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
		p.logger.Warn("session no longer online, re-logging in silently", "err", err)
		p.Invalidate()
		if _, err := p.Credential(ctx); err != nil {
			p.logger.Error("silent re-login failed", "err", err)
		} else {
			p.logger.Info("silent re-login succeeded")
		}
	}
}

// acquire restores the persisted session or performs a full login. After
// Invalidate, the restore step is skipped once: the persisted session is the
// one the caller rejected.
func (p *Provider) acquire(ctx context.Context) (*Credential, error) {
	p.mu.Lock()
	skipRestore := p.forceLogin
	p.forceLogin = false
	p.mu.Unlock()

	if !skipRestore {
		if cred, err := p.restore(ctx); err != nil {
			p.logger.Warn("restoring persisted session failed; performing full login", "err", err)
		} else if cred != nil {
			p.logger.Info("restored persisted session", "sid", ShortSID(cred.SID))
			return cred, nil
		}
	}
	return p.login(ctx)
}

// restore validates the persisted state via onlineInfo and rebuilds the
// resource maps. Returns (nil, nil) when there is nothing to restore.
func (p *Provider) restore(ctx context.Context) (*Credential, error) {
	st, err := p.store.Load()
	if err != nil || st == nil {
		return nil, err
	}
	if st.SID == "" || len(st.Cookies) == 0 {
		return nil, nil
	}
	if st.DeviceID != "" && st.DeviceID != p.cfg.DeviceID {
		p.logger.Warn("persisted session belongs to another device_id; ignoring",
			"state_device", st.DeviceID, "config_device", p.cfg.DeviceID)
		return nil, nil
	}

	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	sc := sdpc.NewClient(p.cfg.BaseURL, p.cfg.Platform, p.cfg.DeviceID, hc)
	cookies := make([]*http.Cookie, 0, len(st.Cookies))
	for _, rec := range st.Cookies {
		cookies = append(cookies, &http.Cookie{Name: rec.Name, Value: rec.Value})
	}
	sc.SetCookies(cookies)
	sc.SetCSRF(st.CsrfToken)

	info, err := sc.OnlineInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("onlineInfo: %w", err)
	}
	if !info.IsOnline {
		return nil, errors.New("persisted session is offline")
	}
	cred, err := p.finishLogin(ctx, sc, st.Gateways)
	if err != nil {
		return nil, err
	}
	p.logger.Info("session online", "user", info.Username, "display_name", info.DisplayName)
	return cred, nil
}

// login runs the full sequence: IDS passkey → CAS → reportEnv → authCheck
// (→ SMS on new devices) → session exchange → clientResource.
func (p *Provider) login(ctx context.Context) (*Credential, error) {
	ks, err := idsauth.LoadKeystore(p.cfg.Keystore)
	if err != nil {
		return nil, err
	}
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar, Timeout: 30 * time.Second}

	p.logger.Info("logging in via IDS passkey", "user", ks.Username())
	ids := idsauth.NewClient(ks, hc)
	if err := ids.Login(ctx); err != nil {
		return nil, fmt.Errorf("ids login: %w", err)
	}
	p.logger.Info("IDS passkey login ok")

	sc := sdpc.NewClient(p.cfg.BaseURL, p.cfg.Platform, p.cfg.DeviceID, hc)
	ac, err := sc.AuthConfig(ctx)
	if err != nil {
		return nil, err
	}
	casTicket, err := sc.CasTicket(ctx)
	if err != nil {
		return nil, err
	}
	if err := sc.ReportEnv(ctx, casTicket, ac); err != nil {
		return nil, err
	}
	needSMS, err := sc.AuthCheck(ctx)
	if err != nil {
		return nil, err
	}

	var sidTicket string
	if needSMS {
		sidTicket, err = p.smsFlow(ctx, sc)
	} else {
		p.logger.Info("device is trusted, no SMS required")
		sidTicket, err = sc.TicketExchange(ctx)
	}
	if err != nil {
		return nil, err
	}
	if err := sc.SessionIDExchange(ctx, sidTicket); err != nil {
		return nil, err
	}
	if sc.SID() == "" {
		return nil, errors.New("sessionIdExchange did not establish a sid cookie")
	}
	info, err := sc.OnlineInfo(ctx)
	if err != nil {
		return nil, err
	}
	if !info.IsOnline {
		return nil, errors.New("onlineInfo reports offline after session exchange")
	}
	p.logger.Info("session established", "user", info.Username, "display_name", info.DisplayName)
	return p.finishLogin(ctx, sc, nil)
}

// smsFlow handles the one-time new-device SMS verification (TECHNICAL.md §3.6).
func (p *Provider) smsFlow(ctx context.Context, sc *sdpc.Client) (string, error) {
	if p.prompt == nil {
		return "", errors.New("this device_id is not trusted yet and requires SMS verification, but no prompt is available")
	}
	if err := sc.SendSMS(ctx); err != nil {
		return "", fmt.Errorf("send sms: %w", err)
	}
	code, err := p.prompt(ctx)
	if err != nil {
		return "", err
	}
	ticket, err := sc.CheckSMSCode(ctx, code)
	if err != nil {
		return "", fmt.Errorf("check sms code: %w", err)
	}
	return ticket, nil
}

// finishLogin pulls clientResource, assembles the Credential and persists the
// state file. gatewaysOverride comes from the persisted state (if any).
func (p *Provider) finishLogin(ctx context.Context, sc *sdpc.Client, gatewaysOverride []string) (*Credential, error) {
	res, err := sc.ClientResource(ctx)
	if err != nil {
		return nil, fmt.Errorf("clientResource: %w", err)
	}

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
		SID:       sc.SID(),
		DeviceID:  p.cfg.DeviceID,
		CsrfToken: sc.CSRF(),
		Cookies:   sc.Cookies(),
		Gateways:  gateways,
		DNS:       dns,
		DomainMap: res.DomainMap,
		IPApps:    res.IPApps,
		AppID:     p.cfg.AppID,
	}

	records := make([]CookieRecord, 0, len(cred.Cookies))
	for _, ck := range cred.Cookies {
		records = append(records, CookieRecord{Name: ck.Name, Value: ck.Value})
	}
	if err := p.store.Save(&State{
		SID:       cred.SID,
		DeviceID:  cred.DeviceID,
		CsrfToken: cred.CsrfToken,
		Cookies:   records,
		Gateways:  cred.Gateways,
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
