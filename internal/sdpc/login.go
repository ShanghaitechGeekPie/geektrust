package sdpc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// CasTicket runs the CAS redirect chain (TECHNICAL.md §3.3):
//
//	GET /passport/v1/public/casLogin?sfDomain=Shanghaitech.edu.cn
//	  302 → IDS (session/CASTGC from the passkey login is sent by the jar)
//	  302 → /passport/v1/auth/cas?ticket=ST-…
//	  302 → /portal/shortcut.html?…&data={"ticket":"<casTicket>",…}
//
// and returns the casTicket needed by reportEnv.
func (c *Client) CasTicket(ctx context.Context) (string, error) {
	// casLogin is a /passport/v1 endpoint: the shared query parameters are
	// mandatory (TECHNICAL.md §2.3), and the csrf header exists by now.
	q := url.Values{}
	q.Set("sfDomain", "Shanghaitech.edu.cn")
	q.Set("clientType", ClientTypeBrowser)
	q.Set("platform", c.Platform)
	q.Set("lang", DefaultLang)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.BaseURL+"/passport/v1/public/casLogin?"+q.Encode(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", UserAgent)
	if c.csrf != "" {
		req.Header.Set("x-csrf-token", c.csrf)
	}

	base, err := url.Parse(c.BaseURL)
	if err != nil {
		return "", err
	}
	var shortcutURL *url.URL
	noFollow := *c.HTTP
	noFollow.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if r.URL.Path == "/portal/shortcut.html" {
			shortcutURL = r.URL
			return http.ErrUseLastResponse
		}
		// Never leak the controller CSRF token to the IDS hop.
		if r.URL.Host != base.Host {
			r.Header.Del("x-csrf-token")
		}
		if len(via) >= 10 {
			return fmt.Errorf("cas chain: too many redirects")
		}
		return nil
	}
	resp, err := noFollow.Do(req)
	if err != nil {
		return "", fmt.Errorf("cas chain: %w", err)
	}
	resp.Body.Close()

	if shortcutURL == nil {
		// Some deployments serve shortcut.html directly as the final 200.
		if resp.Request != nil && resp.Request.URL.Path == "/portal/shortcut.html" {
			shortcutURL = resp.Request.URL
		}
	}
	if shortcutURL == nil {
		return "", fmt.Errorf("cas chain: never reached /portal/shortcut.html (IDS session invalid?)")
	}

	dataParam := shortcutURL.Query().Get("data")
	if dataParam == "" {
		return "", fmt.Errorf("cas chain: shortcut.html missing data parameter")
	}
	var data struct {
		Ticket string `json:"ticket"`
	}
	if err := json.Unmarshal([]byte(dataParam), &data); err != nil {
		return "", fmt.Errorf("cas chain: decode data parameter: %w", err)
	}
	if data.Ticket == "" {
		return "", fmt.Errorf("cas chain: empty casTicket in data parameter")
	}
	return data.Ticket, nil
}

// ReportEnv posts the environment report (TECHNICAL.md §3.4). Skipping it
// makes authCheck fail with 75599999. Must run before the session exists;
// CodeAlreadyLogged means a session is already up, which is fine.
func (c *Client) ReportEnv(ctx context.Context, casTicket string, ac *AuthConfig) error {
	body := map[string]any{
		"ticket": casTicket,
		"timing": "pre-login",
		"env": map[string]any{
			"endpoint": map[string]any{
				"device_id": c.DeviceID,
				"device":    map[string]string{"type": "browser"},
			},
		},
		"antiMITMAttackData": map[string]any{
			"enable":          0,
			"devicePubKeyMod": ac.DevicePubKeyMod,
			"devicePubKeyExp": ac.DevicePubKeyExp,
			"rsaCert":         ac.RsaCert,
		},
	}
	err := c.doJSON(ctx, "POST", "/controller/v1/public/reportEnv", url.Values{}, body, nil)
	if apiErr, ok := err.(*APIError); ok && apiErr.Code == CodeAlreadyLogged {
		return nil
	}
	return err
}

// AuthCheck reports whether the device still needs SMS second factor
// (TECHNICAL.md §3.5). Trusted devices pass directly. nextService is the
// server's selected route; the list is only consulted when it is absent.
func (c *Client) AuthCheck(ctx context.Context) (needSMS bool, err error) {
	var data struct {
		NextService     string `json:"nextService"`
		NextServiceList []struct {
			AuthType string `json:"authType"`
		} `json:"nextServiceList"`
	}
	if err := c.doJSON(ctx, "GET", "/passport/v1/auth/authCheck", url.Values{}, nil, &data); err != nil {
		return false, err
	}
	if data.NextService != "" {
		return data.NextService == "auth/sms", nil
	}
	for _, item := range data.NextServiceList {
		if item.AuthType == "auth/sms" {
			return true, nil
		}
	}
	return false, nil
}

// SendSMS triggers the verification text (TECHNICAL.md §3.6).
func (c *Client) SendSMS(ctx context.Context) error {
	q := url.Values{"action": {"sendsms"}}
	return c.doJSON(ctx, "POST", "/passport/v1/auth/sms", q, map[string]any{}, nil)
}

// CheckSMSCode verifies the code and returns the sidTicket. Codes expire in
// 60 seconds and are single-use.
func (c *Client) CheckSMSCode(ctx context.Context, code string) (string, error) {
	q := url.Values{"action": {"checkcode"}}
	var data struct {
		SidTicket string `json:"sidTicket"`
	}
	err := c.doJSON(ctx, "POST", "/passport/v1/auth/sms", q, map[string]string{"code": code}, &data)
	if err != nil {
		return "", err
	}
	if data.SidTicket == "" {
		return "", fmt.Errorf("checkcode: response missing sidTicket")
	}
	return data.SidTicket, nil
}

// TicketExchange converts the logged-in state into a sidTicket
// (TECHNICAL.md §3.7, trusted-device path).
func (c *Client) TicketExchange(ctx context.Context) (string, error) {
	var data struct {
		SidTicket string `json:"sidTicket"`
	}
	if err := c.doJSON(ctx, "POST", "/passport/v1/public/ticketExchange", url.Values{}, map[string]any{}, &data); err != nil {
		return "", err
	}
	if data.SidTicket == "" {
		return "", fmt.Errorf("ticketExchange: response missing sidTicket")
	}
	return data.SidTicket, nil
}

// SessionIDExchange establishes the sid session from a sidTicket
// (TECHNICAL.md §3.7). The sid cookie lands in the jar.
func (c *Client) SessionIDExchange(ctx context.Context, sidTicket string) error {
	return c.doJSON(ctx, "POST", "/passport/v1/public/sessionIdExchange", url.Values{},
		map[string]string{"sidTicket": sidTicket}, nil)
}

// OnlineInfo is the session liveness probe (TECHNICAL.md §3.8).
type OnlineInfo struct {
	IsOnline    bool   `json:"isOnline"`
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
	ClientIP    string `json:"clientIp"`
}

// OnlineInfo reports whether the current session is live.
func (c *Client) OnlineInfo(ctx context.Context) (*OnlineInfo, error) {
	var data OnlineInfo
	if err := c.doJSON(ctx, "GET", "/passport/v1/user/onlineInfo", url.Values{}, nil, &data); err != nil {
		return nil, err
	}
	return &data, nil
}
