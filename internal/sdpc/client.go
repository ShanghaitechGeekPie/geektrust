// Package sdpc implements the aTrust SDP controller (SDPC) control plane:
// authConfig, CAS login chain, reportEnv, authCheck, SMS second factor,
// session exchange, onlineInfo and clientResource (TECHNICAL.md §3–§4).
//
// It uses the browser path (clientType=SDPBrowserClient), which requires no
// request signing (X-Request-Sig).
package sdpc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// ClientTypeBrowser is the unsigned browser client path.
const ClientTypeBrowser = "SDPBrowserClient"

// DefaultLang is the language parameter for every control-plane call.
const DefaultLang = "zh-CN"

// UserAgent mimics a desktop browser, matching the reference implementation.
const UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
	"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0"

// Control-plane error codes (TECHNICAL.md §11.1).
const (
	CodeOK             = 0
	CodeAlreadyLogged  = 10000000 // user has been logged in
	CodeInvalidParam   = 10000001
	CodeSessionMissing = 10000004 // session not found
	CodeSigVerify      = 10000008
	CodeAuthTimeout    = 75500001 // 当前认证已超时
	CodeSessionInvalid = 75500002 // 会话无效/未登录
	CodeAlreadyOnline  = 75500006
	CodeTicketExpired  = 75500304
	CodeOpAbnormal     = 75599999 // reportEnv 前置未完成
)

// APIError is a non-zero controller response code.
type APIError struct {
	Op      string
	Code    int64
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("sdpc %s: code %d: %s", e.Op, e.Code, e.Message)
}

// IsSessionExpired reports whether the error means the session is gone and a
// re-login is required.
func IsSessionExpired(err error) bool {
	apiErr, ok := err.(*APIError)
	if !ok {
		return false
	}
	switch apiErr.Code {
	case CodeSessionInvalid, CodeAuthTimeout, CodeSessionMissing, CodeTicketExpired:
		return true
	}
	return false
}

// Client talks to the SDPC controller over the browser path. The HTTP client
// must carry a cookie jar; the session cookies (sid & friends) live there.
type Client struct {
	BaseURL  string
	Platform string
	DeviceID string
	HTTP     *http.Client
	csrf     string
}

// NewClient builds a controller client. deviceID is the persistent 32-hex
// uppercase device identifier.
func NewClient(baseURL, platform, deviceID string, hc *http.Client) *Client {
	return &Client{BaseURL: baseURL, Platform: platform, DeviceID: deviceID, HTTP: hc}
}

// CSRF returns the current csrf token (from the last authConfig).
func (c *Client) CSRF() string { return c.csrf }

// SetCSRF restores a persisted token (e.g. from the encrypted state file).
func (c *Client) SetCSRF(token string) { c.csrf = token }

// Cookies returns the controller cookies currently in the jar.
func (c *Client) Cookies() []*http.Cookie {
	u, err := url.Parse(c.BaseURL)
	if err != nil || c.HTTP.Jar == nil {
		return nil
	}
	return c.HTTP.Jar.Cookies(u)
}

// SetCookies installs persisted cookies into the jar.
func (c *Client) SetCookies(cookies []*http.Cookie) {
	if c.HTTP.Jar == nil || len(cookies) == 0 {
		return
	}
	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return
	}
	c.HTTP.Jar.SetCookies(u, cookies)
}

// SID reads the sid cookie established by sessionIdExchange.
func (c *Client) SID() string {
	for _, ck := range c.Cookies() {
		if ck.Name == "sid" {
			return ck.Value
		}
	}
	return ""
}

// envelope is the standard controller response wrapper.
type envelope struct {
	Code    int64           `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

// doJSON performs a control-plane request with the mandatory query parameters
// and headers, checks the envelope code, and decodes data into out (if set).
func (c *Client) doJSON(ctx context.Context, method, path string, query url.Values, body, out any) error {
	if query == nil {
		query = url.Values{}
	}
	query.Set("clientType", ClientTypeBrowser)
	query.Set("platform", c.Platform)
	query.Set("lang", DefaultLang)

	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = json.Marshal(body)
		if err != nil {
			return fmt.Errorf("sdpc %s: encode body: %w", path, err)
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path+"?"+query.Encode(), bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("sdpc %s: %w", path, err)
	}
	req.Header.Set("User-Agent", UserAgent)
	if c.csrf != "" {
		req.Header.Set("x-csrf-token", c.csrf)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json;charset=utf-8")
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("sdpc %s: %w", path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return fmt.Errorf("sdpc %s: read response: %w", path, err)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("sdpc %s: HTTP %d: %s", path, resp.StatusCode, truncate(raw, 256))
	}

	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("sdpc %s: decode envelope: %w (body %s)", path, err, truncate(raw, 256))
	}
	if env.Code != CodeOK {
		return &APIError{Op: path, Code: env.Code, Message: env.Message}
	}
	if out != nil && len(env.Data) > 0 && string(env.Data) != "null" {
		if err := json.Unmarshal(env.Data, out); err != nil {
			return fmt.Errorf("sdpc %s: decode data: %w", path, err)
		}
	}
	return nil
}

func truncate(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	return string(b)
}
