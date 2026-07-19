package idsauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DefaultUserAgent matches the Python library's default browser UA.
const DefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
	"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0"

var executionRe = regexp.MustCompile(`name="execution" value="([^"]+)"`)

// Client performs IDS passkey logins. The HTTP client should carry a cookie
// jar: after Login it holds the IDS session (CASTGC), which the VPN control
// plane reuses for the CAS redirect chain.
type Client struct {
	Keystore *Keystore
	HTTP     *http.Client
	// BaseURL is the IDS root, e.g. https://ids.shanghaitech.edu.cn.
	// Defaults to the keystore's recorded base_url.
	BaseURL string
	// Origin is the WebAuthn origin. Defaults to BaseURL.
	Origin    string
	UserAgent string
}

// NewClient builds a Client with defaults filled in.
func NewClient(ks *Keystore, httpClient *http.Client) *Client {
	base := strings.TrimRight(ks.BaseURL(), "/")
	return &Client{
		Keystore:  ks,
		HTTP:      httpClient,
		BaseURL:   base,
		Origin:    base,
		UserAgent: DefaultUserAgent,
	}
}

// Login runs the full passkey login: fetch execution, startAssertion, sign the
// challenge, POST the login form, verify the session, and persist the
// incremented sign_count back to the keystore file.
func (c *Client) Login(ctx context.Context) error {
	execution, err := c.getExecution(ctx)
	if err != nil {
		return err
	}
	responseJSON, err := c.buildResponseJSON(ctx)
	if err != nil {
		return err
	}

	form := url.Values{
		"_eventId":     {"submit"},
		"responseJson": {string(responseJSON)},
		"username":     {encodeUsername(c.Keystore.Username())},
		"cllt":         {"fidoLogin"},
		"dllt":         {"generalLogin"},
		"lt":           {""},
		"execution":    {execution},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/authserver/login",
		strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.do(req)
	if err != nil {
		return fmt.Errorf("ids login: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("ids login: HTTP %d", resp.StatusCode)
	}

	loggedIn, err := c.IsLoggedIn(ctx)
	if err != nil {
		return err
	}
	if !loggedIn {
		return fmt.Errorf("ids login: session not established (login page did not accept the assertion)")
	}
	// Persist the incremented sign_count only after a verified login.
	if err := c.Keystore.Save(); err != nil {
		return fmt.Errorf("ids login: persist keystore: %w", err)
	}
	return nil
}

// IsLoggedIn checks whether the current cookies form a valid IDS session.
func (c *Client) IsLoggedIn(ctx context.Context) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.BaseURL+"/personalInfo/common/tenant/info?t="+strconv.FormatInt(time.Now().Unix(), 10), nil)
	if err != nil {
		return false, err
	}
	resp, err := c.doNoRedirect(req)
	if err != nil {
		return false, fmt.Errorf("ids session check: %w", err)
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK, nil
}

// getExecution fetches the login page and extracts the `execution` hidden
// field required by the CAS form.
func (c *Client) getExecution(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/authserver/login", nil)
	if err != nil {
		return "", err
	}
	resp, err := c.do(req)
	if err != nil {
		return "", fmt.Errorf("fetch login page: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("fetch login page: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return "", fmt.Errorf("read login page: %w", err)
	}
	m := executionRe.FindSubmatch(body)
	if m == nil {
		return "", fmt.Errorf("fetch login page: no execution field found (already logged in or page layout changed)")
	}
	return string(m[1]), nil
}

// buildResponseJSON calls startAssertion and signs the challenge, returning
// the wrapped {"requestId", "credential", "sessionToken"} JSON payload.
func (c *Client) buildResponseJSON(ctx context.Context) ([]byte, error) {
	startBody, err := marshalNoEscape(map[string]string{
		"userId": encodeUsername(c.Keystore.Username()),
		"id":     c.Keystore.AnonBiometricsID(),
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/authserver/startAssertion",
		strings.NewReader(string(startBody)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json;charset=utf-8")
	resp, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("startAssertion: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("startAssertion: HTTP %d", resp.StatusCode)
	}
	var parsed struct {
		Result struct {
			Request map[string]any `json:"request"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("startAssertion: decode response: %w", err)
	}
	requestOptions, _ := parsed.Result.Request["publicKeyCredentialRequestOptions"].(map[string]any)
	if requestOptions == nil {
		return nil, fmt.Errorf("startAssertion: missing result.request.publicKeyCredentialRequestOptions")
	}
	requestID := parsed.Result.Request["requestId"]

	assertionJSON, newCount, err := buildAssertion(requestOptions, c.Keystore, c.Origin)
	if err != nil {
		return nil, fmt.Errorf("startAssertion: %w", err)
	}
	// The counter advanced whether or not the login POST below succeeds;
	// keeping the in-memory value monotonic is safe for the next attempt.
	c.Keystore.SetSignCount(newCount)

	var cred any
	if err := json.Unmarshal(assertionJSON, &cred); err != nil {
		return nil, err
	}
	// sessionToken must serialize as JSON null, not be omitted.
	wrapped := map[string]any{
		"requestId":    requestID,
		"credential":   cred,
		"sessionToken": nil,
	}
	return marshalNoEscape(wrapped)
}

func (c *Client) do(req *http.Request) (*http.Response, error) {
	c.setHeaders(req)
	return c.HTTP.Do(req)
}

// doNoRedirect performs a request without following redirects, regardless of
// the shared client's CheckRedirect hook. It shallow-copies the http.Client
// (sharing Transport and Jar) so the shared instance is never mutated.
func (c *Client) doNoRedirect(req *http.Request) (*http.Response, error) {
	c.setHeaders(req)
	noRedirect := *c.HTTP
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return noRedirect.Do(req)
}

func (c *Client) setHeaders(req *http.Request) {
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
}

// encodeUsername base64-encodes the username as the IDS API expects
// (standard alphabet, padded).
func encodeUsername(username string) string {
	return base64.StdEncoding.EncodeToString([]byte(username))
}
