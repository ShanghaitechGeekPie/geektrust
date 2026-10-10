package idsauth

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/ShanghaitechGeekPie/geektrust/internal/httporigin"
	"golang.org/x/net/html"
)

type ecnuClient struct{ *Client }

// ECNU uses an RSA-wrapped AES-ECB envelope for the challenge endpoint.
// This is the server's transport format, not credential storage encryption.
type ecnuEnvelope struct {
	key     []byte
	wrapped string
}

var transportPEM = regexp.MustCompile(`(?s)-----BEGIN PUBLIC KEY-----[A-Za-z0-9+/=\s]+-----END PUBLIC KEY-----`)

func newECNUEnvelope(script []byte) (*ecnuEnvelope, error) {
	block, _ := pem.Decode(transportPEM.Find(script))
	if block == nil {
		return nil, errors.New("missing SSO transport key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid SSO transport key")
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok || pub.N.BitLen() < 2048 {
		return nil, errors.New("unsupported SSO transport key")
	}
	key := make([]byte, 16)
	if _, err = rand.Read(key); err != nil {
		return nil, err
	}
	wrapped, err := rsa.EncryptPKCS1v15(rand.Reader, pub, []byte(base64.StdEncoding.EncodeToString(key)))
	if err != nil {
		return nil, err
	}
	return &ecnuEnvelope{key: key, wrapped: base64.StdEncoding.EncodeToString(wrapped)}, nil
}
func (e *ecnuEnvelope) encrypt(v any) ([]byte, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	n := aes.BlockSize - len(plain)%aes.BlockSize
	plain = append(plain, bytes.Repeat([]byte{byte(n)}, n)...)
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(plain); i += aes.BlockSize {
		block.Encrypt(plain[i:i+aes.BlockSize], plain[i:i+aes.BlockSize])
	}
	return []byte(base64.StdEncoding.EncodeToString(plain)), nil
}
func (e *ecnuEnvelope) decode(body []byte) (map[string]any, error) {
	for range 4 {
		var value any
		if json.Unmarshal(body, &value) == nil {
			if m, ok := value.(map[string]any); ok {
				return m, nil
			}
			if s, ok := value.(string); ok {
				body = []byte(s)
			} else {
				return nil, errors.New("invalid SSO response type")
			}
		}
		b, err := base64.StdEncoding.DecodeString(string(body))
		if err != nil || len(b) == 0 || len(b)%aes.BlockSize != 0 {
			return nil, errors.New("invalid SSO encrypted response")
		}
		block, err := aes.NewCipher(e.key)
		if err != nil {
			return nil, err
		}
		for i := 0; i < len(b); i += aes.BlockSize {
			block.Decrypt(b[i:i+aes.BlockSize], b[i:i+aes.BlockSize])
		}
		n := int(b[len(b)-1])
		if n < 1 || n > aes.BlockSize || !bytes.Equal(b[len(b)-n:], bytes.Repeat([]byte{byte(n)}, n)) {
			return nil, errors.New("invalid SSO response padding")
		}
		body = b[:len(b)-n]
	}
	return nil, errors.New("SSO response nesting limit")
}
func pageValue(body []byte, id string) string {
	root, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return ""
	}
	var content func(*html.Node) string
	content = func(n *html.Node) string {
		if n.Type == html.TextNode {
			return n.Data
		}
		s := ""
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			s += content(c)
		}
		return s
	}
	var find func(*html.Node) string
	find = func(n *html.Node) string {
		attrs := map[string]string{}
		for _, a := range n.Attr {
			attrs[a.Key] = a.Val
		}
		if attrs["id"] == id {
			return strings.TrimSpace(content(n))
		}
		if n.Data == "input" && attrs["name"] == id {
			return attrs["value"]
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if s := find(c); s != "" {
				return s
			}
		}
		return ""
	}
	return find(root)
}
func (c *ecnuClient) request(ctx context.Context, method, target, content string, body []byte, envelope *ecnuEnvelope, follow bool) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("invalid SSO request")
	}
	if method == http.MethodPost {
		req.Header.Set("Origin", c.Origin)
		req.Header.Set("Referer", c.BaseURL+"/login")
		req.Header.Set("Content-Type", content)
		req.Header.Set("X-CSRF-TOKEN", "csrfToken")
	}
	if envelope != nil {
		req.Header.Set("hasCrypto", "true")
		req.Header.Set("privateKey", envelope.wrapped)
	}
	hc := *c.HTTP
	origin, _ := url.Parse(c.BaseURL)
	hc.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if !follow {
			return http.ErrUseLastResponse
		}
		if len(via) >= 10 {
			return errors.New("SSO redirect limit")
		}
		if !httporigin.Same(r.URL, origin) {
			return http.ErrUseLastResponse
		}
		return nil
	}
	c.setHeaders(req)
	resp, err := hc.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		return nil, errors.New("SSO request failed")
	}
	defer resp.Body.Close()
	if method == http.MethodPost && req.URL.Path == "/login" && (resp.StatusCode == 302 || resp.StatusCode == 303) {
		return nil, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("SSO %s: HTTP %d", req.URL.Path, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, (2<<20)+1))
	if err != nil || len(b) > 2<<20 {
		return nil, errors.New("cannot read SSO response")
	}
	return b, nil
}
func (c *ecnuClient) Login(ctx context.Context) error {
	if c.BaseURL != strings.TrimRight(c.Keystore.BaseURL(), "/") || c.Origin != c.BaseURL {
		return errors.New("credential origin mismatch")
	}
	page, err := c.request(ctx, http.MethodGet, c.BaseURL+"/login", "", nil, nil, true)
	if err != nil {
		return err
	}
	if pageValue(page, "riskSystemSwitch") == "USTC" {
		return errors.New("SSO requires interactive browser verification")
	}
	execution := pageValue(page, "login-page-flowkey")
	if execution == "" {
		execution = pageValue(page, "execution")
	}
	if execution == "" {
		return errors.New("SSO execution token missing")
	}
	script, err := c.request(ctx, http.MethodGet, c.BaseURL+"/public/webauthJs/webauthn.js?v=2.0.1", "", nil, nil, true)
	if err != nil {
		return err
	}
	env, err := newECNUEnvelope(script)
	if err != nil {
		return err
	}
	body, err := env.encrypt(map[string]string{"username": c.Keystore.Username()})
	if err != nil {
		return err
	}
	raw, err := c.request(ctx, http.MethodPost, c.BaseURL+"/webauthn/authenticate", "application/json", body, env, false)
	if err != nil {
		return err
	}
	data, err := env.decode(raw)
	if err != nil {
		return err
	}
	if data["success"] != true {
		return errors.New("SSO challenge rejected")
	}
	request, _ := data["request"].(map[string]any)
	options, _ := request["publicKeyCredentialRequestOptions"].(map[string]any)
	if options["rpId"] != c.Keystore.RpID() {
		return errors.New("SSO RP ID mismatch")
	}
	requestID, _ := request["requestId"].(string)
	if requestID == "" {
		return errors.New("SSO request ID missing")
	}
	actions, _ := data["actions"].(map[string]any)
	finish, _ := actions["finish"].(string)
	if finish == "" {
		return errors.New("SSO finish URL missing")
	}
	base, _ := url.Parse(c.BaseURL + "/")
	ref, err := url.Parse(finish)
	if err != nil {
		return errors.New("invalid SSO finish URL")
	}
	target := base.ResolveReference(ref)
	if !httporigin.Same(target, base) || target.Fragment != "" {
		return errors.New("SSO finish URL outside credential origin")
	}
	assertion, count, err := buildAssertion(options, c.Keystore, c.Origin)
	if err != nil {
		return err
	}
	c.Keystore.SetSignCount(count)
	if err = c.Keystore.Save(); err != nil {
		return fmt.Errorf("cannot persist passkey counter: %w", err)
	}
	token := request["sessionToken"]
	if token == nil {
		token = data["sessionToken"]
	}
	body, err = json.Marshal(map[string]any{"requestId": requestID, "credential": json.RawMessage(assertion), "sessionToken": token})
	if err != nil {
		return err
	}
	raw, err = c.request(ctx, http.MethodPost, target.String(), "text/plain;charset=UTF-8", body, nil, false)
	if err != nil {
		return err
	}
	var result struct {
		Success       bool            `json:"success"`
		Token         string          `json:"sessionToken"`
		Registrations json.RawMessage `json:"registrations"`
	}
	if json.Unmarshal(raw, &result) != nil || !result.Success || result.Token == "" {
		return errors.New("SSO assertion rejected")
	}
	form := url.Values{"username": {c.Keystore.Username()}, "token": {result.Token}, "_eventId": {"validateWebAuthn"}, "execution": {execution}, "geolocation": {""}}
	_, err = c.request(ctx, http.MethodPost, c.BaseURL+"/login", "application/x-www-form-urlencoded", []byte(form.Encode()), nil, true)
	if err != nil {
		return err
	}
	loggedIn, err := c.IsLoggedIn(ctx)
	if err != nil {
		return err
	}
	if !loggedIn {
		return errors.New("SSO account session not established")
	}
	return nil
}

func (c *ecnuClient) IsLoggedIn(ctx context.Context) (bool, error) {
	page, err := c.request(ctx, http.MethodGet, c.BaseURL+"/account", "", nil, nil, false)
	if err != nil {
		return false, err
	}
	return pageValue(page, "ps-username") == c.Keystore.Username(), nil
}
