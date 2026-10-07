package idsauth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/ShanghaitechGeekPie/geektrust/internal/httporigin"
)

// DefaultUserAgent matches the Python library's default browser UA.
const DefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
	"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0"

// Client shares HTTP and credential settings between the supported login flows.
// Its cookie jar is reused by the VPN controller for the CAS redirect chain.
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

type loginClient interface {
	Login(context.Context) error
	IsLoggedIn(context.Context) (bool, error)
}

func (c *Client) backend() loginClient {
	if c.Keystore.Kind() == kindECNU {
		return &ecnuClient{Client: c}
	}
	return &shtuClient{Client: c}
}

// Login authenticates against the identity provider recorded in the keystore.
func (c *Client) Login(ctx context.Context) error { return c.backend().Login(ctx) }

// IsLoggedIn checks the provider's current account session.
func (c *Client) IsLoggedIn(ctx context.Context) (bool, error) { return c.backend().IsLoggedIn(ctx) }

func (c *Client) do(req *http.Request) (*http.Response, error) {
	c.setHeaders(req)
	hc := *c.HTTP
	checkRedirect := hc.CheckRedirect
	hc.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		// A successful login may navigate to another service. Return that
		// response and confirm the identity session separately; never forward
		// assertion data or fetch challenges outside the credential origin.
		if !httporigin.Same(r.URL, req.URL) {
			return http.ErrUseLastResponse
		}
		if checkRedirect != nil {
			return checkRedirect(r, via)
		}
		if len(via) >= 10 {
			return errors.New("identity redirect limit")
		}
		return nil
	}
	return hc.Do(req)
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
