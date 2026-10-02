package sdpc

import (
	"context"
	"fmt"
	"net/url"
)

// AuthConfig carries the fields later login steps need.
type AuthConfig struct {
	CsrfToken       string
	Guid            string
	DevicePubKeyMod string
	DevicePubKeyExp string
	Challenge       string
	RsaCert         string
}

// AuthConfig fetches /passport/v1/public/authConfig and stores the csrf token
// for subsequent calls.
func (c *Client) AuthConfig(ctx context.Context, selectCASDomain bool) (*AuthConfig, error) {
	var data struct {
		AuthServerInfoList []struct {
			AuthType    string `json:"authType"`
			LoginDomain string `json:"loginDomain"`
		} `json:"authServerInfoList"`
		Security struct {
			CsrfToken string `json:"csrfToken"`
		} `json:"security"`
		Guid               string `json:"guid"`
		AntiMITMAttackData struct {
			DevicePubKeyMod string `json:"devicePubKeyMod"`
			DevicePubKeyExp string `json:"devicePubKeyExp"`
			Challenge       string `json:"challenge"`
			RsaCert         string `json:"rsaCert"`
		} `json:"antiMITMAttackData"`
	}
	// authConfig is the first call: no x-csrf-token exists yet.
	if err := c.doJSON(ctx, "GET", "/passport/v1/public/authConfig", url.Values{}, nil, &data); err != nil {
		return nil, err
	}
	if data.Security.CsrfToken == "" {
		return nil, &APIError{Op: "authConfig", Code: -1, Message: "response missing security.csrfToken"}
	}
	c.csrf = data.Security.CsrfToken
	if selectCASDomain && c.LoginDomain == "" {
		var selected string
		for _, method := range data.AuthServerInfoList {
			if method.AuthType != "auth/cas" || method.LoginDomain == "" {
				continue
			}
			if selected != "" && selected != method.LoginDomain {
				return nil, fmt.Errorf("multiple CAS login domains; select login_domain explicitly")
			}
			selected = method.LoginDomain
		}
		c.LoginDomain = selected
	}
	exp := data.AntiMITMAttackData.DevicePubKeyExp
	if exp == "" {
		exp = "10001"
	}
	ac := &AuthConfig{
		CsrfToken:       data.Security.CsrfToken,
		Guid:            data.Guid,
		DevicePubKeyMod: data.AntiMITMAttackData.DevicePubKeyMod,
		DevicePubKeyExp: exp,
		Challenge:       data.AntiMITMAttackData.Challenge,
		RsaCert:         data.AntiMITMAttackData.RsaCert,
	}
	return ac, nil
}
