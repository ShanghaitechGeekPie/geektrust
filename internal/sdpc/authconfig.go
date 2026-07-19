package sdpc

import (
	"context"
	"net/url"
)

// AuthConfig carries the fields later steps need (TECHNICAL.md §3.2).
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
func (c *Client) AuthConfig(ctx context.Context) (*AuthConfig, error) {
	var data struct {
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
	exp := data.AntiMITMAttackData.DevicePubKeyExp
	if exp == "" {
		exp = "10001"
	}
	return &AuthConfig{
		CsrfToken:       data.Security.CsrfToken,
		Guid:            data.Guid,
		DevicePubKeyMod: data.AntiMITMAttackData.DevicePubKeyMod,
		DevicePubKeyExp: exp,
		Challenge:       data.AntiMITMAttackData.Challenge,
		RsaCert:         data.AntiMITMAttackData.RsaCert,
	}, nil
}
