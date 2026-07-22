package sdpc

import (
	"context"
	"fmt"
	"net/url"
)

// TrustDeviceEntry is a single terminal record from queryDevice.
type TrustDeviceEntry struct {
	ID               string   `json:"id"`
	DeviceName       string   `json:"deviceName"`
	DeviceType       string   `json:"deviceType"` // "browser" or desktop platform
	OS               string   `json:"os"`
	OSVersion        string   `json:"osVersion"`
	LastLoginIP      string   `json:"lastLoginIp"`
	LastLoginAddress string   `json:"lastLoginAddress"`
	NetworkZoneList  []string `json:"networkZoneList"`
	OnlineStatus     bool     `json:"onlineStatus"`
}

// TrustDeviceConfig mirrors the server-side trusted-terminal policy.
type TrustDeviceConfig struct {
	Enable bool `json:"enable"`
}

// TrustDeviceList is the response from queryDevice?status=trust.
type TrustDeviceList struct {
	Devices            []TrustDeviceEntry `json:"data"`
	SelfID             string             `json:"selfId"`
	CurrentTrustStatus int                `json:"currentTrustStatus"`
	Config             TrustDeviceConfig  `json:"trustDeviceConfig"`
}

// QueryTrustDevice lists the terminals currently trusted by the account.
// Requires an active session (sid cookie + csrf). The status=trust query
// parameter is mandatory; without it the controller answers 422.
func (c *Client) QueryTrustDevice(ctx context.Context) (*TrustDeviceList, error) {
	q := url.Values{"status": {"trust"}}
	var data TrustDeviceList
	if err := c.doJSON(ctx, "GET", "/passport/v1/security/queryDevice", q, nil, &data); err != nil {
		return nil, err
	}
	return &data, nil
}

// QueryUntrustedDevice lists terminals known to the account but not trusted.
func (c *Client) QueryUntrustedDevice(ctx context.Context) ([]TrustDeviceEntry, error) {
	q := url.Values{"status": {"untrust"}}
	var data struct {
		Devices []TrustDeviceEntry `json:"data"`
	}
	if err := c.doJSON(ctx, "GET", "/passport/v1/security/queryDevice", q, nil, &data); err != nil {
		return nil, err
	}
	return data.Devices, nil
}

// TrustDevice binds the current device as a trusted terminal. After this
// succeeds, subsequent authCheck calls should not demand SMS verification
// (server-side policy permitting).
//
// The server identifies the device by the session cookies and the device_id
// sent in reportEnv, so the request body is empty. The session must have
// been established through the desktop path (clientType=SDPClient); a pure
// web session is rejected with code 75500000.
func (c *Client) TrustDevice(ctx context.Context) error {
	return c.doJSON(ctx, "POST", "/passport/v1/security/trustDevice", url.Values{}, map[string]any{}, nil)
}

// UntrustDevice removes a trusted terminal by its device ID list.
func (c *Client) UntrustDevice(ctx context.Context, idList []string) error {
	if len(idList) == 0 {
		return fmt.Errorf("untrustDevice: idList must not be empty")
	}
	body := map[string]any{"idList": idList}
	return c.doJSON(ctx, "POST", "/passport/v1/security/untrustDevice", url.Values{}, body, nil)
}

// LogoutDevice logs out a trusted terminal by its device ID.
func (c *Client) LogoutDevice(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("logoutDevice: id must not be empty")
	}
	body := map[string]string{"id": id}
	return c.doJSON(ctx, "POST", "/passport/v1/security/logoutDevice", url.Values{}, body, nil)
}
