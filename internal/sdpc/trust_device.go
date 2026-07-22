package sdpc

import (
	"context"
	"fmt"
	"net/url"
)

// TrustDeviceEntry is a single trusted terminal record.
type TrustDeviceEntry struct {
	ID         string `json:"id"`
	DeviceName string `json:"deviceName"`
	Platform   string `json:"platform"`
	TrustTime  string `json:"trustTime"`
	LastLogin  string `json:"lastLoginTime"`
	Current    bool   `json:"isCurrent"`
}

// TrustDeviceList is the response from queryDevice.
type TrustDeviceList struct {
	Devices       []TrustDeviceEntry `json:"deviceList"`
	MaxCount      int                `json:"maxCount"`
	CurrentCount  int                `json:"currentCount"`
	DeviceTrusted bool               `json:"deviceTrusted"`
}

// QueryTrustDevice lists all trusted terminals bound to the account.
// Requires an active session (sid cookie + csrf).
func (c *Client) QueryTrustDevice(ctx context.Context) (*TrustDeviceList, error) {
	var data TrustDeviceList
	if err := c.doJSON(ctx, "GET", "/passport/v1/security/queryDevice", url.Values{}, nil, &data); err != nil {
		return nil, err
	}
	return &data, nil
}

// TrustDevice binds the current device as a trusted terminal. After this
// succeeds, subsequent authCheck calls should not demand SMS verification
// (server-side policy permitting).
//
// The server identifies the device by the session cookies and the device_id
// sent in reportEnv, so the request body is empty.
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
