package runtime

import (
	"context"
	"errors"
	"github.com/ShanghaitechGeekPie/geektrust/internal/sdpc"
	"github.com/ShanghaitechGeekPie/geektrust/internal/session"
)

var ErrNoSession = errors.New("no active controller session")

func (c *Runtime) prepareDevices(ctx context.Context) error {
	if err := c.prepare(ctx); err != nil {
		return err
	}
	_, err := c.provider.Credential(ctx)
	return err
}

// deviceOperation binds a controller request to the current session and lifetime.
func (c *Runtime) deviceOperation(parent context.Context, fn func(context.Context, *sdpc.Client) error) (*session.Credential, error) {
	ctx, done := c.operation(parent)
	defer done()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cred, sc := c.provider.ActiveSession()
	if cred == nil || sc == nil {
		return nil, ErrNoSession
	}
	ctx, releaseSession := bindSession(ctx, cred)
	defer releaseSession()
	err := fn(ctx, sc)
	if c.provider.Current() != cred {
		return nil, session.ErrSessionReplaced
	}
	return cred, err
}

// These controller DTO methods are internal panel hooks; they require an active session.
func (c *Runtime) QueryTrustDevice(parent context.Context) (*sdpc.TrustDeviceList, error) {
	var list *sdpc.TrustDeviceList
	_, err := c.deviceOperation(parent, func(ctx context.Context, sc *sdpc.Client) error {
		var err error
		list, err = sc.QueryTrustDevice(ctx)
		return err
	})
	return list, err
}
func (c *Runtime) TrustDevice(parent context.Context) error {
	_, err := c.deviceOperation(parent, func(ctx context.Context, sc *sdpc.Client) error { return sc.TrustDevice(ctx) })
	return err
}
func (c *Runtime) UntrustDevice(parent context.Context, ids []string) error {
	_, err := c.deviceOperation(parent, func(ctx context.Context, sc *sdpc.Client) error { return sc.UntrustDevice(ctx, ids) })
	return err
}
func (c *Runtime) LogoutTrustDevice(parent context.Context, id string) error {
	self := ""
	cred, err := c.deviceOperation(parent, func(ctx context.Context, sc *sdpc.Client) error {
		list, err := sc.QueryTrustDevice(ctx)
		if err != nil {
			return err
		}
		self = list.SelfID
		return sc.LogoutDevice(ctx, id)
	})
	if err == nil && id == self && c.provider.InvalidateIfCurrent(cred) {
		c.resetConnections()
	}
	return err
}

func (c *Runtime) TrustedDevices(parent context.Context) (TrustedDeviceList, error) {
	ctx, done := c.operation(parent)
	defer done()
	e := c.prepareDevices(ctx)
	if e != nil {
		return TrustedDeviceList{}, e
	}
	v, e := c.QueryTrustDevice(ctx)
	if e != nil {
		return TrustedDeviceList{}, e
	}
	out := TrustedDeviceList{CurrentDeviceID: v.SelfID, CurrentTrustStatus: v.CurrentTrustStatus, TrustEnabled: v.Config.Enable}
	for _, x := range v.Devices {
		out.Devices = append(out.Devices, TrustedDevice{ID: x.ID, Name: x.DeviceName, Platform: x.DeviceType, OS: x.OS, OSVersion: x.OSVersion, LastLoginIP: x.LastLoginIP, LastLoginAddress: x.LastLoginAddress, NetworkZones: append([]string(nil), x.NetworkZoneList...), Online: x.OnlineStatus})
	}
	return out, nil
}
func (c *Runtime) TrustCurrentDevice(parent context.Context) error {
	ctx, done := c.operation(parent)
	defer done()
	e := c.prepareDevices(ctx)
	if e != nil {
		return e
	}
	return c.TrustDevice(ctx)
}
func (c *Runtime) UntrustDevices(parent context.Context, ids []string) error {
	ctx, done := c.operation(parent)
	defer done()
	e := c.prepareDevices(ctx)
	if e != nil {
		return e
	}
	return c.UntrustDevice(ctx, ids)
}
func (c *Runtime) LogoutDevice(parent context.Context, id string) error {
	ctx, done := c.operation(parent)
	defer done()
	if err := c.prepareDevices(ctx); err != nil {
		return err
	}
	return c.LogoutTrustDevice(ctx, id)
}
