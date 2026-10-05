package runtime

import (
	"context"
	"errors"
	"github.com/ShanghaitechGeekPie/geektrust/internal/sdpc"
)

func (c *Runtime) controller(ctx context.Context) (*sdpc.Client, error) {
	if e := c.prepare(ctx); e != nil {
		return nil, e
	}
	if _, e := c.provider.Credential(ctx); e != nil {
		return nil, e
	}
	sc := c.provider.ActiveSDPC()
	if sc == nil {
		return nil, errors.New("no active controller session")
	}
	return sc, nil
}
func (c *Runtime) TrustedDevices(parent context.Context) (TrustedDeviceList, error) {
	ctx, done := c.operation(parent)
	defer done()
	sc, e := c.controller(ctx)
	if e != nil {
		return TrustedDeviceList{}, e
	}
	v, e := sc.QueryTrustDevice(ctx)
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
	sc, e := c.controller(ctx)
	if e != nil {
		return e
	}
	return sc.TrustDevice(ctx)
}
func (c *Runtime) UntrustDevices(parent context.Context, ids []string) error {
	ctx, done := c.operation(parent)
	defer done()
	sc, e := c.controller(ctx)
	if e != nil {
		return e
	}
	return sc.UntrustDevice(ctx, ids)
}
func (c *Runtime) LogoutDevice(parent context.Context, id string) error {
	ctx, done := c.operation(parent)
	defer done()
	list, e := c.TrustedDevices(ctx)
	if e != nil {
		return e
	}
	sc, e := c.controller(ctx)
	if e != nil {
		return e
	}
	if e = sc.LogoutDevice(ctx, id); e != nil {
		return e
	}
	if id == list.CurrentDeviceID {
		c.provider.Invalidate()
		c.resetConnections()
	}
	return nil
}
