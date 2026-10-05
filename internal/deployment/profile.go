// Package deployment owns the verified defaults for known controllers.
package deployment

import (
	public "github.com/ShanghaitechGeekPie/geektrust/deployment"
	"github.com/ShanghaitechGeekPie/geektrust/internal/settings"
	"net/url"
	"strings"
)

type Resolved struct {
	Profile               public.Profile
	Compatibility         settings.Compatibility
	Platform, LoginDomain string
}

func Resolve(origin string, o public.Options) Resolved {
	p := o.Profile
	if p == public.Auto {
		u, _ := url.Parse(origin)
		p = public.Generic
		if u != nil {
			switch strings.ToLower(u.Host) {
			case "vpn.shanghaitech.edu.cn", "vpn.shanghaitech.edu.cn:443":
				p = public.ShanghaiTech
			case "vpn.ecnu.edu.cn", "vpn.ecnu.edu.cn:443":
				p = public.ECNU
			}
		}
	}
	v := Resolved{Profile: p, Platform: "Mac"}
	if p == public.ShanghaiTech {
		v = shanghaiTechProfile()
	}
	if o.Protocol.ControllerPlatform != "" {
		v.Platform = o.Protocol.ControllerPlatform
	}
	if x := o.Protocol.Process; x != nil {
		v.Compatibility.ProcessIdentity = &settings.ProcessIdentity{Name: x.Name, Platform: x.Platform, Path: x.Path}
	}
	if f := o.Fallbacks; f != nil {
		v.Compatibility.FallbackAppID = f.ApplicationID
		v.Compatibility.FallbackGateways = append([]string(nil), f.Gateways...)
		v.Compatibility.MissingGatewayGroupFallback = f.MissingGatewayGroup
		v.Compatibility.TCPToL3Fallback = f.StreamToL3
	}
	return v
}

// DomainAddress preserves the known single-school mapping, never a generic protocol assumption.
func DomainAddress(origin, ip string) string {
	if Resolve(origin, public.Options{}).Profile == public.ShanghaiTech {
		return ip
	}
	return ""
}
