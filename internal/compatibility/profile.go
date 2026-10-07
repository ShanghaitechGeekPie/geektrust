// Package compatibility owns the verified defaults for known controllers.
package compatibility

import (
	public "github.com/ShanghaitechGeekPie/geektrust/compatibility"
	"net/url"
	"strings"
)

type Resolved struct {
	Profile               public.Profile
	Fallbacks             public.Fallbacks
	Process               *public.ProcessMetadata
	GatewayServerName     string
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
		value := *x
		v.Process = &value
	}
	if f := o.Fallbacks; f != nil {
		v.Fallbacks.ApplicationID = f.ApplicationID
		v.Fallbacks.Gateways = append([]string(nil), f.Gateways...)
		v.Fallbacks.MissingGatewayGroup = f.MissingGatewayGroup
		v.Fallbacks.StreamToL3 = f.StreamToL3
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
