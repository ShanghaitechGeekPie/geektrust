package compatibility

import (
	public "github.com/ShanghaitechGeekPie/geektrust/compatibility"
)

// Preserve the existing compatibility's missing-information fallbacks, after server policy.
func shanghaiTechProfile() Resolved {
	return Resolved{Profile: public.ShanghaiTech, Platform: "Mac", LoginDomain: "Shanghaitech.edu.cn", GatewayServerName: "vpn.shanghaitech.edu.cn", Fallbacks: public.Fallbacks{ApplicationID: "681165d0-1c77-11ed-8650-cd35a51aa42a", Gateways: []string{"119.78.254.241:441", "59.78.171.241:441"}, MissingGatewayGroup: true, StreamToL3: true}}
}
