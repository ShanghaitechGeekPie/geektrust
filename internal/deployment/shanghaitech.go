package deployment

import (
	public "github.com/ShanghaitechGeekPie/geektrust/deployment"
	"github.com/ShanghaitechGeekPie/geektrust/internal/settings"
)

// Preserve the existing deployment's missing-information fallbacks, after server policy.
func shanghaiTechProfile() Resolved {
	return Resolved{Profile: public.ShanghaiTech, Platform: "Mac", LoginDomain: "Shanghaitech.edu.cn", Compatibility: settings.Compatibility{GatewayServerName: "vpn.shanghaitech.edu.cn", FallbackAppID: "681165d0-1c77-11ed-8650-cd35a51aa42a", FallbackGateways: []string{"119.78.254.241:441", "59.78.171.241:441"}, MissingGatewayGroupFallback: true, TCPToL3Fallback: true}}
}
