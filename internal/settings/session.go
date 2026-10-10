// Package settings contains normalized runtime values, independent of file formats.
package settings

import "github.com/ShanghaitechGeekPie/geektrust/compatibility"

type Session struct {
	DomainMapping                                        *bool
	BaseURL, DeviceID, Platform, ClientType, LoginDomain string
	Gateways, DNS                                        []string
	Fallbacks                                            compatibility.Fallbacks
	Process                                              *compatibility.ProcessMetadata
	IdentityIssuer, IdentitySubject, IdentityKind        string
	LegacyGatewayOverride                                bool
	DNSConfigured                                        bool
	GatewayFilter                                        bool
}
