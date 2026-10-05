// Package settings contains normalized runtime values, independent of file formats.
package settings

type Session struct {
	DomainMapping                                        *bool
	BaseURL, DeviceID, Platform, ClientType, LoginDomain string
	Keystore, StateFile                                  string
	Gateways, DNS                                        []string
	Compatibility                                        Compatibility
	IdentityIssuer, IdentitySubject, IdentityKind        string
	LegacyGatewayOverride                                bool
	DNSConfigured                                        bool
	StrictStorage                                        bool
	GatewayFilter                                        bool
}

func (s Session) SessionOptions() Session { return s }
