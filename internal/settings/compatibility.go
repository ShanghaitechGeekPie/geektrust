// LegacyCompatibility is the version-1 file representation.
package settings

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode"
)

// Compatibility is opt-in. Its zero value uses controller policy without
// deployment-specific fallbacks. These settings never override a server denial.
type Compatibility struct {
	ProcessIdentity             *ProcessIdentity `toml:"process_identity" json:"process_identity,omitempty"`
	FallbackAppID               string           `toml:"fallback_app_id" json:"fallback_app_id,omitempty"`
	FallbackGateways            []string         `toml:"fallback_gateways" json:"fallback_gateways,omitempty"`
	GatewayServerName           string           `toml:"gateway_server_name" json:"gateway_server_name,omitempty"`
	MissingGatewayGroupFallback bool             `toml:"missing_gateway_group_fallback" json:"missing_gateway_group_fallback,omitempty"`
	TCPToL3Fallback             bool             `toml:"tcp_to_l3_fallback" json:"tcp_to_l3_fallback,omitempty"`
}

// Clone separates an active client's settings from caller-owned configuration.
func (c Compatibility) Clone() Compatibility {
	if c.ProcessIdentity != nil {
		identity := *c.ProcessIdentity
		c.ProcessIdentity = &identity
	}
	c.FallbackGateways = append([]string(nil), c.FallbackGateways...)
	return c
}

func (c Compatibility) Validate() error {
	if c.ProcessIdentity != nil {
		if err := c.ProcessIdentity.Validate(); err != nil {
			return err
		}
	}
	if len(c.FallbackAppID) > 256 || strings.IndexFunc(c.FallbackAppID, unicode.IsControl) >= 0 {
		return fmt.Errorf("compatibility.fallback_app_id must be at most 256 characters without control characters")
	}
	if c.GatewayServerName != "" {
		name := c.GatewayServerName
		if len(name) > 253 || strings.ContainsAny(name, "/\\:@?# \t\r\n") || strings.IndexFunc(name, unicode.IsControl) >= 0 {
			return fmt.Errorf("compatibility.gateway_server_name must be a TLS hostname without a port")
		}
	}
	for _, address := range c.FallbackGateways {
		host, port, err := net.SplitHostPort(address)
		number, portErr := strconv.Atoi(port)
		if err != nil || host == "" || portErr != nil || number < 1 || number > 65535 || strings.ContainsAny(host, "/\\@?# \t\r\n") {
			return fmt.Errorf("compatibility.fallback_gateways entries must be host:port with port 1-65535")
		}
	}
	return nil
}

// ProcessIdentity overrides the process metadata sent to the gateway. It is
// protocol metadata, not a claim about a locally running or verified process.
type ProcessIdentity struct {
	Name     string `toml:"name" json:"name"`
	Platform string `toml:"platform" json:"platform"`
	Path     string `toml:"path" json:"path"`
}

func (p ProcessIdentity) Validate() error {
	for _, value := range []string{p.Name, p.Platform, p.Path} {
		if strings.TrimSpace(value) == "" || len(value) > 4096 || strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return fmt.Errorf("compatibility.process_identity requires name, platform and path without control characters (max 4096 bytes each)")
		}
	}
	return nil
}
