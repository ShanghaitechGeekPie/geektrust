package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompatibilityConfigIsExplicit(t *testing.T) {
	for _, controller := range []string{DefaultBaseURL, "https://vpn.ecnu.edu.cn", "https://vpn.example.org"} {
		t.Run(controller, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			base := "keystore = 'synthetic.keystore'\nbase_url = '" + controller + "'\n"
			for _, enabled := range []bool{false, true, false} {
				body := base
				if enabled {
					body += `login_domain = "custom-domain"
[compatibility]
fallback_app_id = "custom-app"
fallback_gateways = ["gateway.example:441", "[2001:db8::1]:441"]
gateway_server_name = "gateway.example"
missing_gateway_group_fallback = true
tcp_to_l3_fallback = true
`
				}
				if err := os.WriteFile(path, []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
				c, err := Load(path)
				if err != nil {
					t.Fatal(err)
				}
				if c.Compatibility.TCPToL3Fallback != enabled || c.Compatibility.MissingGatewayGroupFallback != enabled || (c.Compatibility.FallbackAppID != "") != enabled || (len(c.Compatibility.FallbackGateways) > 0) != enabled || (c.GatewayServerName() != "") != enabled || (c.LoginDomain != "") != enabled {
					t.Fatalf("unexpected settings for enabled=%v: %+v", enabled, c.Compatibility)
				}
				after, err := os.ReadFile(path)
				if err != nil || string(after) != body {
					t.Fatal("loading changed original configuration")
				}
			}
		})
	}
}

func TestCompatibilityConfigRejectsMistakes(t *testing.T) {
	for _, setting := range []string{
		"[compatibility]\ntcp_to_l3_fallbak = true",
		"[compatibility]\nfallback_gateways = ['gateway:0']",
		"[compatibility]\nfallback_gateways = ['gateway']",
		"[compatibility]\ngateway_server_name = 'https://gateway'",
		"app_id = 'removed-setting'",
	} {
		path := filepath.Join(t.TempDir(), "config.toml")
		if err := os.WriteFile(path, []byte("keystore = 'synthetic.keystore'\n"+setting), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatalf("accepted invalid setting: %s", setting)
		}
	}
}

func TestGeneratedConfigDefaultsToStrictCompatibility(t *testing.T) {
	cfg, err := PrepareInitialConfig(InitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	data := renderInitialConfig(cfg)
	if !strings.Contains(string(data), "[compatibility]") {
		t.Fatal("missing discoverable settings")
	}
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	if loaded.Compatibility.TCPToL3Fallback || loaded.Compatibility.MissingGatewayGroupFallback || loaded.Compatibility.FallbackAppID != "" || loaded.GatewayServerName() != "" {
		t.Fatal("generated config enabled compatibility")
	}
}
