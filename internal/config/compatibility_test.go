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
				if enabled {
					if c.Compatibility.FallbackAppID != "custom-app" || c.GatewayServerName() != "gateway.example" || c.LoginDomain != "custom-domain" {
						t.Fatal("explicit settings lost")
					}
				} else if controller == DefaultBaseURL {
					if c.GatewayServerName() != "vpn.shanghaitech.edu.cn" || c.Compatibility.FallbackAppID == "" {
						t.Fatal("ShanghaiTech defaults missing")
					}
				} else if c.GatewayServerName() != "" || c.Compatibility.FallbackAppID != "" {
					t.Fatal("school defaults leaked")
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
		"[compatibility]\nfallback_gateways = ['gateway:0']",
		"[compatibility]\nfallback_gateways = ['gateway']",
		"[compatibility]\ngateway_server_name = 'https://gateway'",
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

func TestGeneratedConfigDefaultsToShanghaiTech(t *testing.T) {
	cfg, e := PrepareInitialConfig(InitOptions{})
	if e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(t.TempDir(), "config.toml")
	b := renderInitialConfig(cfg)
	if !strings.Contains(string(b), "config_version = 2") {
		t.Fatal("init did not generate v2")
	}
	if e = os.WriteFile(p, b, 0600); e != nil {
		t.Fatal(e)
	}
	v, e := Load(p)
	if e != nil {
		t.Fatal(e)
	}
	if v.GatewayServerName() != "vpn.shanghaitech.edu.cn" || !v.Compatibility.TCPToL3Fallback {
		t.Fatal("minimal ShanghaiTech defaults missing")
	}
}
