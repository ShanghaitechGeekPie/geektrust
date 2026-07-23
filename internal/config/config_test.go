package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadDefaults(t *testing.T) {
	path := writeConfig(t, `keystore = "./k.keystore"`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DeviceID != DefaultDeviceID {
		t.Errorf("device_id default = %q", cfg.DeviceID)
	}
	if cfg.BaseURL != DefaultBaseURL {
		t.Errorf("base_url default = %q", cfg.BaseURL)
	}
	if cfg.Platform != "Mac" || cfg.AppID != DefaultAppID || cfg.StateFile != "./state.enc" || cfg.LogLevel != "info" {
		t.Errorf("defaults wrong: %+v", cfg)
	}
	if cfg.ClientType != "browser" {
		t.Errorf("client_type default = %q", cfg.ClientType)
	}
}

func TestLoadFull(t *testing.T) {
	path := writeConfig(t, `
keystore = "./k.keystore"
device_id = "0123456789ABCDEF0123456789ABCDEF"
base_url = "https://vpn.example.invalid/"
platform = "Mac"
gateways = ["192.0.2.10:441", "198.51.100.10:441"]
dns = ["192.0.2.53"]
client_type = "client"

[inbound.socks5]
enabled = true
listen = "127.0.0.1:1080"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BaseURL != "https://vpn.example.invalid" {
		t.Errorf("trailing slash not trimmed: %q", cfg.BaseURL)
	}
	if len(cfg.Gateways) != 2 || len(cfg.DNS) != 1 {
		t.Errorf("gateways/dns = %v / %v", cfg.Gateways, cfg.DNS)
	}
	if !cfg.Inbound.SOCKS5.Enabled || cfg.Inbound.SOCKS5.Listen != "127.0.0.1:1080" {
		t.Errorf("socks5 = %+v", cfg.Inbound.SOCKS5)
	}
	if cfg.ClientType != "client" {
		t.Errorf("client_type = %q", cfg.ClientType)
	}
}

func TestLoadValidation(t *testing.T) {
	cases := map[string]string{
		"missing keystore":  `device_id = "84B5B45FE73EC0036C3E97717308447F"`,
		"bad device_id":     "keystore = \"k\"\ndevice_id = \"lowercasehex\"",
		"bad platform":      "keystore = \"k\"\nplatform = \"mac\"",
		"bad dns":           "keystore = \"k\"\ndns = [\"dns.example.com\"]",
		"bad log level":     "keystore = \"k\"\nlog_level = \"verbose\"",
		"bad client type":   "keystore = \"k\"\nclient_type = \"desktop\"",
		"client default id": "keystore = \"k\"\nclient_type = \"client\"",
		"enabled no listen": "keystore = \"k\"\n[inbound.socks5]\nenabled = true",
	}
	for name, body := range cases {
		if _, err := Load(writeConfig(t, body)); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
}

func TestSplitHostPort(t *testing.T) {
	cases := []struct {
		in, host, port string
		wantErr        bool
	}{
		{"192.0.2.10:441", "192.0.2.10", "441", false},
		{"198.51.100.10", "198.51.100.10", "441", false},
		{"[2001:db8::10]:441", "2001:db8::10", "441", false},
		{"gw.example.invalid", "gw.example.invalid", "441", false},
		{"", "", "", true},
	}
	for _, c := range cases {
		host, port, err := SplitHostPort(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("SplitHostPort(%q): expected error", c.in)
			}
			continue
		}
		if err != nil || host != c.host || port != c.port {
			t.Errorf("SplitHostPort(%q) = %q,%q,%v; want %q,%q", c.in, host, port, err, c.host, c.port)
		}
	}
}
