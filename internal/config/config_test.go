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
keystore = "./ids.keystore"
device_id = "84B5B45FE73EC0036C3E97717308447F"
base_url = "https://vpn.shanghaitech.edu.cn/"
gateways = ["119.78.254.241:441", "59.78.171.241"]
dns = ["223.5.5.5"]
[inbound.socks5]
enabled = true
listen = "127.0.0.1:1080"
[inbound.http]
enabled = true
listen = "127.0.0.1:8080"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BaseURL != "https://vpn.shanghaitech.edu.cn" {
		t.Errorf("trailing slash not trimmed: %q", cfg.BaseURL)
	}
	if len(cfg.Gateways) != 2 || len(cfg.DNS) != 1 {
		t.Errorf("gateways/dns = %v / %v", cfg.Gateways, cfg.DNS)
	}
	if !cfg.Inbound.SOCKS5.Enabled || cfg.Inbound.SOCKS5.Listen != "127.0.0.1:1080" {
		t.Errorf("socks5 = %+v", cfg.Inbound.SOCKS5)
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
		{"119.78.254.241:441", "119.78.254.241", "441", false},
		{"59.78.171.241", "59.78.171.241", "441", false},
		{"[2001:da8:801d:d5a:9020:100:d:5a93]:441", "2001:da8:801d:d5a:9020:100:d:5a93", "441", false},
		{"gw.example.com", "gw.example.com", "441", false},
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
