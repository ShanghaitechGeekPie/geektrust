package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRejectUnreleasedCompatibilitySection(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(p, []byte("keystore='fixture'\n[compatibility]\nfallback_app_id='old'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("unreleased compatibility format retained")
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
	if v.GatewayServerName() != "vpn.shanghaitech.edu.cn" || !v.Fallbacks.StreamToL3 {
		t.Fatal("minimal ShanghaiTech defaults missing")
	}
}
