package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestV2MinimalAndReadOnly(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.toml")
	data := "config_version = 2\n[controller]\ndeployment='auto'\n[auth.passkey]\nkeystore = './credential'\n[storage]\ndirectory = './private'\n"
	if e := os.WriteFile(p, []byte(data), 0600); e != nil {
		t.Fatal(e)
	}
	c, e := Load(p)
	if e != nil {
		t.Fatal(e)
	}
	if c.Keystore != filepath.Join(dir, "credential") || c.DeviceID != "" || c.GatewayServerName() != "vpn.shanghaitech.edu.cn" {
		t.Fatal("minimal v2 defaults incorrect")
	}
	if _, e = os.Stat(c.Directory); !os.IsNotExist(e) {
		t.Fatal("loading created storage")
	}
	if e = c.EnsureDeviceID(); e != nil {
		t.Fatal(e)
	}
	id := c.DeviceID
	c2, e := Load(p)
	if e != nil || c2.DeviceID != id {
		t.Fatal("persistent identity changed")
	}
	b, _ := os.ReadFile(p)
	if string(b) != data {
		t.Fatal("loader rewrote source")
	}
}
func TestV2StrictAndLegacyMigration(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.toml")
	for _, data := range []string{"config_version = 3", "config_version = 2\nkeystore='old'", "config_version=2\n[auth.passkey]\nkeystore='x'\n[web]\ntypo=true"} {
		os.WriteFile(p, []byte(data), 0600)
		if _, e := Load(p); e == nil {
			t.Fatal("invalid v2 accepted")
		}
	}
	old := "keystore='credential'\ndevice_id='0123456789ABCDEF0123456789ABCDEF'\nclient_type='browser'\napp_id='custom'\nunknown_old_key=true\n"
	os.WriteFile(p, []byte(old), 0600)
	b, e := Migration(p)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(b), "state_file =") || strings.Contains(string(b), "legacy_state") {
		t.Fatal("migration did not emit only storage.state_file")
	}
	migrated := filepath.Join(dir, "migrated.toml")
	if err := os.WriteFile(migrated, b, 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(migrated)
	if err != nil {
		t.Fatal(err)
	}
	expectedState, err := filepath.Abs("./state.enc")
	if err != nil {
		t.Fatal(err)
	}
	if c.StateFile != expectedState {
		t.Fatal("migration changed the effective session path")
	}
	if !strings.Contains(string(b), "0123456789ABCDEF0123456789ABCDEF") || !strings.Contains(string(b), "browser") || !strings.Contains(string(b), "custom") {
		t.Fatal("migration lost existing semantics")
	}
	os.WriteFile(p, []byte(old+"gateways=['other:441']\n"), 0600)
	if _, e = Migration(p); e == nil {
		t.Fatal("legacy override silently converted")
	}
}

func TestV2StateFileAliasAndConflicts(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.toml")
	base := "config_version = 2\n[auth.passkey]\nkeystore = './credential'\n[storage]\ndirectory = './private'\n"
	cases := []struct {
		name, storage, want string
		conflict            bool
	}{
		{"default", "", filepath.Join(dir, "private", "session.enc"), false},
		{"new path", "state_file = './current.enc'\n", filepath.Join(dir, "current.enc"), false},
		{"legacy path", "legacy_state = './previous.enc'\n", filepath.Join(dir, "previous.enc"), false},
		{"empty new path", "state_file = ''\n", filepath.Join(dir, "private", "session.enc"), false},
		{"equivalent aliases", "state_file = './cache.enc'\nlegacy_state = 'nested/../cache.enc'\n", filepath.Join(dir, "cache.enc"), false},
		{"conflicting aliases", "state_file = './new.enc'\nlegacy_state = './old.enc'\n", "", true},
		{"explicit empty conflicts", "state_file = './new.enc'\nlegacy_state = ''\n", "", true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			original := base + tt.storage
			if err := os.WriteFile(p, []byte(original), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(p)
			if tt.conflict {
				if err == nil || !strings.Contains(err.Error(), "conflicting storage.state_file") {
					t.Fatalf("expected conflict, got %v", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if cfg.StateFile != tt.want {
					t.Fatalf("state path=%q, want %q", cfg.StateFile, tt.want)
				}
				if _, err := os.Stat(cfg.StateFile); !os.IsNotExist(err) {
					t.Fatal("loading created a session file")
				}
			}
			after, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != original {
				t.Fatal("loading rewrote source configuration")
			}
		})
	}
}
