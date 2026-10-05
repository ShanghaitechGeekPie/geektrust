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
	if !strings.Contains(string(b), "0123456789ABCDEF0123456789ABCDEF") || !strings.Contains(string(b), "browser") || !strings.Contains(string(b), "custom") {
		t.Fatal("migration lost existing semantics")
	}
	os.WriteFile(p, []byte(old+"gateways=['other:441']\n"), 0600)
	if _, e = Migration(p); e == nil {
		t.Fatal("legacy override silently converted")
	}
}
