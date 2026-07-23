package config

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestGenerateDeviceID(t *testing.T) {
	source := bytes.NewReader([]byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	})
	id, err := generateDeviceID(source)
	if err != nil {
		t.Fatal(err)
	}
	if id != "000102030405060708090A0B0C0D0E0F" {
		t.Errorf("device_id = %q", id)
	}
	if _, err := generateDeviceID(strings.NewReader("short")); err == nil {
		t.Fatal("short random source did not return an error")
	}

	randomID, err := GenerateDeviceID()
	if err != nil {
		t.Fatal(err)
	}
	if valid := regexp.MustCompile(`^[0-9A-F]{32}$`); !valid.MatchString(randomID) {
		t.Fatalf("generated device_id %q is not 32 uppercase hex characters", randomID)
	}
}

func TestInitializeDefaultsAndPreservesExistingConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "config.toml")
	cfg, err := Initialize(path, InitOptions{Keystore: "./synthetic.keystore"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ClientType != "client" {
		t.Errorf("client_type = %q, want client", cfg.ClientType)
	}
	if cfg.DeviceID == "" || cfg.DeviceID == DefaultDeviceID {
		t.Errorf("generated device_id = %q", cfg.DeviceID)
	}
	if !cfg.Inbound.SOCKS5.Enabled || !cfg.Inbound.HTTP.Enabled {
		t.Errorf("listeners not enabled: %+v", cfg.Inbound)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("config mode = %o, want 600", info.Mode().Perm())
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.DeviceID != cfg.DeviceID || loaded.ClientType != "client" {
		t.Errorf("loaded config = %+v", loaded)
	}

	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Initialize(path, InitOptions{Keystore: "./other.keystore"}); err == nil {
		t.Fatal("Initialize replaced an existing config without Force")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(original) {
		t.Fatal("existing config changed after refused initialization")
	}
}

func TestInitializeExplicitOptionsAndForce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	const deviceID = "0123456789ABCDEF0123456789ABCDEF"
	cfg, err := Initialize(path, InitOptions{
		Keystore:   "./synthetic.keystore",
		DeviceID:   deviceID,
		StateFile:  "./synthetic-state.enc",
		ClientType: "browser",
		Force:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DeviceID != deviceID || cfg.ClientType != "browser" || cfg.StateFile != "./synthetic-state.enc" {
		t.Errorf("initialized config = %+v", cfg)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("forced config is invalid: %v", err)
	}
}

func TestInitializeRejectsInvalidOptions(t *testing.T) {
	for name, opts := range map[string]InitOptions{
		"bad device ID":   {Keystore: "./synthetic.keystore", DeviceID: "not-an-id"},
		"bad client type": {Keystore: "./synthetic.keystore", ClientType: "desktop"},
		"shared client ID": {
			Keystore: "./synthetic.keystore", DeviceID: DefaultDeviceID, ClientType: "client",
		},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			if _, err := Initialize(path, opts); err == nil {
				t.Fatal("expected initialization error")
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("invalid initialization created a config: %v", err)
			}
		})
	}
}
