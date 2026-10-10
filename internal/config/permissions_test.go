//go:build !windows

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStrictPermissionsIsOptionalAndPreservedByMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	data := "keystore='fixture'\nstrict_permissions=true\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("strict configuration accepted shared permissions")
	}
	if err := os.WriteFile(path, []byte("keystore='fixture'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if cfg, err := Load(path); err != nil || cfg.StrictPermissions {
		t.Fatalf("default permission mode rejected config: %v", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	migrated, err := Migration(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, migrated, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil || !cfg.StrictPermissions {
		t.Fatalf("migration lost strict permissions: %v", err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("strict v2 configuration accepted shared permissions")
	}
	if err := os.WriteFile(path, []byte("config_version=2\ninvalid = ["), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("default permission mode disabled format validation")
	}
}
