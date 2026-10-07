//go:build !windows

package storage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCredentialPermissionsWarnByDefaultAndFailWhenStrict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	soft := CredentialFile{Path: path}
	if data, err := soft.Load(context.Background()); err != nil || string(data) != "fixture" {
		t.Fatalf("default read blocked: %v", err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0644 {
		t.Fatal("permission check changed the existing file")
	}
	strict := CredentialFile{Path: path, StrictPermissions: true}
	if _, err := strict.Load(context.Background()); err == nil {
		t.Fatal("strict read accepted shared permissions")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := strict.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
}
