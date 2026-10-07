//go:build !windows

package session

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestSessionKeyPermissionsRespectStrictMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.enc")
	strict := NewStore(path, true)
	if err := strict.SaveBytes(context.Background(), []byte("fixture")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(strict.keyPath(), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := strict.LoadBytes(context.Background()); err == nil {
		t.Fatal("strict session store accepted a shared key")
	}
	soft := NewStore(path, false)
	if data, err := soft.LoadBytes(context.Background()); err != nil || string(data) != "fixture" {
		t.Fatalf("default session read blocked: %v", err)
	}
	if err := os.WriteFile(path, []byte("invalid ciphertext"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := soft.LoadBytes(context.Background()); err == nil {
		t.Fatal("default permission mode accepted invalid ciphertext")
	}
}
