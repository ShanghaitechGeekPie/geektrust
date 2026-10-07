package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ShanghaitechGeekPie/geektrust/internal/config"
)

func TestLoginRejectsExtraArgumentsBeforeCreatingIdentity(t *testing.T) {
	for _, args := range [][]string{{"unexpected"}, {"-fresh", "unexpected"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			dir := t.TempDir()
			cfg := &config.Config{Version: 2, Directory: dir, BaseURL: "https://controller.example", Keystore: filepath.Join(dir, "missing.keystore"), StateFile: filepath.Join(dir, "session.enc")}
			err := cmdLogin(context.Background(), cfg, newLogger("error"), args)
			if err == nil || !strings.Contains(err.Error(), "usage:") {
				t.Fatalf("extra login arguments = %v, want a usage error", err)
			}
			if _, err := os.Stat(filepath.Join(dir, "device_id")); !os.IsNotExist(err) {
				t.Fatal("invalid login arguments created a device identity")
			}
		})
	}
}
