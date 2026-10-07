package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigCheckRejectsPrivateFileOverlap(t *testing.T) {
	for _, collision := range []string{"credential", "credential-key", "configuration", "device-identity"} {
		t.Run(collision, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.toml")
			credential, state := "credential", "session.enc"
			switch collision {
			case "credential":
				state = credential
			case "credential-key":
				credential = state + ".key"
			case "configuration":
				state = "config.toml"
			case "device-identity":
				state = "store/device_id"
			}
			data := fmt.Sprintf("config_version=2\n[auth]\ndevice_id='0123456789ABCDEF0123456789ABCDEF'\n[auth.passkey]\nkeystore=%q\n[storage]\ndirectory='store'\nstate_file=%q\n", credential, state)
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			if err := cmdConfig(path, []string{"check"}); err == nil {
				t.Fatal("configuration check accepted overlapping private files")
			}
			after, err := os.ReadFile(path)
			if err != nil || string(after) != data {
				t.Fatal("configuration check changed the file")
			}
		})
	}
}
