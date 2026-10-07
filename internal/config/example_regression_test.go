package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExampleLoggingGroupCanBeEnabled(t *testing.T) {
	b, err := os.ReadFile("../../config.example.toml")
	if err != nil {
		t.Fatal(err)
	}
	template := strings.ReplaceAll(string(b), "\r\n", "\n")
	for _, ending := range []struct{ name, newline string }{{"LF", "\n"}, {"CRLF", "\r\n"}} {
		t.Run(ending.name, func(t *testing.T) {
			s := strings.ReplaceAll(template, "\n", ending.newline)
			s = strings.Replace(s, "# [logging]", "[logging]", 1)
			s = strings.Replace(s, "# level = \"info\"", "level = \"debug\"", 1)
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, []byte(s), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.LogLevel != "debug" {
				t.Fatalf("template log level=%s, want debug", cfg.LogLevel)
			}
		})
	}
}
