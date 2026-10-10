package privatefile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPermissionSettingFailureWarnsUnlessStrict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "secret")
	warnings, err := os.CreateTemp(t.TempDir(), "warnings")
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stderr
	os.Stderr = warnings
	defer func() { os.Stderr = previous; warnings.Close() }()
	if err := Protect(path, false); err != nil {
		t.Fatal(err)
	}
	os.Stderr = previous
	data, err := os.ReadFile(warnings.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "Warning:") || !strings.Contains(string(data), "strict_permissions is disabled") {
		t.Fatalf("missing English warning: %s", data)
	}
	if err := Protect(path, true); err == nil {
		t.Fatal("strict permission setting accepted a missing target")
	}
}
