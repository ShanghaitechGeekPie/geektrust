package session

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	st := NewStore(filepath.Join(dir, "state.enc"))

	// No file yet → (nil, nil).
	got, err := st.Load()
	if err != nil || got != nil {
		t.Fatalf("Load on empty = %v, %v; want nil, nil", got, err)
	}

	want := &State{
		SID:        "unit-1_uuid-2",
		DeviceID:   "0123456789ABCDEF0123456789ABCDEF",
		CsrfToken:  "csrf-abc",
		Cookies:    []CookieRecord{{Name: "sid", Value: "unit-1_uuid-2"}, {Name: "lang", Value: "zh-CN"}},
		Gateways:   []string{"192.0.2.10:441"},
		ClientType: "client",
	}
	if err := st.Save(want); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// State file must not contain the plaintext sid.
	raw, err := os.ReadFile(filepath.Join(dir, "state.enc"))
	if err != nil {
		t.Fatal(err)
	}
	if contains(raw, []byte("unit-1_uuid-2")) || contains(raw, []byte("csrf-abc")) {
		t.Error("state file contains plaintext secrets")
	}
	for _, name := range []string{"state.enc", "state.enc.key"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s perm = %o, want 600", name, info.Mode().Perm())
		}
	}

	got, err = st.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.SID != want.SID || got.DeviceID != want.DeviceID || got.CsrfToken != want.CsrfToken ||
		got.ClientType != want.ClientType {
		t.Errorf("round trip mismatch: %+v", got)
	}
	if len(got.Cookies) != 2 || got.Cookies[0].Name != "sid" {
		t.Errorf("cookies = %+v", got.Cookies)
	}
	if got.SavedAt.IsZero() {
		t.Error("SavedAt not set")
	}

	// The key must be stable across saves (same key file reused).
	key1, _ := os.ReadFile(filepath.Join(dir, "state.enc.key"))
	if err := st.Save(want); err != nil {
		t.Fatal(err)
	}
	key2, _ := os.ReadFile(filepath.Join(dir, "state.enc.key"))
	if string(key1) != string(key2) {
		t.Error("key file was regenerated; it must be stable")
	}
}

func TestStoreWrongKey(t *testing.T) {
	dir := t.TempDir()
	st := NewStore(filepath.Join(dir, "state.enc"))
	if err := st.Save(&State{SID: "s"}); err != nil {
		t.Fatal(err)
	}
	// Corrupt the key.
	if err := os.WriteFile(filepath.Join(dir, "state.enc.key"), make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Load(); err == nil {
		t.Fatal("expected decrypt failure with wrong key")
	}
}

func TestStoreInvalidKeyNotOverwritten(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "state.enc.key")
	if err := os.WriteFile(keyPath, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	st := NewStore(filepath.Join(dir, "state.enc"))
	if err := st.Save(&State{SID: "s"}); err == nil {
		t.Fatal("Save must fail on a present-but-invalid key file, not regenerate it")
	}
	got, _ := os.ReadFile(keyPath)
	if string(got) != "short" {
		t.Error("invalid key file was overwritten")
	}
}

func contains(haystack, needle []byte) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}
