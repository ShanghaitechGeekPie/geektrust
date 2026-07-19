package idsauth

import (
	"bytes"
	"compress/zlib"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// pythonFormat serializes a keystore dict exactly like the Python library's
// default_serialize: magic + zlib(sorted compact JSON).
func pythonFormat(t *testing.T, m map[string]any) []byte {
	t.Helper()
	payload, err := json.Marshal(m) // Go sorts map keys like sort_keys=True
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	buf.Write(keystoreMagic)
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func testKeystoreMap(t *testing.T) map[string]any {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	return map[string]any{
		"username":           "12345678",
		"anon_biometrics_id": "aabbccdd00112233aabbccdd00112233",
		"device_name":        "SHTU-PASSKEY-1700000000",
		"base_url":           "https://ids.shanghaitech.edu.cn",
		"credential_id":      "cred-id-b64url",
		"rp_id":              "ids.shanghaitech.edu.cn",
		"user_id":            "user-handle-b64url",
		"alg":                float64(-7),
		"private_key_pem":    string(pemBytes),
		"sign_count":         float64(41),
		"created_at":         "2024-01-01T00:00:00Z",
		"some_future_field":  "must-survive", // unknown fields must round-trip
		"another_extra":      float64(7),
	}
}

func TestKeystoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.keystore")
	original := testKeystoreMap(t)
	if err := os.WriteFile(path, pythonFormat(t, original), 0o600); err != nil {
		t.Fatal(err)
	}

	ks, err := LoadKeystore(path)
	if err != nil {
		t.Fatalf("LoadKeystore: %v", err)
	}
	if ks.Username() != "12345678" {
		t.Errorf("username = %q", ks.Username())
	}
	if ks.RpID() != "ids.shanghaitech.edu.cn" {
		t.Errorf("rp_id = %q", ks.RpID())
	}
	if alg, _ := ks.Alg(); alg != -7 {
		t.Errorf("alg = %d", alg)
	}
	if count, _ := ks.SignCount(); count != 41 {
		t.Errorf("sign_count = %d", count)
	}

	ks.SetSignCount(42)
	if err := ks.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Decode the written file at the raw level: every original field must
	// survive, sign_count must be updated, format must stay magic+zlib+json.
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(blob, keystoreMagic) {
		t.Fatal("saved file lost the magic prefix")
	}
	zr, err := zlib.NewReader(bytes.NewReader(blob[len(keystoreMagic):]))
	if err != nil {
		t.Fatalf("saved file is not zlib: %v", err)
	}
	var decoded map[string]any
	if err := json.NewDecoder(zr).Decode(&decoded); err != nil {
		t.Fatalf("saved file is not json: %v", err)
	}
	for key, want := range original {
		if key == "sign_count" {
			continue
		}
		if got := decoded[key]; got != want {
			t.Errorf("field %q = %v, want %v (must be preserved verbatim)", key, got, want)
		}
	}
	if got := decoded["sign_count"]; got != float64(42) {
		t.Errorf("sign_count = %v, want 42", got)
	}

	// Reload sees the updated count.
	ks2, err := LoadKeystore(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if count, _ := ks2.SignCount(); count != 42 {
		t.Errorf("reloaded sign_count = %d", count)
	}
}

func TestKeystoreBadMagic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.keystore")
	if err := os.WriteFile(path, []byte("not a keystore"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeystore(path); err == nil {
		t.Fatal("expected error for missing magic")
	}
}

func TestKeystoreMissingField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "incomplete.keystore")
	m := testKeystoreMap(t)
	delete(m, "credential_id")
	if err := os.WriteFile(path, pythonFormat(t, m), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeystore(path); err == nil {
		t.Fatal("expected error for missing credential_id")
	}
}

func TestKeystoreFileMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mode.keystore")
	if err := os.WriteFile(path, pythonFormat(t, testKeystoreMap(t)), 0o644); err != nil {
		t.Fatal(err)
	}
	ks, err := LoadKeystore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ks.Save(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("keystore perm = %o, want 600", info.Mode().Perm())
	}
}

// TestKeystoreBigIntPreserved: unknown integer fields above 2^53 must survive
// a load/save round trip bit-exact (regression: float64 decoding corrupted
// them; Python keeps arbitrary-precision ints).
func TestKeystoreBigIntPreserved(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.keystore")
	m := testKeystoreMap(t)
	const big = "12345678901234567890123456789" // > 2^64, > 2^53
	m["big_counter"] = json.Number(big)
	if err := os.WriteFile(path, pythonFormat(t, m), 0o600); err != nil {
		t.Fatal(err)
	}
	ks, err := LoadKeystore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ks.Save(); err != nil {
		t.Fatal(err)
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zlib.NewReader(bytes.NewReader(blob[len(keystoreMagic):]))
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	dec := json.NewDecoder(zr)
	dec.UseNumber()
	if err := dec.Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	if got := string(decoded["big_counter"].(json.Number)); got != big {
		t.Errorf("big_counter = %s, want %s", got, big)
	}
}
