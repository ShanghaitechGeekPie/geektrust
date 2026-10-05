package idsauth

import (
	"bytes"
	"context"
	"net/http"
	"net/http/cookiejar"
	"os"
	"testing"
	"time"
)

func TestECNUCredentialPersistence(t *testing.T) {
	fields := testKeystoreMap(t)
	delete(fields, "anon_biometrics_id")
	fields["base_url"] = "https://sso.ecnu.edu.cn"
	fields["rp_id"] = "sso.ecnu.edu.cn"
	blob := pythonFormat(t, fields)
	blob = append(append([]byte{}, ecnuMagic...), blob[len(keystoreMagic):]...)
	var saved []byte
	k, err := ParseKeystore(blob, func(b []byte) error { saved = append([]byte{}, b...); return nil })
	if err != nil {
		t.Fatal(err)
	}
	k.SetSignCount(42)
	if err = k.Save(); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(saved, ecnuMagic) {
		t.Fatal("format changed")
	}
	reloaded, err := ParseKeystore(saved, nil)
	if err != nil {
		t.Fatal(err)
	}
	count, _ := reloaded.SignCount()
	if count != 42 || reloaded.raw["some_future_field"] != "must-survive" {
		t.Fatal("credential fields were lost")
	}
	if err = reloaded.Save(); err == nil {
		t.Fatal("missing persistence accepted")
	}
}

// TestECNULiveLogin is opt-in and never logs credentials or server payloads.
// The credential counter is durably updated; do not run another signer concurrently.
func TestECNULiveLogin(t *testing.T) {
	if os.Getenv("GEEKTRUST_LIVE_TESTS") != "1" {
		t.Skip("online tests require explicit GEEKTRUST_LIVE_TESTS=1")
	}
	path := os.Getenv("GEEKTRUST_ECNU_KEYSTORE")
	if path == "" {
		t.Skip("explicit live credential required")
	}
	k, err := LoadKeystore(path)
	if err != nil {
		t.Fatal("cannot load live credential")
	}
	if k.BaseURL() != "https://sso.ecnu.edu.cn" {
		t.Fatal("unexpected credential origin")
	}
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar, Timeout: 20 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err = NewClient(k, hc).Login(ctx); err != nil {
		t.Fatal(err)
	}
}
