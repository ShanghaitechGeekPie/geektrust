package idsauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"testing"
)

func makeKeystore(t *testing.T, alg int, pemBytes []byte) *Keystore {
	t.Helper()
	return &Keystore{raw: map[string]any{
		"username":           "12345678",
		"anon_biometrics_id": "anon-id",
		"device_name":        "dev",
		"base_url":           "https://ids.shanghaitech.edu.cn",
		"credential_id":      "cred-123",
		"rp_id":              "ids.shanghaitech.edu.cn",
		"user_id":            "handle-456",
		"alg":                alg,
		"private_key_pem":    string(pemBytes),
		"sign_count":         10,
		"created_at":         "2024-01-01T00:00:00Z",
	}}
}

func challengeOptions() map[string]any {
	return map[string]any{
		"rpId":      "ids.shanghaitech.edu.cn",
		"challenge": base64.RawURLEncoding.EncodeToString([]byte("server-challenge-bytes")),
		"allowCredentials": []any{
			map[string]any{"id": "cred-123", "type": "public-key"},
		},
	}
}

// verifyAssertion decodes the assertion and cryptographically verifies every
// WebAuthn invariant against the public key.
func verifyAssertion(t *testing.T, assertionJSON []byte, alg int, pub crypto.PublicKey, wantCount int) {
	t.Helper()
	var a struct {
		Type     string `json:"type"`
		ID       string `json:"id"`
		Response struct {
			AuthenticatorData string `json:"authenticatorData"`
			ClientDataJSON    string `json:"clientDataJSON"`
			Signature         string `json:"signature"`
			UserHandle        string `json:"userHandle"`
		} `json:"response"`
		ClientExtensionResults map[string]any `json:"clientExtensionResults"`
	}
	if err := json.Unmarshal(assertionJSON, &a); err != nil {
		t.Fatalf("assertion is not JSON: %v", err)
	}
	if a.Type != "public-key" || a.ID != "cred-123" {
		t.Errorf("type/id = %q/%q", a.Type, a.ID)
	}
	if a.Response.UserHandle != "handle-456" {
		t.Errorf("userHandle = %q", a.Response.UserHandle)
	}
	if a.ClientExtensionResults == nil {
		t.Error("clientExtensionResults must be present (empty object)")
	}

	authData, err := base64.RawURLEncoding.DecodeString(a.Response.AuthenticatorData)
	if err != nil || len(authData) != 37 {
		t.Fatalf("authenticatorData len=%d err=%v", len(authData), err)
	}
	rpHash := sha256.Sum256([]byte("ids.shanghaitech.edu.cn"))
	if string(authData[:32]) != string(rpHash[:]) {
		t.Error("authData rpIdHash mismatch")
	}
	if authData[32] != 0x01 { // UP flag, no UV
		t.Errorf("authData flags = 0x%02x", authData[32])
	}
	if got := binary.BigEndian.Uint32(authData[33:37]); got != uint32(wantCount) {
		t.Errorf("authData signCount = %d, want %d", got, wantCount)
	}

	clientData, err := base64.RawURLEncoding.DecodeString(a.Response.ClientDataJSON)
	if err != nil {
		t.Fatal(err)
	}
	// Canonical JSON: keys sorted, compact.
	wantClientData := `{"challenge":"` + challengeOptions()["challenge"].(string) +
		`","crossOrigin":false,"origin":"https://ids.shanghaitech.edu.cn","type":"webauthn.get"}`
	if string(clientData) != wantClientData {
		t.Errorf("clientDataJSON = %s\nwant %s", clientData, wantClientData)
	}

	sig, err := base64.RawURLEncoding.DecodeString(a.Response.Signature)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(clientData)
	signed := append(append([]byte{}, authData...), digest[:]...)

	switch alg {
	case algES256:
		d := sha256.Sum256(signed)
		if !ecdsa.VerifyASN1(pub.(*ecdsa.PublicKey), d[:], sig) {
			t.Error("ES256 signature does not verify")
		}
	case algEdDSA:
		if !ed25519.Verify(pub.(ed25519.PublicKey), signed, sig) {
			t.Error("EdDSA signature does not verify")
		}
	case algRS256:
		d := sha256.Sum256(signed)
		if err := rsa.VerifyPKCS1v15(pub.(*rsa.PublicKey), crypto.SHA256, d[:], sig); err != nil {
			t.Errorf("RS256 signature does not verify: %v", err)
		}
	}
}

func TestBuildAssertionES256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	ks := makeKeystore(t, algES256, pemBytes)

	assertionJSON, newCount, err := buildAssertion(challengeOptions(), ks, "https://ids.shanghaitech.edu.cn")
	if err != nil {
		t.Fatalf("buildAssertion: %v", err)
	}
	if newCount != 11 {
		t.Errorf("newCount = %d, want 11", newCount)
	}
	verifyAssertion(t, assertionJSON, algES256, key.Public(), 11)
}

func TestBuildAssertionEdDSA(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	ks := makeKeystore(t, algEdDSA, pemBytes)

	assertionJSON, _, err := buildAssertion(challengeOptions(), ks, "https://ids.shanghaitech.edu.cn")
	if err != nil {
		t.Fatalf("buildAssertion: %v", err)
	}
	verifyAssertion(t, assertionJSON, algEdDSA, pub, 11)
}

func TestBuildAssertionRS256(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	ks := makeKeystore(t, algRS256, pemBytes)

	assertionJSON, _, err := buildAssertion(challengeOptions(), ks, "https://ids.shanghaitech.edu.cn")
	if err != nil {
		t.Fatalf("buildAssertion: %v", err)
	}
	verifyAssertion(t, assertionJSON, algRS256, key.Public(), 11)
}

func TestBuildAssertionRpIDMismatch(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	ks := makeKeystore(t, algES256, pemBytes)

	opts := challengeOptions()
	opts["rpId"] = "evil.example.com"
	if _, _, err := buildAssertion(opts, ks, "https://ids.shanghaitech.edu.cn"); err == nil {
		t.Fatal("expected rpId/origin mismatch error")
	}
}

func TestBuildAssertionCredentialNotAllowed(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	ks := makeKeystore(t, algES256, pemBytes)

	opts := challengeOptions()
	opts["allowCredentials"] = []any{map[string]any{"id": "some-other-cred"}}
	if _, _, err := buildAssertion(opts, ks, "https://ids.shanghaitech.edu.cn"); err == nil {
		t.Fatal("expected allowCredentials rejection")
	}
}
