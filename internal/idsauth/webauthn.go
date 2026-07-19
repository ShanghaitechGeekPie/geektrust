package idsauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"net/url"
	"strings"
)

// COSE algorithm identifiers used by the IDS server.
const (
	algES256 = -7
	algEdDSA = -8
	algRS256 = -257
)

// assertion is the WebAuthn PublicKeyCredential object posted inside
// responseJson. Field order is irrelevant to the server (only clientDataJSON
// bytes are signed), but kept close to the WebAuthn spec for readability.
type assertion struct {
	Type                   string            `json:"type"`
	ID                     string            `json:"id"`
	Response               assertionResponse `json:"response"`
	ClientExtensionResults map[string]any    `json:"clientExtensionResults"`
}

type assertionResponse struct {
	AuthenticatorData string `json:"authenticatorData"`
	ClientDataJSON    string `json:"clientDataJSON"`
	Signature         string `json:"signature"`
	UserHandle        string `json:"userHandle,omitempty"`
}

// clientDataJSON must serialize with sorted keys to match the canonical JSON
// the signature is computed over (Python json.dumps(sort_keys=True)):
// challenge, crossOrigin, origin, type.
type clientDataJSON struct {
	Challenge   string `json:"challenge"`
	CrossOrigin bool   `json:"crossOrigin"`
	Origin      string `json:"origin"`
	Type        string `json:"type"`
}

// buildAssertion creates a WebAuthn assertion for the server challenge in
// requestOptions (result.request.publicKeyCredentialRequestOptions) and
// returns its JSON encoding plus the incremented sign count.
func buildAssertion(requestOptions map[string]any, k *Keystore, origin string) ([]byte, int, error) {
	rpID, _ := requestOptions["rpId"].(string)
	challenge, _ := requestOptions["challenge"].(string)
	if rpID == "" || challenge == "" {
		return nil, 0, fmt.Errorf("startAssertion: missing rpId or challenge")
	}
	if !rpIDMatchesOrigin(rpID, origin) {
		return nil, 0, fmt.Errorf("origin %q does not match rpId %q", origin, rpID)
	}

	// If the server restricts allowed credentials, ours must be listed.
	if allow, ok := requestOptions["allowCredentials"].([]any); ok && len(allow) > 0 {
		found := false
		for _, item := range allow {
			if m, ok := item.(map[string]any); ok {
				if id, _ := m["id"].(string); id == k.CredentialID() {
					found = true
					break
				}
			}
		}
		if !found {
			return nil, 0, fmt.Errorf("stored credential is not in allowCredentials")
		}
	}

	alg, err := k.Alg()
	if err != nil {
		return nil, 0, err
	}
	count, err := k.SignCount()
	if err != nil {
		return nil, 0, err
	}
	newCount := count + 1

	authData := buildAuthenticatorData(rpID, newCount)
	clientData, err := marshalNoEscape(clientDataJSON{
		Challenge:   challenge,
		CrossOrigin: false,
		Origin:      origin,
		Type:        "webauthn.get",
	})
	if err != nil {
		return nil, 0, fmt.Errorf("encode clientDataJSON: %w", err)
	}
	digest := sha256.Sum256(clientData)
	signature, err := signAssertion(k.PrivateKeyPEM(), alg, append(authData, digest[:]...))
	if err != nil {
		return nil, 0, err
	}

	b64url := base64.RawURLEncoding.EncodeToString
	a := assertion{
		Type: "public-key",
		ID:   k.CredentialID(),
		Response: assertionResponse{
			AuthenticatorData: b64url(authData),
			ClientDataJSON:    b64url(clientData),
			Signature:         b64url(signature),
			UserHandle:        k.UserID(),
		},
		ClientExtensionResults: map[string]any{},
	}
	payload, err := marshalNoEscape(a)
	if err != nil {
		return nil, 0, fmt.Errorf("encode assertion: %w", err)
	}
	return payload, newCount, nil
}

// buildAuthenticatorData: SHA-256(rpId) || flags(UP=0x01) || BE32(signCount).
func buildAuthenticatorData(rpID string, signCount int) []byte {
	hash := sha256.Sum256([]byte(rpID))
	out := make([]byte, 0, 37)
	out = append(out, hash[:]...)
	out = append(out, 0x01)
	var cnt [4]byte
	binary.BigEndian.PutUint32(cnt[:], uint32(signCount))
	return append(out, cnt[:]...)
}

func rpIDMatchesOrigin(rpID, origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return false
	}
	host := u.Hostname()
	return host == rpID || strings.HasSuffix(host, "."+rpID)
}

// signAssertion signs payload per COSE alg. ES256/RS256 sign SHA-256(payload);
// EdDSA signs the raw payload. ES256 produces a DER (ASN.1) signature, matching
// Python cryptography's ec.ECDSA(SHA256) output.
func signAssertion(pemText string, alg int, payload []byte) ([]byte, error) {
	key, err := parsePrivateKey(pemText)
	if err != nil {
		return nil, err
	}
	switch alg {
	case algES256:
		ecKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("alg ES256 requires an ECDSA key, got %T", key)
		}
		digest := sha256.Sum256(payload)
		return ecdsa.SignASN1(rand.Reader, ecKey, digest[:])
	case algEdDSA:
		edKey, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("alg EdDSA requires an Ed25519 key, got %T", key)
		}
		return ed25519.Sign(edKey, payload), nil
	case algRS256:
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("alg RS256 requires an RSA key, got %T", key)
		}
		digest := sha256.Sum256(payload)
		return rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, digest[:])
	default:
		return nil, fmt.Errorf("unsupported COSE alg: %d", alg)
	}
}

// parsePrivateKey accepts PKCS#8, SEC 1 (EC) and PKCS#1 PEM encodings, like
// Python cryptography's load_pem_private_key.
func parsePrivateKey(pemText string) (any, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, fmt.Errorf("no PEM block in private_key_pem")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("unable to parse private key (tried PKCS#8, SEC 1, PKCS#1)")
}
