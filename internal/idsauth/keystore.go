// Package idsauth implements passwordless ShanghaiTech IDS login using a
// WebAuthn passkey, mirroring the third_party/shanghaitech-ids-passkey Python
// library (login only; passkey binding still happens through that library).
package idsauth

import (
	"bytes"
	"compress/zlib"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// keystoreMagic prefixes every default-format keystore file
// ("SHTUIDSPASSKEY" + 0x01), followed by zlib-compressed JSON.
var keystoreMagic = []byte("SHTUIDSPASSKEY\x01")

// Keystore is a passkey credential store compatible with the Python library's
// default binary format. All fields (including unrecognized ones) are kept in
// raw so a write-back never drops data the Python from_dict would require.
type Keystore struct {
	path string
	raw  map[string]any
}

// LoadKeystore reads and decodes a keystore file.
func LoadKeystore(path string) (*Keystore, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read keystore: %w", err)
	}
	if !bytes.HasPrefix(blob, keystoreMagic) {
		return nil, fmt.Errorf("keystore %s: unsupported format (missing magic); use the default binary format produced by `shanghaitech-ids-passkey bind`", path)
	}
	zr, err := zlib.NewReader(bytes.NewReader(blob[len(keystoreMagic):]))
	if err != nil {
		return nil, fmt.Errorf("keystore %s: zlib: %w", path, err)
	}
	defer zr.Close()
	payload, err := io.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("keystore %s: decompress: %w", path, err)
	}
	var raw map[string]any
	dec := json.NewDecoder(bytes.NewReader(payload))
	// UseNumber keeps unknown numeric fields exact across a load/save
	// round trip (float64 would corrupt integers above 2^53 that the
	// Python library preserves as arbitrary-precision ints).
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("keystore %s: decode json: %w", path, err)
	}
	k := &Keystore{path: path, raw: raw}
	if err := k.validate(); err != nil {
		return nil, fmt.Errorf("keystore %s: %w", path, err)
	}
	return k, nil
}

func (k *Keystore) validate() error {
	for _, field := range []string{
		"username", "anon_biometrics_id", "device_name", "base_url",
		"credential_id", "rp_id", "user_id", "private_key_pem",
	} {
		if s, _ := k.raw[field].(string); s == "" {
			return fmt.Errorf("missing or empty field %q", field)
		}
	}
	if _, err := k.alg(); err != nil {
		return err
	}
	if _, err := k.signCount(); err != nil {
		return err
	}
	return nil
}

// Path returns the file this keystore was loaded from.
func (k *Keystore) Path() string { return k.path }

func (k *Keystore) str(field string) string { s, _ := k.raw[field].(string); return s }

func (k *Keystore) alg() (int, error) {
	n, err := asInt(k.raw["alg"])
	if err != nil {
		return 0, fmt.Errorf("field alg must be an integer, got %T", k.raw["alg"])
	}
	return n, nil
}

func (k *Keystore) signCount() (int, error) {
	v, ok := k.raw["sign_count"]
	if !ok {
		return 0, nil
	}
	n, err := asInt(v)
	if err != nil {
		return 0, fmt.Errorf("field sign_count must be an integer, got %T", v)
	}
	return n, nil
}

// asInt accepts the representations an integer field may take: json.Number
// (UseNumber decoding), float64 (plain decoding) and native ints (tests).
func asInt(v any) (int, error) {
	switch n := v.(type) {
	case json.Number:
		i, err := n.Int64()
		return int(i), err
	case float64:
		return int(n), nil
	case int:
		return n, nil
	case int64:
		return int(n), nil
	default:
		return 0, fmt.Errorf("not an integer: %T", v)
	}
}

// Username is the IDS account name (student/staff id).
func (k *Keystore) Username() string { return k.str("username") }

// AnonBiometricsID identifies the passkey credential to the IDS server.
func (k *Keystore) AnonBiometricsID() string { return k.str("anon_biometrics_id") }

// CredentialID is the base64url WebAuthn credential id.
func (k *Keystore) CredentialID() string { return k.str("credential_id") }

// RpID is the relying party id (ids.shanghaitech.edu.cn).
func (k *Keystore) RpID() string { return k.str("rp_id") }

// UserID is the base64url user handle echoed in assertions.
func (k *Keystore) UserID() string { return k.str("user_id") }

// BaseURL is the IDS base URL recorded at bind time.
func (k *Keystore) BaseURL() string { return k.str("base_url") }

// PrivateKeyPEM is the passkey private key (PKCS#8/SEC1/PKCS#1 PEM).
func (k *Keystore) PrivateKeyPEM() string { return k.str("private_key_pem") }

// Alg is the COSE signing algorithm: -7 (ES256), -8 (EdDSA) or -257 (RS256).
func (k *Keystore) Alg() (int, error) { return k.alg() }

// SignCount is the current WebAuthn signature counter.
func (k *Keystore) SignCount() (int, error) { return k.signCount() }

// SetSignCount updates the counter after a successful assertion.
func (k *Keystore) SetSignCount(n int) { k.raw["sign_count"] = n }

// Save writes the keystore back to its file (0600, atomic), preserving every
// original field so the Python library can still load it.
func (k *Keystore) Save() error {
	payload, err := marshalNoEscape(k.raw)
	if err != nil {
		return fmt.Errorf("encode keystore: %w", err)
	}
	var buf bytes.Buffer
	buf.Write(keystoreMagic)
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(payload); err != nil {
		return fmt.Errorf("compress keystore: %w", err)
	}
	if err := zw.Close(); err != nil {
		return fmt.Errorf("compress keystore: %w", err)
	}
	if err := writeFileAtomic(k.path, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("write keystore: %w", err)
	}
	return nil
}

// marshalNoEscape encodes JSON compactly without HTML escaping. Map keys are
// sorted by encoding/json, matching the Python library's
// json.dumps(sort_keys=True, separators=(",", ":")).
func marshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// writeFileAtomic writes data to a temp file in the same directory and renames
// it over path, so a crash never leaves a half-written secret file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".keystore-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
