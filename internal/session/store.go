// Package session persists VPN session credentials and provides them to the
// tunnel on demand (CredentialProvider), re-logging in silently when they
// expire.
package session

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// State is the persisted session (encrypted, 0600).
type State struct {
	SID       string         `json:"sid"`
	DeviceID  string         `json:"device_id"`
	CsrfToken string         `json:"csrf_token"`
	Cookies   []CookieRecord `json:"cookies"`
	Gateways  []string       `json:"gateways,omitempty"`
	SignKey   string         `json:"sign_key,omitempty"`
	SavedAt   time.Time      `json:"saved_at"`
}

// CookieRecord is a serializable name/value cookie pair.
type CookieRecord struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Store encrypts State with AES-256-GCM under a random key kept in a sibling
// 0600 key file (<state_file>.key). The key is generated on first save; both
// files together protect credentials at rest while staying fully automatic
// (no passphrase to type).
type Store struct {
	path string
}

// NewStore creates a Store for the given state file path.
func NewStore(path string) *Store { return &Store{path: path} }

func (s *Store) keyPath() string { return s.path + ".key" }

// Load reads and decrypts the state. It returns (nil, nil) when no state file
// exists yet.
func (s *Store) Load() (*State, error) {
	sealed, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read state: %w", err)
	}
	key, err := s.readKey()
	if err != nil {
		return nil, fmt.Errorf("state key: %w", err)
	}
	plain, err := decrypt(key, sealed)
	if err != nil {
		return nil, fmt.Errorf("decrypt state: %w", err)
	}
	var st State
	if err := json.Unmarshal(plain, &st); err != nil {
		return nil, fmt.Errorf("decode state: %w", err)
	}
	return &st, nil
}

// Save encrypts and atomically writes the state.
func (s *Store) Save(st *State) error {
	st.SavedAt = time.Now()
	plain, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	key, err := s.loadOrCreateKey()
	if err != nil {
		return fmt.Errorf("state key: %w", err)
	}
	sealed, err := encrypt(key, plain)
	if err != nil {
		return fmt.Errorf("encrypt state: %w", err)
	}
	if err := writeFileAtomic(s.path, sealed, 0o600); err != nil {
		return fmt.Errorf("write state: %w", err)
	}
	return nil
}

func (s *Store) readKey() ([]byte, error) {
	path := s.keyPath()
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("%s: expected 32 bytes, got %d", path, len(key))
	}
	// Tighten a pre-existing permissive mode so the key never stays
	// group/world readable.
	if info, err := os.Stat(path); err == nil && info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, fmt.Errorf("%s: tighten permissions: %w", path, err)
		}
	}
	return key, nil
}

func (s *Store) loadOrCreateKey() ([]byte, error) {
	key, err := s.readKey()
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		// A present-but-invalid key file is fatal: we must never overwrite it
		// (that would destroy the only copy able to decrypt the state).
		return nil, err
	}
	// Create with O_EXCL: concurrent first-time saves (e.g. two processes)
	// can never overwrite each other's key, which would leave the other's
	// ciphertext permanently undecryptable. The loser reads the winner's key.
	key = make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(s.keyPath(), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return s.readKey()
		}
		return nil, err
	}
	_, werr := f.Write(key)
	cerr := f.Close()
	if werr != nil || cerr != nil {
		os.Remove(s.keyPath()) // never leave a half-written key behind
		if werr != nil {
			return nil, werr
		}
		return nil, cerr
	}
	return key, nil
}

// encrypt produces nonce(12) || AES-256-GCM ciphertext+tag.
func encrypt(key, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, nil), nil
}

func decrypt(key, sealed []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}

// writeFileAtomic writes via temp file + rename so secrets are never left
// half-written.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".state-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := io.WriteString(tmp, string(data)); err != nil {
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
