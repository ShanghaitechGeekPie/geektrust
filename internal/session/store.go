// Package session persists VPN session credentials and provides them to the
// tunnel on demand (CredentialProvider), re-logging in silently when they
// expire.
package session

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/ShanghaitechGeekPie/geektrust/internal/storage"
)

// State is the persisted session (encrypted, 0600).
type State struct {
	Version         int    `json:"version"`
	ControllerURL   string `json:"controller_url"`
	IdentityIssuer  string `json:"identity_issuer"`
	IdentitySubject string `json:"identity_subject"`
	IdentityKind    string `json:"identity_kind"`
	LoginDomain     string `json:"login_domain"`
	Username        string `json:"username"`

	SID       string         `json:"sid"`
	DeviceID  string         `json:"device_id"`
	CsrfToken string         `json:"csrf_token"`
	Cookies   []CookieRecord `json:"cookies"`
	Gateways  []string       `json:"gateways,omitempty"`
	// ClientType records the login path that established this session
	// ("browser" or "client"). Restoring a session whose mode differs from
	// the current config would use the wrong server-side session mode, so
	// the provider skips restore and performs a full login instead.
	ClientType string    `json:"client_type,omitempty"`
	SavedAt    time.Time `json:"saved_at"`
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
func (s *Store) Load(ctx context.Context) (*State, error) {
	b, e := s.LoadBytes(ctx)
	if e != nil || len(b) == 0 {
		return nil, e
	}
	var st State
	if e = json.Unmarshal(b, &st); e != nil {
		return nil, e
	}
	return &st, nil
}
func (s *Store) Save(ctx context.Context, st *State) error {
	v := *st
	v.SavedAt = time.Now()
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	return s.SaveBytes(ctx, b)
}
func (s *Store) LoadBytes(ctx context.Context) ([]byte, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	sealed, e := os.ReadFile(s.path)
	if errors.Is(e, os.ErrNotExist) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	key, e := s.readKey()
	if e != nil {
		return nil, e
	}
	return decrypt(key, sealed)
}
func (s *Store) SaveBytes(ctx context.Context, b []byte) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	key, e := s.loadOrCreateKey()
	if e != nil {
		return e
	}
	sealed, e := encrypt(key, b)
	if e != nil {
		return e
	}
	return storage.WriteAtomic(s.path, sealed, 0600)
}
func (s *Store) Delete(ctx context.Context) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	e := os.Remove(s.path)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	return e
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
	return key, nil
}

func (s *Store) loadOrCreateKey() ([]byte, error) {
	key, e := s.readKey()
	if e == nil {
		return key, nil
	}
	if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	key = make([]byte, 32)
	if _, e = rand.Read(key); e != nil {
		return nil, e
	}
	if e = storage.CreateExclusive(s.keyPath(), key); errors.Is(e, os.ErrExist) {
		return s.readKey()
	} else if e != nil {
		return nil, e
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

// StateStore persists session state; embedding applications can supply protected storage.
type StateStore interface {
	Load(context.Context) (*State, error)
	Save(context.Context, *State) error
}

func (p *Provider) SetStore(store StateStore) { p.store = store }
