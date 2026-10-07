package idsauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestECNUFlow(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	script := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	for _, tc := range []struct {
		name     string
		failSave bool
		suffix   string
	}{
		{name: "storage_failure_false"},
		{name: "storage_failure_true", failSave: true},
		{name: "trailing_slash", suffix: "/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			persisted, submitted := false, false
			var origin string
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/login":
					if r.Method == "GET" {
						fmt.Fprint(w, `<input name="execution" value="test-flow">`)
						return
					}
					// The real server redirects to a different host. Login must
					// confirm the same-origin account session instead of following.
					http.Redirect(w, r, "https://unreachable.invalid/", http.StatusSeeOther)
				case "/public/webauthJs/webauthn.js":
					w.Write(script)
				case "/webauthn/authenticate":
					if r.Header.Get("hasCrypto") != "true" || r.Header.Get("privateKey") == "" {
						t.Error("missing transport envelope")
					}
					u, _ := url.Parse(origin)
					options := challengeOptions()
					options["rpId"] = u.Hostname()
					options["allowCredentials"] = []any{map[string]any{"id": "cred-id-b64url", "type": "public-key"}}
					json.NewEncoder(w).Encode(map[string]any{"success": true, "request": map[string]any{"requestId": "test-request", "publicKeyCredentialRequestOptions": options}, "actions": map[string]string{"finish": "/finish"}})
				case "/finish":
					submitted = true
					if !persisted {
						t.Error("submitted before durable counter update")
					}
					fmt.Fprint(w, `{"success":true,"sessionToken":"test-session"}`)
				case "/account":
					fmt.Fprint(w, `<span id="ps-username">12345678</span>`)
				default:
					t.Error("unexpected request")
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			origin = server.URL
			u, _ := url.Parse(origin)
			fields := testKeystoreMap(t)
			fields["base_url"], fields["rp_id"] = origin+tc.suffix, u.Hostname()
			blob := pythonFormat(t, fields)
			blob = append(append([]byte{}, ecnuMagic...), blob[len(keystoreMagic):]...)
			store, err := ParseKeystore(blob, func(b []byte) error {
				if tc.failSave {
					return errors.New("storage unavailable")
				}
				k, e := ParseKeystore(b, nil)
				if e != nil {
					return e
				}
				count, e := k.SignCount()
				if e != nil || count != 42 {
					t.Error("incorrect persisted counter")
				}
				persisted = true
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			err = NewClient(store, server.Client()).Login(context.Background())
			if tc.failSave {
				if err == nil || submitted {
					t.Fatal("failed persistence did not stop authentication")
				}
			} else if err != nil || !submitted {
				t.Fatalf("login failed: %v", err)
			}
		})
	}
}
