package idsauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
)

func TestShanghaiTechLoginAndDurableCounter(t *testing.T) {
	for _, failSave := range []bool{false, true} {
		t.Run(fmt.Sprintf("save_failure_%t", failSave), func(t *testing.T) {
			persisted, submitted := false, false
			var foreignCalls atomic.Int32
			service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				foreignCalls.Add(1)
			}))
			defer service.Close()
			var origin string
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/authserver/login":
					if r.Method == http.MethodGet {
						fmt.Fprint(w, `<input name="execution" value="synthetic-flow">`)
						return
					}
					submitted = true
					if !persisted {
						t.Error("assertion submitted before counter persistence")
					}
					if r.FormValue("username") != encodeUsername("12345678") || r.FormValue("execution") != "synthetic-flow" || r.FormValue("responseJson") == "" {
						t.Error("ShanghaiTech form fields changed")
					}
					http.SetCookie(w, &http.Cookie{Name: "CASTGC", Value: "synthetic-cookie", Path: "/"})
					http.Redirect(w, r, service.URL+"/", http.StatusSeeOther)
				case "/authserver/startAssertion":
					parsed, _ := url.Parse(origin)
					options := challengeOptions()
					options["rpId"] = parsed.Hostname()
					options["allowCredentials"] = []any{map[string]any{"id": "cred-id-b64url", "type": "public-key"}}
					json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"request": map[string]any{"requestId": "synthetic-request", "publicKeyCredentialRequestOptions": options}}})
				case "/personalInfo/common/tenant/info":
					if _, err := r.Cookie("CASTGC"); err != nil {
						w.WriteHeader(http.StatusUnauthorized)
					}
				default:
					t.Error("wrong school's login endpoint used")
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()
			origin = server.URL
			fields := testKeystoreMap(t)
			parsed, _ := url.Parse(origin)
			fields["base_url"] = origin
			fields["rp_id"] = parsed.Hostname()
			store, err := ParseKeystore(pythonFormat(t, fields), func([]byte) error {
				if failSave {
					return errors.New("synthetic storage failure")
				}
				persisted = true
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			hc := server.Client()
			hc.Jar, _ = cookiejar.New(nil)
			err = NewClient(store, hc).Login(context.Background())
			if foreignCalls.Load() != 0 {
				t.Fatal("login followed an external service instead of checking the identity session")
			}
			if failSave {
				if err == nil || submitted {
					t.Fatal("storage failure did not stop login")
				}
			} else if err != nil || !submitted {
				t.Fatalf("ShanghaiTech login failed: %v", err)
			}
		})
	}
}
