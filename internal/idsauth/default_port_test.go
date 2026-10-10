package idsauth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
)

type identityTransportFunc func(*http.Request) (*http.Response, error)

func (f identityTransportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestShanghaiTechLoginCompletesDefaultPortRedirect(t *testing.T) {
	const host = "ids.example.edu.cn"
	for _, destination := range []string{host + ":443", "IDS.example.edu.cn:443"} {
		t.Run(destination, func(t *testing.T) {
			persisted, completed := false, false
			transport := identityTransportFunc(func(r *http.Request) (*http.Response, error) {
				response := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Request: r}
				body := ""
				switch r.URL.Path {
				case "/authserver/login":
					if r.Method == http.MethodGet {
						body = `<input name="execution" value="synthetic-flow">`
					} else {
						if !persisted {
							t.Error("assertion submitted before counter persistence")
						}
						response.StatusCode = http.StatusFound
						response.Header.Set("Location", "https://"+destination+"/authserver/index.do")
					}
				case "/authserver/startAssertion":
					options := challengeOptions()
					options["rpId"] = host
					options["allowCredentials"] = []any{map[string]any{"id": "cred-id-b64url", "type": "public-key"}}
					payload, _ := json.Marshal(map[string]any{"result": map[string]any{"request": map[string]any{"requestId": "synthetic-request", "publicKeyCredentialRequestOptions": options}}})
					body = string(payload)
				case "/authserver/index.do":
					completed = true
					response.Header.Set("Set-Cookie", "identity-session=synthetic; Path=/; Secure")
				case "/personalInfo/common/tenant/info":
					if _, err := r.Cookie("identity-session"); err != nil {
						response.StatusCode = http.StatusUnauthorized
					}
				default:
					t.Fatalf("unexpected login request: %s", r.URL.Path)
				}
				response.Body = io.NopCloser(strings.NewReader(body))
				return response, nil
			})
			fields := testKeystoreMap(t)
			fields["base_url"], fields["rp_id"] = "https://"+host, host
			store, err := ParseKeystore(pythonFormat(t, fields), func([]byte) error { persisted = true; return nil })
			if err != nil {
				t.Fatal(err)
			}
			jar, _ := cookiejar.New(nil)
			if err := NewClient(store, &http.Client{Jar: jar, Transport: transport}).Login(context.Background()); err != nil {
				t.Fatal(err)
			}
			if !completed {
				t.Fatal("default-port login completion was skipped")
			}
		})
	}
}
