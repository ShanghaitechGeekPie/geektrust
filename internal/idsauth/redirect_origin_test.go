package idsauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestIdentityRequestDoesNotForwardAcrossOrigins(t *testing.T) {
	for _, status := range []int{http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var foreignCalls atomic.Int32
			foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				foreignCalls.Add(1)
			}))
			defer foreign.Close()
			identity := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, foreign.URL+"/collect", status)
			}))
			defer identity.Close()
			client := &Client{HTTP: identity.Client(), UserAgent: DefaultUserAgent}
			req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, identity.URL+"/authserver/login", strings.NewReader("assertion=identity-only"))
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if foreignCalls.Load() != 0 {
				t.Fatal("identity request was forwarded outside its origin")
			}
			if resp.StatusCode != status {
				t.Fatal("terminal redirect was lost")
			}
		})
	}
}

func TestIdentityRequestFollowsSameOriginRedirect(t *testing.T) {
	identity := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/result" {
			http.Redirect(w, r, "/result", http.StatusTemporaryRedirect)
			return
		}
		if r.Method != http.MethodPost {
			t.Error("same-origin redirect lost POST")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer identity.Close()
	client := &Client{HTTP: identity.Client(), UserAgent: DefaultUserAgent}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, identity.URL+"/authserver/login", strings.NewReader("assertion=identity-only"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatal("same-origin redirect failed")
	}
}
