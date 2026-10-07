package sdpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
)

func TestCasTicketRejectsForeignShortcut(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusNotFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
			defer foreign.Close()
			controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, foreign.URL+"/portal/shortcut.html?data="+url.QueryEscape(`{"ticket":"foreign-ticket"}`), http.StatusFound)
			}))
			defer controller.Close()
			client := NewClient(controller.URL, "Mac", "device", controller.Client())
			client.LoginDomain = "fixture"
			if ticket, err := client.CasTicket(context.Background()); err == nil {
				t.Fatalf("accepted a foreign shortcut ticket: %q", ticket)
			}
		})
	}
}

func TestCasTicketAcceptsControllerShortcutRedirect(t *testing.T) {
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/portal/shortcut.html?data="+url.QueryEscape(`{"ticket":"controller-ticket"}`), http.StatusFound)
	}))
	defer controller.Close()
	client := NewClient(controller.URL, "Mac", "device", controller.Client())
	client.LoginDomain = "fixture"
	ticket, err := client.CasTicket(context.Background())
	if err != nil || ticket != "controller-ticket" {
		t.Fatalf("controller shortcut = %q, %v", ticket, err)
	}
}

func TestCasTicketRejectsHTTPSDowngrade(t *testing.T) {
	var calls atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(http.StatusOK) }))
	defer plain.Close()
	controller := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/login", http.StatusFound)
	}))
	defer controller.Close()
	client := NewClient(controller.URL, "Mac", "device", controller.Client())
	client.LoginDomain = "fixture"
	_, err := client.CasTicket(context.Background())
	if err == nil {
		t.Fatal("HTTPS downgrade was accepted")
	}
	if calls.Load() != 0 {
		t.Fatal("CAS redirect contacted a plaintext endpoint")
	}
}

func TestCasTicketFollowsHTTPSIdentityProvider(t *testing.T) {
	var controllerURL string
	identity := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-csrf-token") != "" {
			t.Error("controller CSRF token reached the identity provider")
		}
		http.Redirect(w, r, controllerURL+"/portal/shortcut.html?data="+url.QueryEscape(`{"ticket":"controller-ticket"}`), http.StatusFound)
	}))
	defer identity.Close()
	controller := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, identity.URL+"/login", http.StatusFound)
	}))
	defer controller.Close()
	controllerURL = controller.URL
	roots := x509.NewCertPool()
	roots.AddCert(controller.Certificate())
	roots.AddCert(identity.Certificate())
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: roots}
	defer transport.CloseIdleConnections()
	client := NewClient(controller.URL, "Mac", "device", &http.Client{Transport: transport})
	client.LoginDomain = "fixture"
	client.SetCSRF("controller-only")
	ticket, err := client.CasTicket(context.Background())
	if err != nil || ticket != "controller-ticket" {
		t.Fatalf("HTTPS identity chain = %q, %v", ticket, err)
	}
}
