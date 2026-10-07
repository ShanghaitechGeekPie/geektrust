package sdpc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestControllerAPIRejectsForeignRedirects(t *testing.T) {
	for _, status := range []int{http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var foreignCalls atomic.Int32
			foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				foreignCalls.Add(1)
				w.Write([]byte(`{"code":0}`))
			}))
			defer foreign.Close()
			controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, foreign.URL+"/collect", status)
			}))
			defer controller.Close()
			client := NewClient(controller.URL, "Mac", "device", controller.Client())
			client.SetCSRF("controller-only")
			if err := client.SessionIDExchange(context.Background(), "controller-only-ticket"); err == nil {
				t.Error("foreign response was accepted as controller success")
			}
			if foreignCalls.Load() != 0 {
				t.Fatal("controller API contacted a foreign origin")
			}
		})
	}
}

func TestControllerAPIRejectsHTTPSDowngrade(t *testing.T) {
	var plainCalls atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plainCalls.Add(1)
		w.Write([]byte(`{"code":0}`))
	}))
	defer plain.Close()
	controller := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/collect", http.StatusTemporaryRedirect)
	}))
	defer controller.Close()
	client := NewClient(controller.URL, "Mac", "device", controller.Client())
	if err := client.SessionIDExchange(context.Background(), "controller-only-ticket"); err == nil {
		t.Error("HTTPS downgrade was accepted")
	}
	if plainCalls.Load() != 0 {
		t.Fatal("controller API contacted a plaintext endpoint")
	}
}

func TestControllerAPIFollowsSameOriginRedirect(t *testing.T) {
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/result" {
			http.Redirect(w, r, "/result", http.StatusTemporaryRedirect)
			return
		}
		if r.Method != http.MethodPost || r.Header.Get("x-csrf-token") != "controller-only" {
			t.Error("same-origin redirect lost method or CSRF header")
		}
		w.Write([]byte(`{"code":0}`))
	}))
	defer controller.Close()
	client := NewClient(controller.URL, "Mac", "device", controller.Client())
	client.SetCSRF("controller-only")
	if err := client.SessionIDExchange(context.Background(), "controller-only-ticket"); err != nil {
		t.Fatal(err)
	}
}

func TestControllerAPIPreservesCallerRedirectRejection(t *testing.T) {
	var finalCalls atomic.Int32
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/result" {
			finalCalls.Add(1)
			w.Write([]byte(`{"code":0}`))
			return
		}
		http.Redirect(w, r, "/result", http.StatusTemporaryRedirect)
	}))
	defer controller.Close()
	rejected := errors.New("caller rejected redirect")
	hc := controller.Client()
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return rejected }
	client := NewClient(controller.URL, "Mac", "device", hc)
	if err := client.SessionIDExchange(context.Background(), "controller-only-ticket"); !errors.Is(err, rejected) {
		t.Fatalf("caller rejection lost: %v", err)
	}
	if finalCalls.Load() != 0 {
		t.Fatal("caller-rejected redirect was followed")
	}
}
