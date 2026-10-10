package sdpc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPErrorPreservesSessionExpiryCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"code":%d,"message":"expired"}`, CodeSessionMissing)
	}))
	defer server.Close()
	c := NewClient(server.URL, "Mac", "device", server.Client())
	_, err := c.OnlineInfo(context.Background())
	var api *APIError
	if !IsSessionExpired(err) || !errors.As(err, &api) || api.Code != CodeSessionMissing {
		t.Fatalf("HTTP error lost its controller code: %v", err)
	}
}

func TestHTTPErrorWithoutEnvelopeKeepsStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	c := NewClient(server.URL, "Mac", "device", server.Client())
	_, err := c.OnlineInfo(context.Background())
	if err == nil || !strings.Contains(err.Error(), "HTTP 503") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMissingResponseCodeIsNotSuccess(t *testing.T) {
	if err := parseEnvelope([]byte(`{"data":{}}`), nil); err == nil {
		t.Fatal("missing controller code treated as success")
	}
}

func TestRedirectStatusIsNotAPISuccess(t *testing.T) {
	for _, status := range []int{http.StatusMultipleChoices, http.StatusTemporaryRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				fmt.Fprint(w, `{"code":0}`)
			}))
			defer server.Close()
			client := NewClient(server.URL, "Mac", "device", server.Client())
			err := client.SessionIDExchange(context.Background(), "fixture-ticket")
			if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("HTTP %d", status)) {
				t.Fatalf("non-success HTTP status was ignored: %v", err)
			}
		})
	}
}
