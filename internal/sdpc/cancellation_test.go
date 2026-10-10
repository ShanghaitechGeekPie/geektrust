package sdpc

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type cancellationTransport struct{ cause error }

func (t cancellationTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, &url.Error{Op: "Get", URL: "https://fixture.example/?ticket=secret", Err: t.cause}
}
func TestCASPreservesSafeCancellationCauses(t *testing.T) {
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		c := NewClient("https://controller.example", "Mac", "id", &http.Client{Transport: cancellationTransport{cause}})
		c.LoginDomain = "fixture"
		_, e := c.CasTicket(context.Background())
		if !errors.Is(e, cause) {
			t.Fatal("CAS lost the cancellation cause")
		}
		if strings.Contains(e.Error(), "secret") {
			t.Fatal("CAS exposed a credential-bearing URL")
		}
		var raw *url.Error
		if errors.As(e, &raw) {
			t.Fatal("CAS kept the raw URL error in its chain")
		}
	}
}
