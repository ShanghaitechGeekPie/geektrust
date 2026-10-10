package sdpc

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAmbiguousCASDomainDoesNotChangeSelection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `{"code":0,"data":{"security":{"csrfToken":"synthetic"},"authServerInfoList":[{"authType":"auth/cas","loginDomain":"first"},{"authType":"auth/cas","loginDomain":"second"}]}}`)
	}))
	defer server.Close()
	c := NewClient(server.URL, "Mac", "synthetic-device", server.Client())
	for i := 0; i < 2; i++ {
		if _, err := c.AuthConfig(context.Background(), true); err == nil {
			t.Fatal("ambiguous CAS selection accepted")
		}
		if c.LoginDomain != "" {
			t.Fatal("failed discovery changed the selected domain")
		}
	}
	if _, err := c.AuthConfig(context.Background(), false); err != nil {
		t.Fatal("custom controller login must not require CAS domain selection:", err)
	}
	c.LoginDomain = "explicit"
	if _, err := c.AuthConfig(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if c.LoginDomain != "explicit" {
		t.Fatal("explicit CAS domain was replaced")
	}
}
