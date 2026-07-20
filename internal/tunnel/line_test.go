package tunnel

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBestRequiresGatewayTLS(t *testing.T) {
	plain, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	accepted := make(chan struct{})
	go func() {
		conn, err := plain.Accept()
		if err == nil {
			close(accepted)
			conn.Close()
		}
	}()

	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer tlsServer.Close()
	tlsAddr := strings.TrimPrefix(tlsServer.URL, "https://")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	got, err := NewLines([]string{plain.Addr().String(), tlsAddr}).Best(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got != tlsAddr {
		t.Fatalf("Best() = %q, want TLS gateway %q", got, tlsAddr)
	}
	select {
	case <-accepted:
	case <-ctx.Done():
		t.Fatal("plain TCP endpoint was not probed")
	}
}
