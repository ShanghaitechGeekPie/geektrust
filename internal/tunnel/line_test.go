package tunnel

import (
	"bufio"
	"context"
	"fmt"
	"io"
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

func TestDialTLSReturnsLiveWinnerWithoutWaitingForStalledLine(t *testing.T) {
	stalled, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer stalled.Close()
	go func() {
		conn, err := stalled.Accept()
		if err == nil {
			defer conn.Close()
			_, _ = io.Copy(io.Discard, conn)
		}
	}()

	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer tlsServer.Close()
	tlsAddr := strings.TrimPrefix(tlsServer.URL, "https://")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	started := time.Now()
	conn, addr, err := NewLines([]string{stalled.Addr().String(), tlsAddr}).DialTLS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if addr != tlsAddr {
		t.Fatalf("DialTLS() address = %q, want %q", addr, tlsAddr)
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("DialTLS() waited %s for stalled line", elapsed)
	}
	if _, err := fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "204") {
		t.Fatalf("reused winner returned %q", status)
	}
}

func TestReportSuccessPrefersWinner(t *testing.T) {
	lines := NewLines([]string{"first", "second", "third"})
	lines.ReportSuccess("third")
	if got := lines.Addrs(); len(got) != 3 || got[0] != "third" {
		t.Fatalf("Addrs() = %v", got)
	}
}

func TestAllLinesTriedIncludesRecentTLSFailures(t *testing.T) {
	lines := NewLines([]string{"auth-rejected", "tls-failed"})
	tried := map[string]bool{"auth-rejected": true}
	if lines.allLinesTried(tried) {
		t.Fatal("unattempted healthy line must remain eligible")
	}
	lines.ReportFailure("tls-failed")
	if !lines.allLinesTried(tried) {
		t.Fatal("recent TLS failure must count as an attempted line")
	}
	lines.failed["tls-failed"] = time.Now().Add(-failCooldown - time.Second)
	if lines.allLinesTried(tried) {
		t.Fatal("expired TLS failure must be attempted again")
	}
}
