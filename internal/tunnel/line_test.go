package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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
	lines := NewLines([]string{plain.Addr().String(), tlsAddr})
	roots := x509.NewCertPool()
	roots.AddCert(tlsServer.Certificate())
	lines.TLSConfig = &tls.Config{RootCAs: roots}
	got, err := lines.bestForTest(ctx)
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

func TestGatewayTLSRejectsUntrustedCertificateByDefault(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	addr := strings.TrimPrefix(server.URL, "https://")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := NewLines([]string{addr}).bestForTest(ctx); err == nil {
		t.Fatal("untrusted gateway certificate was accepted")
	}
}

type testPinStore struct {
	mu   sync.Mutex
	pins map[string][]byte
}

func (s *testPinStore) LoadPin(_ context.Context, addr string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.pins[addr]...), nil
}
func (s *testPinStore) SavePin(_ context.Context, addr string, pin []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pins[addr] = append([]byte(nil), pin...)
	return nil
}

func TestGatewayTrustOnFirstUsePinsPublicKey(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	addr := strings.TrimPrefix(server.URL, "https://")
	store := &testPinStore{pins: map[string][]byte{}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	newLines := func() *Lines { l := NewLines([]string{addr}); l.GatewayTrustStore = store; return l }
	if _, err := newLines().bestForTest(ctx); err != nil {
		t.Fatal(err)
	}
	if pin, _ := store.LoadPin(ctx, addr); len(pin) != 32 {
		t.Fatal("gateway public key was not persisted")
	}
	if _, err := newLines().bestForTest(ctx); err != nil {
		t.Fatalf("matching gateway pin rejected: %v", err)
	}
	store.SavePin(ctx, addr, make([]byte, 32))
	if _, err := newLines().bestForTest(ctx); err == nil || !strings.Contains(err.Error(), "public key changed") {
		t.Fatalf("changed gateway key accepted: %v", err)
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
	lines := NewLines([]string{stalled.Addr().String(), tlsAddr})
	roots := x509.NewCertPool()
	roots.AddCert(tlsServer.Certificate())
	lines.TLSConfig = &tls.Config{RootCAs: roots}
	conn, addr, err := lines.DialTLS(ctx)
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

func (l *Lines) bestForTest(ctx context.Context) (string, error) {
	conn, addr, err := l.DialTLS(ctx)
	if conn != nil {
		conn.Close()
	}
	return addr, err
}
