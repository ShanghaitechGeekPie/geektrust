package l3

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"syscall"
	"testing"
)

func TestDialWithRetryStopsOnConnectionRefused(t *testing.T) {
	dialer := &Dialer{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	calls := 0
	_, err := dialer.dialWithRetry(context.Background(), "tcp", "10.19.130.42", 443, func() (net.Conn, error) {
		calls++
		return nil, &net.OpError{Op: "connect", Net: "tcp", Err: syscall.ECONNREFUSED}
	})
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("error = %v, want ECONNREFUSED", err)
	}
	if calls != 1 {
		t.Fatalf("dial calls = %d, want 1", calls)
	}
}

func TestShouldRetryDial(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{name: "gateway busy", err: &AuthRejectedError{Code: 10000008}, want: true},
		{name: "line switch", err: &AuthRejectedError{Code: 1001, SwitchLine: true}, want: true},
		{name: "persistent rejection", err: &AuthRejectedError{Code: 10000005}, want: false},
		{name: "connection refused", err: syscall.ECONNREFUSED, want: false},
		{name: "handshake timeout", err: context.DeadlineExceeded, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldRetryDial(tc.err); got != tc.want {
				t.Fatalf("shouldRetryDial(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
