package webui

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"geektrust/internal/sdpc"
)

type promptResult struct {
	code string
	err  error
}

func startPrompt(b *Broker, resend func(context.Context) error) (chan promptResult, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan promptResult, 1)
	go func() {
		code, err := b.Prompt(ctx, resend)
		ch <- promptResult{code, err}
	}()
	return ch, cancel
}

// waitArmed polls until the broker has an armed pending generation.
func waitArmed(t *testing.T, b *Broker) uint64 {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		b.mu.Lock()
		if b.pending != nil {
			gen := b.pending.gen
			b.mu.Unlock()
			return gen
		}
		b.mu.Unlock()
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("prompt did not arm")
	return 0
}

func recvPrompt(t *testing.T, ch chan promptResult) promptResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(3 * time.Second):
		t.Fatal("prompt did not return")
	}
	return promptResult{}
}

func TestBrokerWebThenTerminal(t *testing.T) {
	pipeR, pipeW := io.Pipe()
	b := NewBroker(func(bool, uint64) {})
	b.stdin = pipeR
	defer pipeR.Close()
	defer pipeW.Close()

	// First generation: web wins.
	ch1, cancel1 := startPrompt(b, nil)
	defer cancel1()
	gen1 := waitArmed(t, b)
	if err := b.ClaimWeb("111111", gen1); err != nil {
		t.Fatalf("web claim: %v", err)
	}
	if r := recvPrompt(t, ch1); r.err != nil || r.code != "111111" {
		t.Fatalf("first prompt = %+v", r)
	}

	// Second generation: the SAME persistent stdin reader must deliver the
	// next code (regression: an orphaned scanner swallowing it).
	ch2, cancel2 := startPrompt(b, nil)
	defer cancel2()
	waitArmed(t, b)
	if _, err := io.WriteString(pipeW, "222222\n"); err != nil {
		t.Fatal(err)
	}
	if r := recvPrompt(t, ch2); r.err != nil || r.code != "222222" {
		t.Fatalf("second prompt = %+v", r)
	}
}

func TestBrokerStdinReaderDelivers(t *testing.T) {
	b := NewBroker(func(bool, uint64) {})
	b.stdin = strings.NewReader("not-a-code\n123456\n")
	ch, cancel := startPrompt(b, nil)
	defer cancel()
	// The reader may claim before any arming observation; just wait for the
	// prompt result (non-digit lines are ignored, the code is delivered).
	if r := recvPrompt(t, ch); r.err != nil || r.code != "123456" {
		t.Fatalf("stdin reader prompt = %+v", r)
	}
}

func TestBrokerClaimArbitration(t *testing.T) {
	b := NewBroker(func(bool, uint64) {})
	ch, cancel := startPrompt(b, nil)
	defer cancel()
	gen := waitArmed(t, b)

	if err := b.ClaimWeb("654321", gen+1); !errors.Is(err, ErrNoPending) {
		t.Fatalf("gen mismatch = %v", err)
	}
	if err := b.ClaimWeb("654321", gen); err != nil {
		t.Fatalf("first claim = %v", err)
	}
	// Only one claim succeeds; the web loser gets 409-mapped ErrNoPending.
	if err := b.ClaimWeb("654321", gen); !errors.Is(err, ErrNoPending) {
		t.Fatalf("second claim = %v", err)
	}
	if r := recvPrompt(t, ch); r.err != nil || r.code != "654321" {
		t.Fatalf("prompt = %+v", r)
	}
}

func TestBrokerClaimBeatsCancellation(t *testing.T) {
	b := NewBroker(func(bool, uint64) {})
	ch, cancel := startPrompt(b, nil)
	gen := waitArmed(t, b)
	if err := b.ClaimWeb("123456", gen); err != nil {
		t.Fatalf("claim = %v", err)
	}
	cancel() // the claim already won arbitration
	if r := recvPrompt(t, ch); r.err != nil || r.code != "123456" {
		t.Fatalf("claimed prompt lost to cancellation: %+v", r)
	}
}

func TestBrokerCancellationClosesGeneration(t *testing.T) {
	b := NewBroker(func(bool, uint64) {})
	ch, cancel := startPrompt(b, nil)
	gen := waitArmed(t, b)
	cancel()
	if r := recvPrompt(t, ch); r.err == nil {
		t.Fatal("canceled prompt returned a code")
	}
	if err := b.ClaimWeb("123456", gen); !errors.Is(err, ErrNoPending) {
		t.Fatalf("claim after cancellation = %v", err)
	}
}

func TestBrokerResend(t *testing.T) {
	b := NewBroker(func(bool, uint64) {})

	if err := b.Resend(context.Background(), 1); !errors.Is(err, ErrNoPending) {
		t.Fatalf("resend without pending = %v", err)
	}

	var calls int
	resendFn := func(context.Context) error { calls++; return nil }
	ch, cancel := startPrompt(b, resendFn)
	defer cancel()
	gen := waitArmed(t, b)
	if err := b.Resend(context.Background(), gen); err != nil {
		t.Fatalf("resend = %v", err)
	}
	if calls != 1 {
		t.Fatalf("resend closure ran %d times", calls)
	}

	// After a successful claim the first validation rejects a resend.
	if err := b.ClaimWeb("123456", gen); err != nil {
		t.Fatalf("claim = %v", err)
	}
	if err := b.Resend(context.Background(), gen); !errors.Is(err, ErrNoPending) {
		t.Fatalf("resend after claim = %v", err)
	}
	if calls != 1 {
		t.Fatal("resend closure ran after claim")
	}
	recvPrompt(t, ch)
}

// TestBrokerResendSecondValidation forces a resend to arrive at the opMu
// gate while another resend holds it, then resolves the generation: the
// waiting resend must fail its second validation without invoking the
// closure.
func TestBrokerResendSecondValidation(t *testing.T) {
	b := NewBroker(func(bool, uint64) {})
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	blocking := func(context.Context) error {
		once.Do(func() { close(entered) })
		<-release
		return nil
	}
	ch, cancel := startPrompt(b, blocking)
	defer cancel()
	gen := waitArmed(t, b)

	resendA := make(chan error, 1)
	go func() { resendA <- b.Resend(context.Background(), gen) }()
	<-entered // A holds the generation's opMu inside its closure

	// B queues behind opMu; the claim then resolves the generation.
	resendB := make(chan error, 1)
	go func() {
		resendB <- b.Resend(context.Background(), gen)
	}()
	// Wait until B has passed its first validation and is queued on opMu.
	deadline := time.Now().Add(3 * time.Second)
	for {
		b.mu.Lock()
		var waiters int
		if b.pending != nil {
			waiters = b.pending.opWaiters
		}
		b.mu.Unlock()
		if waiters == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("resend B did not reach the opMu gate")
		}
		time.Sleep(2 * time.Millisecond)
	}
	if err := b.ClaimWeb("123456", gen); err != nil {
		t.Fatalf("claim during resend = %v", err)
	}
	close(release)
	if err := <-resendA; err != nil {
		t.Fatalf("resend A = %v", err)
	}
	if err := <-resendB; !errors.Is(err, ErrNoPending) {
		t.Fatalf("resend B = %v, want ErrNoPending (second validation)", err)
	}
	if r := recvPrompt(t, ch); r.err != nil || r.code != "123456" {
		t.Fatalf("prompt = %+v", r)
	}
}

// TestBrokerResendSerializesTeardown proves the opMu contract: with a
// resend in flight, Prompt must not return the claimed code until the
// resend closure finishes.
func TestBrokerResendSerializesTeardown(t *testing.T) {
	b := NewBroker(func(bool, uint64) {})
	entered := make(chan struct{})
	release := make(chan struct{})
	resendFn := func(context.Context) error {
		close(entered)
		<-release
		return nil
	}
	ch, cancel := startPrompt(b, resendFn)
	defer cancel()
	gen := waitArmed(t, b)

	resendDone := make(chan error, 1)
	go func() { resendDone <- b.Resend(context.Background(), gen) }()
	<-entered

	if err := b.ClaimWeb("123456", gen); err != nil {
		t.Fatalf("claim during resend = %v", err)
	}
	select {
	case r := <-ch:
		t.Fatalf("prompt returned %q while resend still in flight", r.code)
	case <-time.After(150 * time.Millisecond):
	}
	close(release)
	if err := <-resendDone; err != nil {
		t.Fatalf("resend = %v", err)
	}
	if r := recvPrompt(t, ch); r.err != nil || r.code != "123456" {
		t.Fatalf("prompt = %+v", r)
	}
}

func TestBrokerGenerationRolloverSkipsZero(t *testing.T) {
	h := NewHub(testConfig("client"))
	b := NewBroker(h.SetSMSPending)
	b.mu.Lock()
	b.gen = ^uint64(0) // MaxUint64: next increment wraps to 0, then skips to 1
	b.mu.Unlock()

	ch, cancel := startPrompt(b, nil)
	defer cancel()
	gen := waitArmed(t, b)
	if gen == 0 {
		t.Fatal("generation wrapped to the zero sentinel")
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var m struct {
			SMSPending bool   `json:"sms_pending"`
			SMSGen     uint64 `json:"sms_gen"`
		}
		if err := json.Unmarshal(h.Snapshot(), &m); err == nil && m.SMSPending && m.SMSGen == gen {
			cancel()
			recvPrompt(t, ch)
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("snapshot never carried the broker generation")
}

func TestBrokerResendTypedErrorPassthrough(t *testing.T) {
	b := NewBroker(func(bool, uint64) {})
	apiErr := &sdpc.APIError{Op: "sms", Code: sdpc.CodeSMSStillValid, Message: "still valid"}
	ch, cancel := startPrompt(b, func(context.Context) error { return apiErr })
	defer cancel()
	gen := waitArmed(t, b)
	err := b.Resend(context.Background(), gen)
	var got *sdpc.APIError
	if !errors.As(err, &got) || got.Code != sdpc.CodeSMSStillValid {
		t.Fatalf("typed error lost: %v", err)
	}
	cancel()
	recvPrompt(t, ch)
}
