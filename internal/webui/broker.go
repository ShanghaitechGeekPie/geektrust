package webui

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

// ErrNoPending is returned by claims and resends when no SMS verification is
// pending (or the generation does not match). HTTP maps it to 409.
var ErrNoPending = errors.New("no SMS verification pending")

// smsPending is one armed prompt generation. opMu serializes resend network
// I/O against Prompt teardown only; claims never touch it.
type smsPending struct {
	gen      uint64
	result   chan string // cap 1; written once by the winning claim
	resolved bool        // Broker.mu: a claim won
	done     bool        // Broker.mu: Prompt retired this generation
	resend   func(context.Context) error
	opMu     sync.Mutex
	// opWaiters counts resends between the first validation and the opMu
	// acquisition (observability for tests; guarded by Broker.mu).
	opWaiters int
}

// Broker implements session.SMSHandler with two equivalent channels: the
// web API and one shared process-wide stdin reader (first wins). Unlike the
// old per-prompt smsPrompt, the single reader can never leave an orphaned
// scanner behind that swallows the next code.
type Broker struct {
	mu      sync.Mutex
	gen     uint64
	pending *smsPending // non-nil only while Prompt is armed

	stdin     io.Reader // os.Stdin in production; injectable for tests
	stdinOnce sync.Once

	onPendingChange func(pending bool, gen uint64)
}

// NewBroker requires the Hub's pending callback; a nil callback is a wiring
// error, so fail fast instead of panicking later inside Prompt.
func NewBroker(onPendingChange func(pending bool, gen uint64)) *Broker {
	if onPendingChange == nil {
		panic("webui: NewBroker requires a pending-change callback")
	}
	return &Broker{onPendingChange: onPendingChange, stdin: os.Stdin}
}

// Prompt arms a new generation, then waits for the web or terminal channel
// (or cancellation). The session provider's single-flight guarantee means
// at most one Prompt is active at a time.
func (b *Broker) Prompt(ctx context.Context, resend func(context.Context) error) (string, error) {
	b.mu.Lock()
	b.gen++
	if b.gen == 0 { // rollover: 0 is the "no pending" sentinel
		b.gen++
	}
	result := make(chan string, 1)
	p := &smsPending{gen: b.gen, result: result, resend: resend}
	b.pending = p
	b.mu.Unlock()

	b.startStdin()
	fmt.Fprintln(os.Stderr, "The controller requires SMS verification; a code was sent to your phone.")
	fmt.Fprint(os.Stderr, "Enter the 6-digit code: ")
	// Arm first, then publish: the snapshot can never show a pending prompt
	// that has no delivery target.
	b.onPendingChange(true, p.gen)

	var code string
	gotCode := false
	select {
	case code = <-result:
		gotCode = true
	case <-ctx.Done():
	}

	// Unified exit arbitration: one critical section decides between a claim
	// that already won and a genuine cancellation.
	b.mu.Lock()
	cur := b.pending // only this Prompt can clear it, so it is never nil here
	if cur.resolved {
		if !gotCode {
			// The claim marked resolved before its (lock-free) channel
			// write; that write is the only one, so this receive succeeds.
			code = <-result
		}
		cur.done = true
		b.pending = nil
		b.mu.Unlock()
		b.onPendingChange(false, 0)
		// Wait for an in-flight resend so CheckSMSCode never overlaps it.
		cur.opMu.Lock()
		cur.opMu.Unlock()
		return code, nil
	}
	cur.done = true
	b.pending = nil
	b.mu.Unlock()
	b.onPendingChange(false, 0)
	cur.opMu.Lock()
	cur.opMu.Unlock()
	return "", ctx.Err()
}

// ClaimWeb delivers a code submitted through the API; the generation must
// match the armed one.
func (b *Broker) ClaimWeb(code string, gen uint64) error {
	return b.claim(code, gen, true)
}

// claimTerminal delivers a line from the shared stdin reader. Terminal
// users see the current prompt, so no generation check applies.
func (b *Broker) claimTerminal(code string) {
	_ = b.claim(code, 0, false)
}

func (b *Broker) claim(code string, gen uint64, web bool) error {
	b.mu.Lock()
	p := b.pending
	if p == nil || p.done || p.resolved || (web && gen != p.gen) {
		b.mu.Unlock()
		return ErrNoPending
	}
	p.resolved = true
	b.mu.Unlock()
	// Send on the generation channel bound under the lock; cap 1 and the
	// only writer, so this never blocks even after Prompt cleared pending.
	p.result <- code
	return nil
}

// Resend re-triggers the SMS for the armed generation. Two validations
// (before and after acquiring the generation's opMu) keep it from running
// after a claim or teardown; the network call holds opMu, not Broker.mu.
func (b *Broker) Resend(ctx context.Context, gen uint64) error {
	b.mu.Lock()
	p := b.pending
	if p == nil || p.done || p.resolved || gen != p.gen {
		b.mu.Unlock()
		return ErrNoPending
	}
	b.mu.Unlock()

	// Between the two validations the resend queues on the generation's opMu.
	b.mu.Lock()
	p.opWaiters++
	b.mu.Unlock()
	p.opMu.Lock()
	b.mu.Lock()
	p.opWaiters--
	b.mu.Unlock()
	defer p.opMu.Unlock()
	b.mu.Lock()
	valid := b.pending == p && !p.done && !p.resolved && gen == p.gen
	resendFn := p.resend
	b.mu.Unlock()
	if !valid {
		return ErrNoPending
	}
	return resendFn(ctx)
}

// startStdin lazily starts the single process-wide stdin reader.
func (b *Broker) startStdin() {
	b.stdinOnce.Do(func() {
		go func() {
			sc := bufio.NewScanner(b.stdin)
			for sc.Scan() {
				code := strings.TrimSpace(sc.Text())
				if isSixDigits(code) {
					b.claimTerminal(code)
				}
				// Non-digit lines are ignored; the user simply retypes.
			}
		}()
	})
}

// isSixDigits validates the controller's 6-digit SMS code format.
func isSixDigits(s string) bool {
	if len(s) != 6 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
