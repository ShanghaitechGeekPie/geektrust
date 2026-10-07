package session

import (
	"context"
	"errors"
	"sync"
	"testing"
)

type checkedContext struct {
	context.Context
	checked chan struct{}
	once    sync.Once
}

func (c *checkedContext) Err() error {
	err := c.Context.Err()
	c.once.Do(func() { close(c.checked) })
	return err
}

func TestQueuedAcquisitionCancellationKeepsSession(t *testing.T) {
	for _, forced := range []bool{false, true} {
		t.Run(map[bool]string{false: "credential", true: "forced"}[forced], func(t *testing.T) {
			p := failingProvider(t)
			current := &Credential{SID: "existing"}
			p.mu.Lock()
			p.cur = current
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			checked := &checkedContext{Context: ctx, checked: make(chan struct{})}
			result := make(chan error, 1)
			acquire := p.Credential
			if forced {
				acquire = p.ForceLogin
			}
			go func() { _, err := acquire(checked); result <- err }()
			<-checked.checked
			cancel()
			p.mu.Unlock()
			if err := <-result; !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled queued acquisition = %v", err)
			}
			if p.Current() != current {
				t.Fatal("cancellation while waiting for the lock invalidated the session")
			}
		})
	}
}
