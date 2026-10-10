package storage

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestExclusivePublicationAndCredentialLock(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "identity")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = CreateExclusive(p, []byte("complete identity"), true) }()
	}
	wg.Wait()
	b, e := os.ReadFile(p)
	if e != nil || string(b) != "complete identity" {
		t.Fatal("partially published exclusive file")
	}
	key := CredentialFile{Path: filepath.Join(dir, "credential"), StrictPermissions: true}
	if e = WriteAtomic(key.Path, []byte("fixture"), true); e != nil {
		t.Fatal(e)
	}
	unlock, e := key.Lock(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, e = key.Lock(ctx); e == nil {
		t.Fatal("lock did not honor cancellation")
	}
	unlock()
}
