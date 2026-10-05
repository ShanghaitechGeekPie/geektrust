//go:build !windows

package storage

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"time"
)

func (p CredentialFile) Lock(ctx context.Context) (func(), error) {
	canonical, e := filepath.EvalSymlinks(string(p))
	if e != nil {
		return nil, e
	}
	f, e := os.OpenFile(canonical+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	for {
		e = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if e == nil {
			return func() { unix.Flock(int(f.Fd()), unix.LOCK_UN); f.Close() }, nil
		}
		if !errors.Is(e, unix.EWOULDBLOCK) {
			f.Close()
			return nil, e
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}
