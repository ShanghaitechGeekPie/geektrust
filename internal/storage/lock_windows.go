package storage

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"time"
)

func (p CredentialFile) Lock(ctx context.Context) (func(), error) {
	canonical, e := filepath.EvalSymlinks(p.Path)
	if e != nil {
		return nil, e
	}
	f, e := os.OpenFile(canonical+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	ov := &windows.Overlapped{}
	for {
		e = windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ov)
		if e == nil {
			return func() { windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, ov); f.Close() }, nil
		}
		if !errors.Is(e, windows.ERROR_LOCK_VIOLATION) {
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
