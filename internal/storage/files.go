// Package storage provides the CLI's small, durable private-file boundary.
package storage

import (
	"context"
	"github.com/ShanghaitechGeekPie/geektrust/internal/privatefile"
	"os"
	"path/filepath"
)

func WriteAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(dir, ".geektrust-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = privatefile.Protect(name); e != nil {
		f.Close()
		return e
	}
	if _, e = f.Write(data); e != nil {
		f.Close()
		return e
	}
	if e = f.Chmod(mode); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Rename(name, path); e != nil {
		return e
	}
	return syncDirectory(dir)
}
func CreateExclusive(path string, data []byte) error {
	dir := filepath.Dir(path)
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(dir, ".geektrust-new-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = privatefile.Protect(name); e != nil {
		f.Close()
		return e
	}
	if _, e = f.Write(data); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Link(name, path); e != nil {
		return e
	}
	return syncDirectory(dir)
}

type CredentialFile string

func (p CredentialFile) Load(ctx context.Context) ([]byte, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	return os.ReadFile(string(p))
}
func (p CredentialFile) Save(ctx context.Context, b []byte) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	target, e := filepath.EvalSymlinks(string(p))
	if e != nil {
		return e
	}
	return WriteAtomic(target, b, 0600)
}
