package storage

import (
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"testing"
)

func TestSecretFileHasProtectedDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if e := WriteAtomic(path, []byte("fixture"), 0600); e != nil {
		t.Fatal(e)
	}
	if b, e := os.ReadFile(path); e != nil || string(b) != "fixture" {
		t.Fatal("secret write failed")
	}
	sd, e := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		t.Fatal(e)
	}
	control, _, e := sd.Control()
	if e != nil || control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("secret inherited a parent DACL")
	}
	dacl, _, e := sd.DACL()
	if e != nil || dacl == nil || dacl.AceCount != 2 {
		t.Fatal("expected current-user and LocalSystem access only")
	}
}
