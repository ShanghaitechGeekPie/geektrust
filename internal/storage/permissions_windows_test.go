package storage

import (
	"context"
	"github.com/ShanghaitechGeekPie/geektrust/internal/privatefile"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"testing"
)

func TestSecretFileHasProtectedDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if e := WriteAtomic(path, []byte("fixture"), true); e != nil {
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

func TestCredentialPermissionsWarnByDefaultAndFailWhenStrict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential")
	if err := WriteAtomic(path, []byte("fixture"), true); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;" + user.User.Sid.String() + ")(A;;FR;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	soft := CredentialFile{Path: path}
	if data, err := soft.Load(context.Background()); err != nil || string(data) != "fixture" {
		t.Fatalf("default read blocked: %v", err)
	}
	strict := CredentialFile{Path: path, StrictPermissions: true}
	if _, err := strict.Load(context.Background()); err == nil {
		t.Fatal("strict read accepted Everyone access")
	}
	if err := privatefile.Protect(path, true); err != nil {
		t.Fatal(err)
	}
	if _, err := strict.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
}
