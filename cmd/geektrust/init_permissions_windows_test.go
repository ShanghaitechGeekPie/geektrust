package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/ShanghaitechGeekPie/geektrust/internal/config"
)

// Only call this on fixtures created by the test, never user directories.
func setTestWindowsACL(t *testing.T, path, extra string) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString(fmt.Sprintf("D:P(A;OICI;FA;;;%s)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)%s", user.User.Sid.String(), extra))
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(pathPtr, windows.WRITE_DAC|windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatalf("open test ACL %s: %v", path, err)
	}
	defer windows.CloseHandle(handle)
	if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatalf("set test ACL %s: %v", path, err)
	}
}

func TestWindowsInitACLIntegration(t *testing.T) {
	t.Logf("process elevated=%v", windows.GetCurrentProcessToken().IsElevated())
	root := t.TempDir()
	t.Logf("test root=%s", root)
	setTestWindowsACL(t, root, "")
	t.Run("normal private directory", func(t *testing.T) {
		path := filepath.Join(root, "normal", "config.toml")
		err := cmdInit(context.Background(), path, []string{"--keystore", filepath.Join(root, "key"), "--state-file", filepath.Join(root, "state")})
		if err != nil {
			t.Fatal(err)
		}
		if err := validateInitFilePermissions("config", path); err != nil {
			t.Fatal(err)
		}
	})
	for _, tt := range []struct{ name, ace string }{
		{"world writable", "(A;;FW;;;WD)"},
		{"delete child", "(A;;0x40;;;WD)"},
		{"inherit only read", "(A;OIIO;FR;;;BU)"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := filepath.Join(root, strings.ReplaceAll(tt.name, " ", "-"))
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			setTestWindowsACL(t, dir, tt.ace)
			path := filepath.Join(dir, "config.toml")
			if err := cmdInit(context.Background(), path, []string{"--keystore", filepath.Join(root, "key"), "--state-file", filepath.Join(root, "state")}); err == nil {
				t.Fatal("unsafe directory accepted")
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("config created before rejecting unsafe ACL: %v", err)
			}
		})
	}
	t.Run("private child under replaceable ancestor", func(t *testing.T) {
		parent := filepath.Join(root, "replaceable")
		child := filepath.Join(parent, "private")
		if err := os.MkdirAll(child, 0700); err != nil {
			t.Fatal(err)
		}
		setTestWindowsACL(t, parent, "(A;;0x40;;;WD)")
		setTestWindowsACL(t, child, "")
		if err := validateInitDirectory("config", filepath.Join(child, "config.toml")); err == nil {
			t.Fatal("replaceable ancestor accepted")
		}
	})
	t.Run("protected child under sibling creation ancestor", func(t *testing.T) {
		parent := filepath.Join(root, "siblings")
		child := filepath.Join(parent, "private")
		if err := os.MkdirAll(child, 0700); err != nil {
			t.Fatal(err)
		}
		setTestWindowsACL(t, parent, "(A;;0x4;;;AU)(A;OICIIO;FR;;;BU)")
		setTestWindowsACL(t, child, "")
		if err := validateInitDirectory("config", filepath.Join(child, "config.toml")); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("existing readable credential", func(t *testing.T) {
		key := filepath.Join(root, "readable.key")
		if err := os.WriteFile(key, []byte("synthetic"), 0600); err != nil {
			t.Fatal(err)
		}
		setTestWindowsACL(t, key, "(A;;FR;;;BU)")
		_, err := validateInitPaths(filepath.Join(root, "existing.toml"), &config.Config{Keystore: key, StateFile: filepath.Join(root, "existing.state")})
		if err == nil || !strings.Contains(err.Error(), "keystore file") {
			t.Fatalf("unsafe existing credential was not rejected: %v", err)
		}
	})
	t.Run("junction to readable credential", func(t *testing.T) {
		target := filepath.Join(root, "junction-target")
		link := filepath.Join(root, "junction-link")
		if err := os.Mkdir(target, 0700); err != nil {
			t.Fatal(err)
		}
		output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", link, target).CombinedOutput()
		if err != nil {
			t.Fatalf("create test junction: %v: %s", err, output)
		}
		t.Logf("mklink: %s", output)
		linkTarget, linkErr := os.Readlink(link)
		t.Logf("junction target=%q error=%v", linkTarget, linkErr)
		defer os.Remove(link)
		key := filepath.Join(target, "key")
		if err := os.WriteFile(key, []byte("synthetic"), 0600); err != nil {
			t.Fatal(err)
		}
		cfg := &config.Config{Keystore: filepath.Join(link, "key"), StateFile: filepath.Join(root, "junction.state")}
		if _, err := validateInitPaths(filepath.Join(root, "junction.toml"), cfg); err != nil {
			t.Fatalf("private junction target was rejected: %v", err)
		}
		setTestWindowsACL(t, key, "(A;;FR;;;BU)")
		_, err = validateInitPaths(filepath.Join(root, "junction.toml"), cfg)
		if err == nil || !strings.Contains(err.Error(), "keystore file") {
			t.Fatalf("readable junction target was not rejected: %v", err)
		}
		setTestWindowsACL(t, key, "")
		setTestWindowsACL(t, link, "(A;;SD;;;WD)")
		if _, err := validateInitPaths(filepath.Join(root, "junction.toml"), cfg); err == nil {
			t.Fatal("junction with unsafe DELETE access was accepted")
		}
		outer := filepath.Join(root, "outer-junction")
		if output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", outer, link).CombinedOutput(); err != nil {
			t.Fatalf("create outer junction: %v: %s", err, output)
		}
		defer os.Remove(outer)
		cfg.Keystore = filepath.Join(outer, "key")
		if _, err := validateInitPaths(filepath.Join(root, "junction.toml"), cfg); err == nil {
			t.Fatal("unsafe intermediate junction was accepted")
		}
		setTestWindowsACL(t, link, "")
		if _, err := validateInitPaths(filepath.Join(root, "junction.toml"), cfg); err != nil {
			t.Fatalf("safe multi-hop junction rejected: %v", err)
		}
	})
}
