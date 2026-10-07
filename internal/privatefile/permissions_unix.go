//go:build !windows

package privatefile

import (
	"fmt"
	"os"
	"path/filepath"
)

func ResolveExistingPath(path string) (string, error) { return filepath.EvalSymlinks(path) }
func protect(path string) error                       { return os.Chmod(path, 0600) }

func check(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("group or other users have access (mode %04o)", info.Mode().Perm())
	}
	return nil
}
