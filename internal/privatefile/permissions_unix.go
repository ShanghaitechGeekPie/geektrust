//go:build !windows

package privatefile

import (
	"os"
	"path/filepath"
)

func ResolveExistingPath(path string) (string, error) { return filepath.EvalSymlinks(path) }
func Protect(path string) error                       { return os.Chmod(path, 0600) }
