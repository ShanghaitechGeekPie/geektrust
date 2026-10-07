// Package privatefile protects new secret files; it does not audit user directories.
package privatefile

import (
	"errors"
	"fmt"
	"os"
)

// Check verifies existing file permissions without changing them.
func Check(path string, strict bool) error {
	err := check(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return permissionResult(path, "verify", err, strict)
}

// Protect attempts to restrict a file before its contents are written.
func Protect(path string, strict bool) error {
	err := protect(path)
	if err == nil {
		err = check(path)
	}
	return permissionResult(path, "restrict", err, strict)
}

func permissionResult(path, operation string, err error, strict bool) error {
	if err == nil {
		return nil
	}
	if strict {
		return fmt.Errorf("cannot %s private file permissions for %q: %w", operation, path, err)
	}
	fmt.Fprintf(os.Stderr, "Warning: cannot %s private file permissions for %q: %v; continuing because strict_permissions is disabled.\n", operation, path, err)
	return nil
}
