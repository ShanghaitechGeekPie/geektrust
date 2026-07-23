package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"geektrust/internal/config"

	"golang.org/x/text/unicode/norm"
)

const passkeyToolSource = "git+https://github.com/vvbbnn00/shanghaitech-ids-passkey.git"

type initPath struct {
	name string
	path string
}

func validateInitPaths(configPath string, cfg *config.Config) (string, error) {
	paths := []initPath{
		{name: "config", path: configPath},
		{name: "keystore", path: cfg.Keystore},
		{name: "state_file", path: cfg.StateFile},
		{name: "state key", path: cfg.StateFile + ".key"},
	}
	resolved := make([]string, len(paths))
	lexical := make([]string, len(paths))
	infos := make([]os.FileInfo, len(paths))
	for i, item := range paths {
		if item.path == "" {
			return "", fmt.Errorf("%s path is required", item.name)
		}
		if containsParentTraversal(item.path) {
			return "", fmt.Errorf("%s path must not contain '..'", item.name)
		}
		var err error
		lexical[i], err = filepath.Abs(filepath.Clean(item.path))
		if err != nil {
			return "", fmt.Errorf("resolve lexical %s path: %w", item.name, err)
		}
		var infoErr error
		resolved[i], infos[i], infoErr = resolveInitPath(item.path)
		if infoErr != nil {
			return "", fmt.Errorf("resolve %s path: %w", item.name, infoErr)
		}
		if infos[i] != nil && !infos[i].Mode().IsRegular() {
			return "", fmt.Errorf("%s path %s is not a regular file", item.name, item.path)
		}
	}
	for i := range paths {
		for j := i + 1; j < len(paths); j++ {
			overlap := initPathsOverlap(resolved[i], resolved[j])
			if !overlap && infos[i] != nil && infos[j] != nil {
				overlap = os.SameFile(infos[i], infos[j])
			}
			if overlap {
				return "", fmt.Errorf("%s and %s paths must not overlap", paths[i].name, paths[j].name)
			}
		}
	}
	for i, item := range paths {
		if err := validateInitDirectory(item.name, lexical[i]); err != nil {
			return "", err
		}
		if err := validateInitDirectory(item.name, resolved[i]); err != nil {
			return "", err
		}
	}
	return resolved[0], nil
}

func initPathsOverlap(left, right string) bool {
	// NFC + EqualFold is deliberately conservative: generated file paths
	// must also be distinct on case-insensitive APFS, which treats canonically
	// equivalent Unicode filenames as the same entry.
	leftParts := strings.Split(filepath.ToSlash(norm.NFC.String(filepath.Clean(left))), "/")
	rightParts := strings.Split(filepath.ToSlash(norm.NFC.String(filepath.Clean(right))), "/")
	if len(leftParts) > len(rightParts) {
		leftParts, rightParts = rightParts, leftParts
	}
	for i := range leftParts {
		if !strings.EqualFold(leftParts[i], rightParts[i]) {
			return false
		}
	}
	return true
}

func containsParentTraversal(path string) bool {
	for _, component := range strings.Split(filepath.ToSlash(path), "/") {
		if component == ".." {
			return true
		}
	}
	return false
}

func validateInitDirectory(name, path string) error {
	dir := filepath.Dir(path)
	for {
		info, err := os.Stat(dir)
		if err == nil {
			if !info.IsDir() {
				return fmt.Errorf("%s parent %s is not a directory", name, dir)
			}
			// A directory entry can be replaced by anyone who can write its
			// parent. Check every existing ancestor before creating or
			// replacing any config or credential file.
			if info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
				return fmt.Errorf("%s directory ancestor %s is writable by other users", name, dir)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect %s directory: %w", name, err)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
		dir = parent
	}
}

// resolveInitPath resolves symlinks in the longest existing prefix, so paths
// for files that do not exist yet can still be compared safely.
func resolveInitPath(path string) (string, os.FileInfo, error) {
	absolute, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", nil, err
	}
	if info, err := os.Stat(absolute); err == nil {
		resolved, err := filepath.EvalSymlinks(absolute)
		return resolved, info, err
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", nil, err
	}

	current := absolute
	var suffix []string
	for {
		if _, err := os.Stat(current); err == nil {
			resolved, err := filepath.EvalSymlinks(current)
			if err != nil {
				return "", nil, err
			}
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			return filepath.Clean(resolved), nil, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", nil, err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return absolute, nil, nil
		}
		suffix = append(suffix, filepath.Base(current))
		current = parent
	}
}

func bindPasskeyKeystore(ctx context.Context, uvx, destination string) error {
	dir := filepath.Dir(destination)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create keystore directory: %w", err)
	}
	if err := validateInitDirectory("keystore", destination); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".geektrust-keystore-*")
	if err != nil {
		return fmt.Errorf("reserve temporary keystore: %w", err)
	}
	tmpPath := tmp.Name()
	cleaned := false
	defer func() {
		if !cleaned {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("secure temporary keystore: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary keystore: %w", err)
	}

	cmd := exec.CommandContext(ctx, uvx,
		"--from", passkeyToolSource,
		"--with", "selenium",
		"shanghaitech-ids-passkey", "bind", "--keystore", tmpPath,
	)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("bind passkey: %w", err)
	}
	info, err := os.Lstat(tmpPath)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		return fmt.Errorf("passkey binding completed without creating a valid keystore")
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return fmt.Errorf("secure bound keystore: %w", err)
	}
	// Linking within the same directory installs the completed file
	// atomically and refuses to overwrite a path created during binding.
	if err := os.Link(tmpPath, destination); err != nil {
		return fmt.Errorf("install bound keystore: %w", err)
	}
	if err := os.Remove(tmpPath); err != nil {
		_ = os.Remove(destination)
		return fmt.Errorf("remove temporary keystore: %w", err)
	}
	cleaned = true
	return nil
}

func cmdInit(ctx context.Context, configPath string, args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	keystore := fs.String("keystore", "./ids-passkey.keystore", "passkey keystore path")
	deviceID := fs.String("device-id", "", "persistent 32-character uppercase hex device ID (generated when omitted)")
	stateFile := fs.String("state-file", "./state.enc", "encrypted session state path")
	clientType := fs.String("client-type", "client", "login mode: client (recommended) or browser")
	bindPasskey := fs.Bool("bind-passkey", false, "run shanghaitech-ids-passkey bind when the keystore is missing")
	force := fs.Bool("force", false, "replace an existing config file")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}

	initOpts := config.InitOptions{
		Keystore:   *keystore,
		DeviceID:   *deviceID,
		StateFile:  *stateFile,
		ClientType: *clientType,
		Force:      *force,
	}
	prepared, err := config.PrepareInitialConfig(initOpts)
	if err != nil {
		return err
	}
	resolvedConfigPath, err := validateInitPaths(configPath, prepared)
	if err != nil {
		return err
	}

	if !*force {
		if _, err := os.Stat(resolvedConfigPath); err == nil {
			return fmt.Errorf("config %s already exists; use --force to replace it", configPath)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect config path: %w", err)
		}
	}

	keystoreExists := false
	if info, err := os.Stat(prepared.Keystore); err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("keystore %s is not a regular file", prepared.Keystore)
		}
		if err := os.Chmod(prepared.Keystore, 0o600); err != nil {
			return fmt.Errorf("secure existing keystore: %w", err)
		}
		keystoreExists = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect keystore: %w", err)
	}

	if *bindPasskey && !keystoreExists {
		uvx, err := exec.LookPath("uvx")
		if err != nil {
			return fmt.Errorf("uvx is not installed; install uv first or omit --bind-passkey")
		}
		if err := bindPasskeyKeystore(ctx, uvx, prepared.Keystore); err != nil {
			return err
		}
		keystoreExists = true
	}
	// The binder may have created a symlink or hard link. Re-evaluate path
	// identity before writing the config.
	resolvedConfigPath, err = validateInitPaths(configPath, prepared)
	if err != nil {
		return err
	}

	cfg, err := config.Initialize(resolvedConfigPath, config.InitOptions{
		Keystore:   prepared.Keystore,
		DeviceID:   prepared.DeviceID,
		StateFile:  prepared.StateFile,
		ClientType: prepared.ClientType,
		Force:      *force,
	})
	if err != nil {
		return err
	}

	fmt.Printf("created %s with client_type=%s\n", configPath, cfg.ClientType)
	fmt.Printf("device_id: %s (keep this value stable)\n", cfg.DeviceID)
	if keystoreExists {
		fmt.Printf("next: geektrust -config %q login\n", configPath)
	} else {
		fmt.Printf("next: uvx --from %q --with selenium shanghaitech-ids-passkey bind --keystore %q\n", passkeyToolSource, cfg.Keystore)
		fmt.Printf("then: geektrust -config %q login\n", configPath)
	}
	return nil
}
