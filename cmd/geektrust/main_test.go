package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"geektrust/internal/config"
)

func TestBuildVersion(t *testing.T) {
	original := version
	t.Cleanup(func() { version = original })

	version = "v1.2.3-rc.1"
	if got := buildVersion(); got != "v1.2.3-rc.1" {
		t.Fatalf("buildVersion() = %q, want v1.2.3-rc.1", got)
	}

	version = ""
	if got := buildVersion(); got != "dev" {
		t.Fatalf("empty buildVersion() = %q, want dev", got)
	}
}

func TestValidateTrustDeviceArgs(t *testing.T) {
	clientCfg := &config.Config{ClientType: "client"}
	browserCfg := &config.Config{ClientType: "browser"}

	tests := []struct {
		name    string
		cfg     *config.Config
		args    []string
		wantSub string
		wantErr bool
	}{
		{name: "missing subcommand", cfg: clientCfg, wantErr: true},
		{name: "unknown subcommand", cfg: clientCfg, args: []string{"typo"}, wantErr: true},
		{name: "list", cfg: browserCfg, args: []string{"list"}, wantSub: "list"},
		{name: "list extra argument", cfg: browserCfg, args: []string{"list", "extra"}, wantErr: true},
		{name: "bind client", cfg: clientCfg, args: []string{"bind"}, wantSub: "bind"},
		{name: "bind browser", cfg: browserCfg, args: []string{"bind"}, wantErr: true},
		{name: "bind extra argument", cfg: clientCfg, args: []string{"bind", "extra"}, wantErr: true},
		{name: "unbind one", cfg: clientCfg, args: []string{"unbind", "device-1"}, wantSub: "unbind"},
		{name: "unbind many", cfg: clientCfg, args: []string{"unbind", "device-1", "device-2"}, wantSub: "unbind"},
		{name: "unbind missing", cfg: clientCfg, args: []string{"unbind"}, wantErr: true},
		{name: "unbind empty", cfg: clientCfg, args: []string{"unbind", " "}, wantErr: true},
		{name: "logout", cfg: clientCfg, args: []string{"logout", "device-1"}, wantSub: "logout"},
		{name: "logout missing", cfg: clientCfg, args: []string{"logout"}, wantErr: true},
		{name: "logout extra", cfg: clientCfg, args: []string{"logout", "device-1", "device-2"}, wantErr: true},
		{name: "logout empty", cfg: clientCfg, args: []string{"logout", ""}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sub, err := validateTrustDeviceArgs(tt.cfg, tt.args)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if sub != tt.wantSub {
				t.Errorf("subcommand = %q, want %q", sub, tt.wantSub)
			}
		})
	}
}

func TestCmdInitDefaultsAndFlags(t *testing.T) {
	t.Run("client defaults", func(t *testing.T) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "config.toml")
		keystore := filepath.Join(dir, "synthetic.keystore")
		stateFile := filepath.Join(dir, "synthetic-state.enc")
		if err := cmdInit(context.Background(), configPath, []string{
			"--keystore", keystore,
			"--state-file", stateFile,
		}); err != nil {
			t.Fatal(err)
		}
		cfg, err := config.Load(configPath)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.ClientType != "client" {
			t.Errorf("client_type = %q, want client", cfg.ClientType)
		}
		if cfg.DeviceID == "" || cfg.DeviceID == config.DefaultDeviceID {
			t.Errorf("generated device_id = %q", cfg.DeviceID)
		}
		if cfg.Keystore != keystore || cfg.StateFile != stateFile {
			t.Errorf("paths = %q, %q", cfg.Keystore, cfg.StateFile)
		}
	})

	t.Run("explicit options", func(t *testing.T) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "config.toml")
		keystore := filepath.Join(dir, "synthetic.keystore")
		if err := os.WriteFile(keystore, []byte("synthetic"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(keystore, 0o644); err != nil {
			t.Fatal(err)
		}
		const deviceID = "0123456789ABCDEF0123456789ABCDEF"
		if err := cmdInit(context.Background(), configPath, []string{
			"--keystore", keystore,
			"--device-id", deviceID,
			"--client-type", "browser",
		}); err != nil {
			t.Fatal(err)
		}
		cfg, err := config.Load(configPath)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.DeviceID != deviceID || cfg.ClientType != "browser" {
			t.Errorf("initialized config = %+v", cfg)
		}
		info, err := os.Stat(keystore)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("existing keystore mode = %04o, want 0600", info.Mode().Perm())
		}
	})

	t.Run("invalid options before binder lookup", func(t *testing.T) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "config.toml")
		err := cmdInit(context.Background(), configPath, []string{
			"--keystore", filepath.Join(dir, "missing.keystore"),
			"--client-type", "invalid",
			"--bind-passkey",
		})
		if err == nil {
			t.Fatal("expected invalid client_type error")
		}
		if !strings.Contains(err.Error(), "client_type") {
			t.Fatalf("error = %v, want client_type validation", err)
		}
		if _, statErr := os.Stat(configPath); !os.IsNotExist(statErr) {
			t.Fatalf("invalid init created config: %v", statErr)
		}
	})
}

func TestValidateInitPaths(t *testing.T) {
	dir := t.TempDir()
	safe := &config.Config{
		Keystore:  filepath.Join(dir, "synthetic.keystore"),
		StateFile: filepath.Join(dir, "synthetic-state.enc"),
	}
	if _, err := validateInitPaths(filepath.Join(dir, "config.toml"), safe); err != nil {
		t.Fatalf("safe paths rejected: %v", err)
	}

	tests := []struct {
		name       string
		configPath string
		keystore   string
		stateFile  string
	}{
		{
			name:       "empty config",
			configPath: "",
			keystore:   filepath.Join(dir, "key-1"),
			stateFile:  filepath.Join(dir, "state-1"),
		},
		{
			name:       "config equals keystore",
			configPath: filepath.Join(dir, "same-1"),
			keystore:   filepath.Join(dir, "same-1"),
			stateFile:  filepath.Join(dir, "state-2"),
		},
		{
			name:       "keystore equals state",
			configPath: filepath.Join(dir, "config-2"),
			keystore:   filepath.Join(dir, "same-2"),
			stateFile:  filepath.Join(dir, "same-2"),
		},
		{
			name:       "config equals state key",
			configPath: filepath.Join(dir, "state-3.key"),
			keystore:   filepath.Join(dir, "key-3"),
			stateFile:  filepath.Join(dir, "state-3"),
		},
		{
			name:       "parent traversal",
			configPath: dir + string(os.PathSeparator) + "nested" + string(os.PathSeparator) + ".." + string(os.PathSeparator) + "config-4",
			keystore:   filepath.Join(dir, "key-4"),
			stateFile:  filepath.Join(dir, "state-4"),
		},
		{
			name:       "config is keystore ancestor",
			configPath: filepath.Join(dir, "config-parent"),
			keystore:   filepath.Join(dir, "config-parent", "keystore"),
			stateFile:  filepath.Join(dir, "state-parent"),
		},
		{
			name:       "case-only collision",
			configPath: filepath.Join(dir, "Config-5"),
			keystore:   filepath.Join(dir, "config-5"),
			stateFile:  filepath.Join(dir, "state-5"),
		},
		{
			name:       "Unicode normalization collision",
			configPath: filepath.Join(dir, "caf\u00e9-6"),
			keystore:   filepath.Join(dir, "cafe\u0301-6"),
			stateFile:  filepath.Join(dir, "state-6"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validateInitPaths(tt.configPath, &config.Config{
				Keystore:  tt.keystore,
				StateFile: tt.stateFile,
			})
			if err == nil {
				t.Fatal("expected path collision error")
			}
		})
	}

	t.Run("existing hard links", func(t *testing.T) {
		first := filepath.Join(dir, "hardlink-source")
		second := filepath.Join(dir, "hardlink-alias")
		if err := os.WriteFile(first, []byte("synthetic"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(first, second); err != nil {
			t.Fatal(err)
		}
		_, err := validateInitPaths(first, &config.Config{
			Keystore:  second,
			StateFile: filepath.Join(dir, "hardlink-state"),
		})
		if err == nil {
			t.Fatal("hard-linked paths were accepted")
		}
	})

	t.Run("symlinked parent", func(t *testing.T) {
		realDir := filepath.Join(dir, "real")
		linkDir := filepath.Join(dir, "link")
		if err := os.Mkdir(realDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(realDir, linkDir); err != nil {
			t.Fatal(err)
		}
		_, err := validateInitPaths(
			filepath.Join(linkDir, "future"),
			&config.Config{
				Keystore:  filepath.Join(realDir, "future"),
				StateFile: filepath.Join(dir, "symlink-state"),
			},
		)
		if err == nil {
			t.Fatal("paths through a symlinked parent were accepted")
		}
	})

	t.Run("symlink through other-writable parent", func(t *testing.T) {
		targetDir := filepath.Join(dir, "safe-symlink-target")
		unsafeDir := filepath.Join(dir, "unsafe-symlink-parent")
		if err := os.Mkdir(targetDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(unsafeDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(unsafeDir, 0o777); err != nil {
			t.Fatal(err)
		}
		linkDir := filepath.Join(unsafeDir, "link")
		if err := os.Symlink(targetDir, linkDir); err != nil {
			t.Fatal(err)
		}
		_, err := validateInitPaths(
			filepath.Join(dir, "safe-symlink-config"),
			&config.Config{
				Keystore:  filepath.Join(dir, "safe-symlink-key"),
				StateFile: filepath.Join(linkDir, "state"),
			},
		)
		if err == nil {
			t.Fatal("symlink through other-writable parent was accepted")
		}
	})

	t.Run("other-writable config directory", func(t *testing.T) {
		shared := filepath.Join(dir, "shared")
		if err := os.Mkdir(shared, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(shared, 0o777); err != nil {
			t.Fatal(err)
		}
		_, err := validateInitPaths(
			filepath.Join(shared, "config.toml"),
			&config.Config{
				Keystore:  filepath.Join(dir, "shared-key"),
				StateFile: filepath.Join(dir, "shared-state"),
			},
		)
		if err == nil {
			t.Fatal("other-writable config directory was accepted")
		}
	})

	t.Run("other-writable keystore directory", func(t *testing.T) {
		shared := filepath.Join(dir, "shared-keystore")
		if err := os.Mkdir(shared, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(shared, 0o777); err != nil {
			t.Fatal(err)
		}
		_, err := validateInitPaths(
			filepath.Join(dir, "shared-keystore-config"),
			&config.Config{
				Keystore:  filepath.Join(shared, "keystore"),
				StateFile: filepath.Join(dir, "shared-keystore-state"),
			},
		)
		if err == nil {
			t.Fatal("other-writable keystore directory was accepted")
		}
	})

	t.Run("private child under other-writable ancestor", func(t *testing.T) {
		shared := filepath.Join(dir, "shared-ancestor")
		privateChild := filepath.Join(shared, "private-child")
		if err := os.Mkdir(shared, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(shared, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(privateChild, 0o700); err != nil {
			t.Fatal(err)
		}
		_, err := validateInitPaths(
			filepath.Join(privateChild, "config.toml"),
			&config.Config{
				Keystore:  filepath.Join(dir, "ancestor-key"),
				StateFile: filepath.Join(dir, "ancestor-state"),
			},
		)
		if err == nil {
			t.Fatal("other-writable ancestor was accepted")
		}
	})

	t.Run("sticky writable ancestor", func(t *testing.T) {
		sticky := filepath.Join(dir, "sticky-ancestor")
		privateChild := filepath.Join(sticky, "private-child")
		if err := os.Mkdir(sticky, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(sticky, 0o777|os.ModeSticky); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(privateChild, 0o700); err != nil {
			t.Fatal(err)
		}
		_, err := validateInitPaths(
			filepath.Join(privateChild, "config.toml"),
			&config.Config{
				Keystore:  filepath.Join(dir, "sticky-key"),
				StateFile: filepath.Join(dir, "sticky-state"),
			},
		)
		if err != nil {
			t.Fatalf("sticky ancestor rejected: %v", err)
		}
	})

	t.Run("state path is a directory", func(t *testing.T) {
		stateDir := filepath.Join(dir, "state-directory")
		if err := os.Mkdir(stateDir, 0o700); err != nil {
			t.Fatal(err)
		}
		_, err := validateInitPaths(
			filepath.Join(dir, "state-directory-config"),
			&config.Config{
				Keystore:  filepath.Join(dir, "state-directory-key"),
				StateFile: stateDir,
			},
		)
		if err == nil {
			t.Fatal("directory state_file was accepted")
		}
	})
}

func TestCmdInitRejectsCredentialPathCollisions(t *testing.T) {
	dir := t.TempDir()
	keystore := filepath.Join(dir, "synthetic.keystore")
	original := []byte("synthetic-private-key")
	if err := os.WriteFile(keystore, original, 0o600); err != nil {
		t.Fatal(err)
	}
	err := cmdInit(context.Background(), keystore, []string{
		"--keystore", keystore,
		"--state-file", filepath.Join(dir, "state.enc"),
		"--force",
	})
	if err == nil {
		t.Fatal("config/keystore collision was accepted")
	}
	after, readErr := os.ReadFile(keystore)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(after) != string(original) {
		t.Fatal("keystore changed after rejected initialization")
	}
}

func TestCmdInitBindPasskey(t *testing.T) {
	t.Run("missing uvx", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("PATH", dir)
		err := cmdInit(context.Background(), filepath.Join(dir, "config.toml"), []string{
			"--keystore", filepath.Join(dir, "missing.keystore"),
			"--state-file", filepath.Join(dir, "state.enc"),
			"--bind-passkey",
		})
		if err == nil || !strings.Contains(err.Error(), "uvx is not installed") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("successful synthetic binder", func(t *testing.T) {
		dir := t.TempDir()
		logPath := filepath.Join(dir, "binder.log")
		installSyntheticUVX(t, dir, `#!/bin/sh
printf '%s\n' "$@" > "$BINDER_LOG"
for keystore do :; done
printf 'synthetic-keystore' > "$keystore"
`)
		t.Setenv("PATH", dir)
		t.Setenv("BINDER_LOG", logPath)

		configPath := filepath.Join(dir, "config.toml")
		keystore := filepath.Join(dir, "synthetic.keystore")
		if err := cmdInit(context.Background(), configPath, []string{
			"--keystore", keystore,
			"--state-file", filepath.Join(dir, "state.enc"),
			"--bind-passkey",
		}); err != nil {
			t.Fatal(err)
		}
		args, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatal(err)
		}
		wantPrefix := "--from\n" + passkeyToolSource + "\n--with\nselenium\nshanghaitech-ids-passkey\nbind\n--keystore\n"
		if !strings.HasPrefix(string(args), wantPrefix) {
			t.Fatalf("uvx arguments = %q", args)
		}
		tmpKeystore := strings.TrimSuffix(strings.TrimPrefix(string(args), wantPrefix), "\n")
		if tmpKeystore == keystore || filepath.Dir(tmpKeystore) != dir ||
			!strings.HasPrefix(filepath.Base(tmpKeystore), ".geektrust-keystore-") {
			t.Errorf("binder keystore path = %q", tmpKeystore)
		}
		info, err := os.Stat(keystore)
		if err != nil {
			t.Fatalf("binder did not create keystore: %v", err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("keystore mode = %04o, want 0600", info.Mode().Perm())
		}
		if leftovers, err := filepath.Glob(filepath.Join(dir, ".geektrust-keystore-*")); err != nil || len(leftovers) != 0 {
			t.Errorf("temporary keystores = %v, err = %v", leftovers, err)
		}
	})

	t.Run("existing config prevents binder", func(t *testing.T) {
		dir := t.TempDir()
		logPath := filepath.Join(dir, "binder.log")
		installSyntheticUVX(t, dir, `#!/bin/sh
printf 'called' > "$BINDER_LOG"
for keystore do :; done
printf 'synthetic-keystore' > "$keystore"
`)
		t.Setenv("PATH", dir)
		t.Setenv("BINDER_LOG", logPath)
		configPath := filepath.Join(dir, "config.toml")
		if err := os.WriteFile(configPath, []byte("existing"), 0o600); err != nil {
			t.Fatal(err)
		}
		err := cmdInit(context.Background(), configPath, []string{
			"--keystore", filepath.Join(dir, "synthetic.keystore"),
			"--state-file", filepath.Join(dir, "state.enc"),
			"--bind-passkey",
		})
		if err == nil {
			t.Fatal("expected existing config error")
		}
		if _, err := os.Stat(logPath); !os.IsNotExist(err) {
			t.Fatalf("binder ran before existing config rejection: %v", err)
		}
	})

	t.Run("failed binder removes partial keystore", func(t *testing.T) {
		dir := t.TempDir()
		installSyntheticUVX(t, dir, `#!/bin/sh
for keystore do :; done
printf 'partial' > "$keystore"
exit 1
`)
		t.Setenv("PATH", dir)
		configPath := filepath.Join(dir, "config.toml")
		keystore := filepath.Join(dir, "missing.keystore")
		err := cmdInit(context.Background(), configPath, []string{
			"--keystore", keystore,
			"--state-file", filepath.Join(dir, "state.enc"),
			"--bind-passkey",
		})
		if err == nil {
			t.Fatal("expected binder failure")
		}
		if _, err := os.Stat(keystore); !os.IsNotExist(err) {
			t.Fatalf("failed binder left destination keystore: %v", err)
		}
		if leftovers, err := filepath.Glob(filepath.Join(dir, ".geektrust-keystore-*")); err != nil || len(leftovers) != 0 {
			t.Errorf("temporary keystores = %v, err = %v", leftovers, err)
		}
	})

	t.Run("binder must create keystore", func(t *testing.T) {
		dir := t.TempDir()
		installSyntheticUVX(t, dir, "#!/bin/sh\nexit 0\n")
		t.Setenv("PATH", dir)
		configPath := filepath.Join(dir, "config.toml")
		err := cmdInit(context.Background(), configPath, []string{
			"--keystore", filepath.Join(dir, "missing.keystore"),
			"--state-file", filepath.Join(dir, "state.enc"),
			"--bind-passkey",
		})
		if err == nil || !strings.Contains(err.Error(), "without creating a valid keystore") {
			t.Fatalf("error = %v", err)
		}
		if _, err := os.Stat(configPath); !os.IsNotExist(err) {
			t.Fatalf("failed binder created config: %v", err)
		}
	})
}

func TestWebListenConflict(t *testing.T) {
	cfg := &config.Config{
		Inbound: config.Inbound{
			SOCKS5: config.Listener{Enabled: true, Listen: "127.0.0.1:1080"},
			HTTP:   config.Listener{Enabled: true, Listen: "127.0.0.1:8081"},
		},
	}
	cfg.Web.Listen = "127.0.0.1:8081"
	if !webListenConflict(cfg) {
		t.Error("enabled inbound HTTP on the panel address must conflict")
	}
	cfg.Web.Listen = "127.0.0.1:8080"
	if webListenConflict(cfg) {
		t.Error("distinct panel address reported as conflict")
	}
	cfg.Inbound.HTTP.Enabled = false
	cfg.Web.Listen = "127.0.0.1:8081"
	if webListenConflict(cfg) {
		t.Error("disabled inbound listener reported as conflict")
	}

	// Equivalent spellings of the same loopback endpoint must conflict even
	// though only Web.Listen is canonicalized by config validation.
	cfg.Inbound.HTTP.Enabled = true
	cfg.Inbound.HTTP.Listen = "[0:0:0:0:0:0:0:1]:8081"
	cfg.Web.Listen = "[::1]:8081"
	if !webListenConflict(cfg) {
		t.Error("IPv6-equivalent inbound/panel addresses not detected")
	}
	cfg.Inbound.HTTP.Listen = "127.0.0.1:8081"
	cfg.Web.Listen = "localhost:8081"
	if !webListenConflict(cfg) {
		t.Error("localhost/127.0.0.1 equivalence not detected")
	}
	cfg.Inbound.HTTP.Listen = "0.0.0.0:8081"
	cfg.Web.Listen = "127.0.0.1:8081"
	if !webListenConflict(cfg) {
		t.Error("wildcard inbound on the panel port not detected")
	}
	cfg.Inbound.HTTP.Listen = "127.0.0.1:08081"
	if !webListenConflict(cfg) {
		t.Error("leading-zero port equivalent not detected")
	}
	// Service names resolve via the system database exactly as net.Listen
	// resolves them; "http" is universally 80 (http-alt is 591 here, 8080
	// on Linux, so it is not a stable fixture).
	if !listenOverlap("127.0.0.1:http", "127.0.0.1:80") {
		t.Error("service-name port (http=80) not detected")
	}
}

func TestCmdInitHelp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := cmdInit(context.Background(), path, []string{"--help"}); err != nil {
		t.Fatalf("help returned error: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("help created config: %v", err)
	}
}

func installSyntheticUVX(t *testing.T, dir, content string) {
	t.Helper()
	path := filepath.Join(dir, "uvx")
	if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
		t.Fatal(err)
	}
}
