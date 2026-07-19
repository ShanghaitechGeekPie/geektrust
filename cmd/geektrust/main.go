// geekTrust is a pure-userspace client for the ShanghaiTech aTrust VPN:
// passkey login, TLS tunnel, per-connection auth with userspace TCP, exposed
// as local SOCKS5/HTTP proxies. See docs/PLAN.md and docs/TECHNICAL.md.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"geektrust/internal/config"
	"geektrust/internal/session"
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "config.toml", "path to the TOML config file")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: geektrust [-config config.toml] <command>\n\nCommands:\n  run     ensure a session, then start the SOCKS5/HTTP proxies (default)\n  login   establish a VPN session (passkey; SMS once per new device)\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	cmd := "run"
	args := flag.Args()
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "geektrust:", err)
		os.Exit(1)
	}
	logger := newLogger(cfg.LogLevel)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch cmd {
	case "login":
		err = cmdLogin(ctx, cfg, logger, args)
	case "run":
		err = cmdRun(ctx, cfg, logger, args)
	default:
		flag.Usage()
		os.Exit(2)
	}
	if err != nil {
		logger.Error("command failed", "command", cmd, "err", err)
		os.Exit(1)
	}
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}

// cmdLogin establishes (or reuses) a VPN session and prints its summary.
func cmdLogin(ctx context.Context, cfg *config.Config, logger *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	fresh := fs.Bool("fresh", false, "force a full login even if the persisted session is still online")
	fs.Parse(args)

	provider := session.NewProvider(cfg, logger, smsPrompt)
	var cred *session.Credential
	var err error
	if *fresh {
		cred, err = provider.ForceLogin(ctx)
	} else {
		cred, err = provider.Credential(ctx)
	}
	if err != nil {
		return err
	}
	printSummary(cred)
	return nil
}

// cmdRun ensures a session and starts the proxy listeners.
func cmdRun(ctx context.Context, cfg *config.Config, logger *slog.Logger, args []string) error {
	provider := session.NewProvider(cfg, logger, smsPrompt)
	cred, err := provider.Credential(ctx)
	if err != nil {
		return err
	}
	printSummary(cred)
	// The tunnel + proxy stack is attached here (M2–M4).
	logger.Info("session ready; proxy listeners are wired in milestone M4")
	<-ctx.Done()
	return nil
}

func printSummary(cred *session.Credential) {
	fmt.Printf("sid:       %s (redacted)\n", session.ShortSID(cred.SID))
	fmt.Printf("device_id: %s\n", cred.DeviceID)
	fmt.Printf("gateways:  %s\n", strings.Join(cred.Gateways, ", "))
	if len(cred.DNS) > 0 {
		fmt.Printf("dns:       %s\n", strings.Join(cred.DNS, ", "))
	}
	domains := make([]string, 0, len(cred.DomainMap))
	for d := range cred.DomainMap {
		domains = append(domains, d)
	}
	sort.Strings(domains)
	fmt.Printf("domain map (%d):\n", len(domains))
	for _, d := range domains {
		ep := cred.DomainMap[d]
		fmt.Printf("  %-40s -> %s (app %s)\n", d, ep.IP, ep.AppID)
	}
}

// smsPrompt reads the one-time SMS code from stdin (new device only).
func smsPrompt(ctx context.Context) (string, error) {
	fmt.Fprintln(os.Stderr, "This device_id is not trusted yet; an SMS verification code was sent to your phone.")
	fmt.Fprint(os.Stderr, "Enter the 6-digit code: ")
	type result struct {
		code string
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		if sc.Scan() {
			ch <- result{code: strings.TrimSpace(sc.Text())}
		} else {
			ch <- result{err: errors.New("no verification code provided")}
		}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			return "", r.err
		}
		if r.code == "" {
			return "", errors.New("empty verification code")
		}
		return r.code, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}
