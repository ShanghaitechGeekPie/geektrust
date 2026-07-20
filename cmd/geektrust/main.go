// geekTrust is a pure-userspace client for the ShanghaiTech aTrust VPN:
// passkey login, TLS tunnel, per-connection auth with userspace TCP, exposed
// as local SOCKS5/HTTP proxies. See docs/PLAN.md and docs/TECHNICAL.md.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"geektrust/internal/config"
	"geektrust/internal/inbound"
	"geektrust/internal/l3"
	"geektrust/internal/resolver"
	"geektrust/internal/session"
	"geektrust/internal/tunnel"
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "config.toml", "path to the TOML config file")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: geektrust [-config config.toml] <command>\n\nCommands:\n  run               ensure a session, then start the SOCKS5/HTTP proxies (default)\n  login             establish a VPN session (passkey; SMS once per new device)\n  dial <host[:port]>  connect through the tunnel (TLS handshake on :443)\n")
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
	case "dial":
		err = cmdDial(ctx, cfg, logger, args)
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

// cmdRun ensures a session, then runs the tunnel-backed SOCKS5/HTTP proxies
// until interrupted.
func cmdRun(ctx context.Context, cfg *config.Config, logger *slog.Logger, args []string) error {
	provider := session.NewProvider(cfg, logger, smsPrompt)
	cred, err := provider.Credential(ctx)
	if err != nil {
		return err
	}
	printSummary(cred)

	// Session liveness: periodic onlineInfo, silent re-login on expiry.
	go provider.CheckLoop(ctx, 5*time.Minute)

	manager := tunnel.NewManager(provider, logger)
	defer manager.Close()
	dialer := &l3.Dialer{Manager: manager, Provider: provider, Logger: logger}
	res := resolver.New(provider, cfg.DNS)

	srv := inbound.New(cfg.Inbound, res, dialer, logger)
	return srv.Run(ctx)
}

func printSummary(cred *session.Credential) {
	fmt.Printf("sid:       %s (redacted)\n", session.ShortSID(cred.SID))
	fmt.Printf("device_id: %s\n", cred.DeviceID)
	fmt.Printf("gateways:  %s\n", strings.Join(cred.Gateways, ", "))
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

// cmdDial connects to a tunnel target and, for port 443, completes a TLS
// handshake — the M3 acceptance check (TCP-over-tunnel to library:443).
func cmdDial(ctx context.Context, cfg *config.Config, logger *slog.Logger, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: geektrust dial <host[:port]>")
	}
	host, portStr, err := net.SplitHostPort(args[0])
	if err != nil {
		host, portStr = args[0], "443"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("invalid port %q", portStr)
	}

	provider := session.NewProvider(cfg, logger, smsPrompt)
	// Resolve exactly like the inbound layer: domain map first, public DNS
	// fallback (via the configured servers).
	res := resolver.New(provider, cfg.DNS)
	ip, _, err := res.Resolve(ctx, host)
	if err != nil {
		return err
	}

	manager := tunnel.NewManager(provider, logger)
	defer manager.Close()
	dialer := &l3.Dialer{Manager: manager, Provider: provider, Logger: logger}

	start := time.Now()
	conn, err := dialer.Dial(ctx, ip, port)
	if err != nil {
		return err
	}
	defer conn.Close()
	fmt.Printf("tunnel TCP connected: %s -> %s (%v)\n", conn.LocalAddr(), conn.RemoteAddr(),
		time.Since(start).Round(time.Millisecond))

	if port == 443 {
		tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: host})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return fmt.Errorf("tls handshake over tunnel: %w", err)
		}
		state := tlsConn.ConnectionState()
		name := "(no certificate)"
		if len(state.PeerCertificates) > 0 {
			name = state.PeerCertificates[0].Subject.String()
		}
		fmt.Printf("tls handshake ok: %s, cipher 0x%04x, subject %s\n",
			tls.VersionName(state.Version), state.CipherSuite, name)
	}
	return nil
}
