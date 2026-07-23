// geekTrust is a pure-userspace client for the ShanghaiTech aTrust VPN:
// passkey login, TLS tunnel, per-connection auth with userspace TCP,
// exposed as local SOCKS5/HTTP proxies.
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
		fmt.Fprintf(os.Stderr, "Usage: geektrust [-config config.toml] <command>\n\nCommands:\n  init              generate a client-mode config and unique device ID\n  run               ensure a session, then start the SOCKS5/HTTP proxies (default)\n  login             establish a VPN session (passkey; SMS when required)\n  dial <host[:port]>  connect through the tunnel (TLS handshake on :443)\n  trust-device <sub>  manage trusted terminals (list | bind | unbind <id> | logout <id>)\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	cmd := "run"
	args := flag.Args()
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cmd == "init" {
		if err := cmdInit(ctx, configPath, args); err != nil {
			fmt.Fprintln(os.Stderr, "geektrust init:", err)
			os.Exit(1)
		}
		return
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "geektrust:", err)
		os.Exit(1)
	}
	logger := newLogger(cfg.LogLevel)

	switch cmd {
	case "login":
		err = cmdLogin(ctx, cfg, logger, args)
	case "run":
		err = cmdRun(ctx, cfg, logger, args)
	case "dial":
		err = cmdDial(ctx, cfg, logger, args)
	case "trust-device":
		err = cmdTrustDevice(ctx, cfg, logger, args)
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
	res := resolver.New(provider, dialer)

	srv := inbound.New(cfg.Inbound, res, dialer, logger)
	return srv.Run(ctx)
}

func printSummary(cred *session.Credential) {
	fmt.Printf("sid:       %s (redacted)\n", session.ShortSID(cred.SID))
	fmt.Printf("device_id: %s\n", cred.DeviceID)
	fmt.Printf("gateways:  %s\n", strings.Join(cred.Gateways, ", "))
	if len(cred.DNS) > 0 {
		fmt.Printf("dns:       %s (through tunnel)\n", strings.Join(cred.DNS, ", "))
	}
	apps := make(map[string]bool)
	for _, r := range cred.Policy.DomainRules {
		apps[r.AppID] = true
	}
	for _, r := range cred.Policy.SuffixRules {
		apps[r.AppID] = true
	}
	for _, r := range cred.Policy.IPRules {
		apps[r.AppID] = true
	}
	fmt.Printf("policy:    %d domain rules, %d suffix rules, %d ip rules, %d apps\n",
		len(cred.Policy.DomainRules), len(cred.Policy.SuffixRules), len(cred.Policy.IPRules), len(apps))
}

// smsPrompt reads the SMS code from stdin whenever the controller demands it.
func smsPrompt(ctx context.Context) (string, error) {
	fmt.Fprintln(os.Stderr, "The controller requires SMS verification; a code was sent to your phone.")
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
// handshake — a quick end-to-end check of the tunnel and data plane.
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
	manager := tunnel.NewManager(provider, logger)
	defer manager.Close()
	dialer := &l3.Dialer{Manager: manager, Provider: provider, Logger: logger}

	// Resolve exactly like the inbound layer: exact domain mapping first,
	// then public DNS/IP policy and tunneled split-horizon DNS fallback.
	res := resolver.New(provider, dialer)
	target, err := res.Resolve(ctx, host, port)
	if err != nil {
		return err
	}

	start := time.Now()
	conn, err := dialer.Dial(ctx, target.IP, port, target.AppID, target.Domain)
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

func validateTrustDeviceArgs(cfg *config.Config, args []string) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("trust-device requires a subcommand: list | bind | unbind <id> | logout <id>")
	}

	sub := args[0]
	switch sub {
	case "list":
		if len(args) != 1 {
			return "", fmt.Errorf("list takes no arguments")
		}
	case "bind":
		if len(args) != 1 {
			return "", fmt.Errorf("bind takes no arguments")
		}
		if cfg.ClientType != "client" {
			return "", fmt.Errorf("trust-device bind requires client_type = \"client\" in config")
		}
	case "unbind":
		if len(args) < 2 {
			return "", fmt.Errorf("unbind requires at least one device ID")
		}
		for _, id := range args[1:] {
			if strings.TrimSpace(id) == "" {
				return "", fmt.Errorf("unbind device IDs must not be empty")
			}
		}
	case "logout":
		if len(args) != 2 {
			return "", fmt.Errorf("logout requires exactly one device ID")
		}
		if strings.TrimSpace(args[1]) == "" {
			return "", fmt.Errorf("logout device ID must not be empty")
		}
	default:
		return "", fmt.Errorf("unknown subcommand %q: use list | bind | unbind <id> | logout <id>", sub)
	}
	return sub, nil
}

// cmdTrustDevice manages trusted terminals: list, bind (mark this device as
// trusted), unbind (remove a device by ID), or logout (logout a device by ID).
// Requires an active session — run `geektrust login` first if needed.
func cmdTrustDevice(ctx context.Context, cfg *config.Config, logger *slog.Logger, args []string) error {
	sub, err := validateTrustDeviceArgs(cfg, args)
	if err != nil {
		return err
	}

	provider := session.NewProvider(cfg, logger, smsPrompt)
	if _, err := provider.Credential(ctx); err != nil {
		return fmt.Errorf("trust-device: need an active session: %w", err)
	}
	sc := provider.SDPCClient()
	if sc == nil {
		return fmt.Errorf("trust-device: no controller client available")
	}

	switch sub {
	case "list":
		list, err := sc.QueryTrustDevice(ctx)
		if err != nil {
			return fmt.Errorf("query trust device: %w", err)
		}
		fmt.Printf("trust device policy enabled: %v, current trust status: %d\n",
			list.Config.Enable, list.CurrentTrustStatus)
		fmt.Printf("trusted terminals (%d):\n", len(list.Devices))
		for _, d := range list.Devices {
			marker := ""
			if d.ID == list.SelfID {
				marker = " (current)"
			}
			name := d.DeviceName
			if name == "" {
				name = d.OS + " " + d.OSVersion
			}
			fmt.Printf("  %s  %s  type=%s  lastIP=%s %s%s\n",
				d.ID, strings.TrimSpace(name), d.DeviceType, d.LastLoginIP, d.LastLoginAddress, marker)
		}

	case "bind":
		if err := sc.TrustDevice(ctx); err != nil {
			return fmt.Errorf("bind trust device: %w", err)
		}
		fmt.Println("device bound as trusted terminal")
		fmt.Println("subsequent logins with the same device_id may skip SMS verification")

	case "unbind":
		if err := sc.UntrustDevice(ctx, args[1:]); err != nil {
			return fmt.Errorf("unbind trust device: %w", err)
		}
		fmt.Printf("untrusted device(s): %s\n", strings.Join(args[1:], ", "))

	case "logout":
		if err := sc.LogoutDevice(ctx, args[1]); err != nil {
			return fmt.Errorf("logout trust device: %w", err)
		}
		fmt.Printf("logged out device: %s\n", args[1])

	}
	return nil
}
