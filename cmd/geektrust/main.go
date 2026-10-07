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
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ShanghaitechGeekPie/geektrust/internal/config"
	"github.com/ShanghaitechGeekPie/geektrust/internal/inbound"
	"github.com/ShanghaitechGeekPie/geektrust/internal/runtime"
	"github.com/ShanghaitechGeekPie/geektrust/internal/session"
	"github.com/ShanghaitechGeekPie/geektrust/internal/webui"
)

// version is replaced by scripts/package-release.sh through the Go linker.
// Direct development builds keep the explicit "dev" value.
var version = "dev"

func main() {
	var configPath string
	var showVersion bool
	flag.StringVar(&configPath, "config", "config.toml", "path to the TOML config file")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: geektrust [-config config.toml] <command>\n\nCommands:\n  version           print the version embedded at build time\n  init              generate a client-mode config and unique device ID\n  run               ensure a session, then start the SOCKS5/HTTP proxies (default)\n  login             establish a VPN session (passkey; SMS when required)\n  dial <host[:port]>  connect through the tunnel (TLS handshake on :443)\n  trust-device <sub>  manage trusted terminals (list | bind | unbind <id> | logout <id>)\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if showVersion {
		fmt.Printf("geektrust %s\n", buildVersion())
		return
	}

	cmd := "run"
	args := flag.Args()
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	if cmd == "version" {
		if len(args) != 0 {
			fmt.Fprintln(os.Stderr, "usage: geektrust version")
			os.Exit(2)
		}
		fmt.Printf("geektrust %s\n", buildVersion())
		return
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

	if cmd == "config" {
		if e := cmdConfig(configPath, args); e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		return
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "geektrust:", err)
		os.Exit(1)
	}
	if cfg.Version == 1 {
		fmt.Fprintf(os.Stderr, "Warning: using a deprecated config (version 1). Run geektrust -config %q config migrate to preview the new format, then add --write to migrate.\n", configPath)
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

func buildVersion() string {
	v := strings.TrimSpace(version)
	if v == "" {
		return "dev"
	}
	return v
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

	c, err := commandClient(cfg, logger)
	if err != nil {
		return err
	}
	defer c.Close()
	connect := c.Connect
	if *fresh {
		connect = c.Authenticate
	}
	info, err := connect(ctx)
	if err != nil {
		return err
	}
	if cfg.ClientType == "client" {
		if e := c.TrustCurrentDevice(ctx); e != nil {
			logger.Warn("trust device binding failed", "err", e)
		}
	}
	fmt.Printf("gateways: %s\ndns: %s\nauthorized resources: %d\n", strings.Join(info.Gateways, ", "), strings.Join(info.DNS, ", "), len(info.Resources))
	return nil
}

// cmdRun ensures a session, then runs the tunnel-backed SOCKS5/HTTP proxies
// until interrupted. When enabled, the web panel is assembled before the
// first login so SMS verification can be completed in the browser; any panel
// failure degrades to the terminal-only path without affecting the VPN.
func cmdRun(ctx context.Context, cfg *config.Config, logger *slog.Logger, args []string) error {
	if len(args) != 0 {
		return errors.New("usage: geektrust run")
	}
	if !cfg.Inbound.SOCKS5.Enabled && !cfg.Inbound.HTTP.Enabled {
		return errors.New("no proxy listeners enabled")
	}
	c, e := commandClient(cfg, logger)
	if e != nil {
		return e
	}
	defer c.Close()
	if cfg.WebEnabled() && !webListenConflict(cfg) {
		ln, e := net.Listen("tcp", cfg.Web.Listen)
		if e != nil {
			logger.Warn("web panel disabled", "err", e)
		} else {
			hub := webui.NewHub(cfg)
			broker := webui.NewBroker(hub.SetSMSPending)
			c.Provider().SetSMSHandler(broker)
			c.Provider().ChallengeHandler = nil
			c.Provider().AddObserver(hub)
			server := webui.NewServer(hub, broker, c, cfg)
			server.SetLifetime(ctx)
			go func() {
				if e := server.Serve(ln); e != nil && !errors.Is(e, http.ErrServerClosed) {
					logger.Warn("web panel stopped", "err", e)
				}
			}()
			defer func() {
				stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = server.Shutdown(stop)
			}()
			logger.Info("web panel", "url", "http://"+cfg.Web.Listen)
		}
	}
	return runVPN(ctx, cfg, logger, c)
}

// webListenConflict reports whether the panel address collides with an
// enabled proxy listener (the panel must never preempt the data plane).
func webListenConflict(cfg *config.Config) bool {
	for _, l := range []config.Listener{cfg.Inbound.SOCKS5, cfg.Inbound.HTTP} {
		if l.Enabled && listenOverlap(cfg.Web.Listen, l.Listen) {
			return true
		}
	}
	return false
}

// listenOverlap compares two host:port addresses semantically: equal ports
// (numeric comparison, so leading zeros cannot hide a collision) with equal
// (after IP normalization), wildcard, or localhost-equivalent hosts overlap.
// Web.Listen is canonicalized by config validation; inbound addresses are
// not, so raw string equality is not enough.
func listenOverlap(a, b string) bool {
	hostA, portA, errA := net.SplitHostPort(a)
	hostB, portB, errB := net.SplitHostPort(b)
	if errA != nil || errB != nil || !portsEqual(portA, portB) {
		return false
	}
	return hostsOverlap(hostA, hostB)
}

// portsEqual compares port strings the way net.Listen would: numeric
// comparison (leading zeros cannot hide a collision), with service names
// resolved via the system database (e.g. http-alt = 8080).
func portsEqual(a, b string) bool {
	if a == b {
		return true
	}
	numA, errA := lookupPort(a)
	numB, errB := lookupPort(b)
	return errA == nil && errB == nil && numA == numB
}

func lookupPort(s string) (int, error) {
	if n, err := strconv.Atoi(s); err == nil {
		return n, nil
	}
	return net.LookupPort("tcp", s)
}

func hostsOverlap(a, b string) bool {
	if a == b {
		return true
	}
	ipA, ipB := listenIP(a), listenIP(b)
	if ipA == nil || ipB == nil {
		return false
	}
	return ipA.Equal(ipB) || ipA.IsUnspecified() || ipB.IsUnspecified()
}

func listenIP(host string) net.IP {
	if host == "localhost" {
		return net.ParseIP("127.0.0.1")
	}
	return net.ParseIP(host)
}

// runVPN establishes the session and serves the proxy listeners.
func runVPN(ctx context.Context, cfg *config.Config, logger *slog.Logger, c *runtime.Runtime) error {
	if _, e := c.Connect(ctx); e != nil {
		return e
	}
	cred, e := c.Provider().Credential(ctx)
	if e != nil {
		return e
	}
	printSummary(cred)
	if cfg.ClientType == "client" {
		if e := c.TrustCurrentDevice(ctx); e != nil {
			logger.Warn("trust device binding failed", "err", e)
		}
	}
	return inbound.New(cfg.Inbound, c, c, logger).Run(ctx)
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
var terminalInput struct {
	once  sync.Once
	lines chan string
}

func smsPrompt(ctx context.Context) (string, error) {
	terminalInput.once.Do(func() {
		terminalInput.lines = make(chan string)
		go func() {
			defer close(terminalInput.lines)
			scan := bufio.NewScanner(os.Stdin)
			for scan.Scan() {
				select {
				case terminalInput.lines <- strings.TrimSpace(scan.Text()):
				default:
				}
			}
		}()
	})
	fmt.Fprintln(os.Stderr, "The controller requires SMS verification; enter the 6-digit code:")
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case code, ok := <-terminalInput.lines:
		if !ok || code == "" {
			return "", errors.New("no verification code provided")
		}
		return code, nil
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

	c, err := commandClient(cfg, logger)
	if err != nil {
		return err
	}
	defer c.Close()
	start := time.Now()
	conn, err := c.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	defer conn.Close()
	fmt.Printf("tunnel TCP connected: %s -> %s (%v)\n", conn.LocalAddr(), conn.RemoteAddr(),
		time.Since(start).Round(time.Millisecond))

	if port == 443 {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: host})
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

	c, err := commandClient(cfg, logger)
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err := c.Connect(ctx); err != nil {
		return fmt.Errorf("trust-device: need an active session: %w", err)
	}

	switch sub {
	case "list":
		list, err := c.QueryTrustDevice(ctx)
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
		if err := c.TrustDevice(ctx); err != nil {
			return fmt.Errorf("bind trust device: %w", err)
		}
		fmt.Println("device bound as trusted terminal")
		fmt.Println("subsequent logins with the same device_id may skip SMS verification")

	case "unbind":
		if err := c.UntrustDevice(ctx, args[1:]); err != nil {
			return fmt.Errorf("unbind trust device: %w", err)
		}
		fmt.Printf("untrusted device(s): %s\n", strings.Join(args[1:], ", "))

	case "logout":
		if err := c.LogoutTrustDevice(ctx, args[1]); err != nil {
			return fmt.Errorf("logout trust device: %w", err)
		}
		fmt.Printf("logged out device: %s\n", args[1])

	}
	return nil
}
