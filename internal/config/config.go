// Package config loads and validates geekTrust TOML configuration.
package config

import (
	"fmt"
	public "github.com/ShanghaitechGeekPie/geektrust/compatibility"
	defaults "github.com/ShanghaitechGeekPie/geektrust/internal/compatibility"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"unicode"

	"github.com/BurntSushi/toml"

	"github.com/ShanghaitechGeekPie/geektrust/internal/privatefile"
	"github.com/ShanghaitechGeekPie/geektrust/internal/settings"
)

// DefaultDeviceID is the legacy shared browser-mode identifier. It remains
// for backward compatibility, but client mode rejects it because trusted
// terminals require a unique identity per installation.
const DefaultDeviceID = "84B5B45FE73EC0036C3E97717308447F"

// DefaultBaseURL is the ShanghaiTech aTrust controller.
const DefaultBaseURL = "https://vpn.shanghaitech.edu.cn"

// DefaultWebListen is the default loopback address of the status panel.
const DefaultWebListen = "127.0.0.1:8081"

// Config is the top-level configuration.
type Config struct {
	UnknownFields     []string       `toml:"-"`
	Version           int            `toml:"-"`
	Compatibility     public.Profile `toml:"-"`
	DNSStrategy       string         `toml:"-"`
	Directory         string         `toml:"-"`
	CAFile            string         `toml:"-"`
	AppID             string         `toml:"app_id"`
	StrictPermissions bool           `toml:"strict_permissions"`

	Fallbacks      public.Fallbacks `toml:"-"`
	GatewayTLSName string           `toml:"-"`
	Keystore       string           `toml:"keystore"`
	DeviceID       string           `toml:"device_id"`
	BaseURL        string           `toml:"base_url"`
	Platform       string           `toml:"platform"`
	ClientType     string           `toml:"client_type"`
	LoginDomain    string           `toml:"login_domain"`
	Gateways       []string         `toml:"gateways"`
	DNS            []string         `toml:"dns"`
	StateFile      string           `toml:"state_file"`
	LogLevel       string           `toml:"log_level"`
	Inbound        Inbound          `toml:"inbound"`
	Web            WebConfig        `toml:"web"`
}

// Inbound holds the proxy listener configuration.
type Inbound struct {
	SOCKS5 Listener `toml:"socks5"`
	HTTP   Listener `toml:"http"`
}

// Listener is a single proxy listener.
type Listener struct {
	Enabled bool   `toml:"enabled"`
	Listen  string `toml:"listen"`
}

// WebConfig holds the local status panel configuration.
type WebConfig struct {
	// Enabled is a pointer to distinguish "unset" (default true) from an
	// explicit false. It is the only pointer boolean in the configuration;
	// do not spread this pattern.
	Enabled *bool  `toml:"enabled"`
	Listen  string `toml:"listen"`
}

// WebEnabled is the single entry point for the panel switch.
func (c *Config) WebEnabled() bool {
	return c.Web.Enabled == nil || *c.Web.Enabled
}

// Load reads a TOML file, applies defaults and validates the result.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var header struct {
		Version int `toml:"config_version"`
	}
	if _, err := toml.Decode(string(data), &header); err != nil {
		return nil, err
	}
	if header.Version != 0 {
		if header.Version != 2 {
			return nil, fmt.Errorf("unsupported config_version %d", header.Version)
		}
		cfg, err := loadV2(path, data)
		if err != nil {
			return nil, err
		}
		return cfg, cfg.checkPermissions(path)
	}
	var cfg Config
	meta, err := toml.Decode(string(data), &cfg)
	if err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	for _, key := range meta.Undecoded() {
		cfg.UnknownFields = append(cfg.UnknownFields, key.String())
	}
	if meta.IsDefined("compatibility") {
		return nil, fmt.Errorf("unsupported configuration field compatibility")
	}
	cfg.Version = 1
	cfg.DNSStrategy = "auto"
	cfg.applyDefaults()
	profile := defaults.Resolve(cfg.BaseURL, public.Options{})
	cfg.Fallbacks = profile.Fallbacks
	cfg.GatewayTLSName = profile.GatewayServerName
	if cfg.AppID != "" {
		cfg.Fallbacks.ApplicationID = cfg.AppID
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return &cfg, cfg.checkPermissions(path)
}

func (c *Config) checkPermissions(path string) error {
	paths := []string{path, c.Keystore, c.StateFile, c.StateFile + ".key"}
	for _, p := range paths {
		if p == "" {
			continue
		}
		if err := privatefile.Check(p, c.StrictPermissions); err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) applyDefaults() {
	if c.DeviceID == "" && c.Version != 2 {
		c.DeviceID = DefaultDeviceID
	}
	if c.BaseURL == "" {
		c.BaseURL = DefaultBaseURL
	}
	if c.Platform == "" {
		c.Platform = "Mac"
	}

	if c.StateFile == "" {
		c.StateFile = "./state.enc"
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.ClientType == "" {
		c.ClientType = "browser"
	}
	c.BaseURL = strings.TrimRight(c.BaseURL, "/")
	if c.Web.Listen == "" {
		c.Web.Listen = DefaultWebListen
	}
}

func (c *Config) validate() error {
	if err := (public.Options{Fallbacks: &c.Fallbacks}).Validate(); err != nil {
		return err
	}
	if c.Keystore == "" {
		return fmt.Errorf("keystore path is required")
	}
	if !(c.Version == 2 && c.DeviceID == "") && !isUpperHex32(c.DeviceID) {
		return fmt.Errorf("device_id must be 32 uppercase hex chars, got %q", c.DeviceID)
	}
	u, err := url.Parse(c.BaseURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.ForceQuery || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return fmt.Errorf("base_url must be an HTTPS origin")
	}
	// Platform is a server-defined, case-sensitive protocol value, not GOOS.
	if len(c.Platform) > 64 || strings.IndexFunc(c.Platform, unicode.IsControl) >= 0 {
		return fmt.Errorf("platform must be at most 64 bytes without control characters")
	}
	for i, gw := range c.Gateways {
		host, port, err := SplitHostPort(gw)
		if err != nil {
			return fmt.Errorf("gateway %q: %w", gw, err)
		}
		// Normalize so downstream dialers always get host:port.
		c.Gateways[i] = net.JoinHostPort(host, port)
	}
	for _, d := range c.DNS {
		if net.ParseIP(d) == nil {
			return fmt.Errorf("dns entry %q is not an IP address", d)
		}
	}
	for name, l := range map[string]Listener{"inbound.socks5": c.Inbound.SOCKS5, "inbound.http": c.Inbound.HTTP} {
		if l.Enabled && l.Listen == "" {
			return fmt.Errorf("%s.listen is required when enabled", name)
		}
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log_level must be one of debug/info/warn/error, got %q", c.LogLevel)
	}
	switch c.ClientType {
	case "browser", "client":
	default:
		return fmt.Errorf("client_type must be \"browser\" or \"client\", got %q", c.ClientType)
	}
	// client mode binds the device_id as a trusted terminal; the shared
	// default ID would let anyone with the same credentials inherit that
	// trust, defeating SMS. Require an explicit, non-default device_id.
	if c.ClientType == "client" && c.DeviceID == DefaultDeviceID {
		return fmt.Errorf("client_type=client requires a non-default device_id; set a unique 32-hex identifier")
	}
	if c.WebEnabled() {
		if err := c.validateWebListen(); err != nil {
			return err
		}
	}
	return nil
}

// validateWebListen enforces the loopback-only policy and rewrites
// Web.Listen to its canonical form (normalized IP literal, decimal port
// without leading zeros). The panel's Host/Origin checks and its logged
// URL all rely on this canonical value matching the browser-serialized
// authority.
func (c *Config) validateWebListen() error {
	host, port, err := net.SplitHostPort(c.Web.Listen)
	if err != nil {
		return fmt.Errorf("web.listen must be host:port, got %q", c.Web.Listen)
	}
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		return fmt.Errorf("web.listen port must be a decimal number in 1-65535, got %q", c.Web.Listen)
	}
	// Browsers elide the default HTTP port from the authority, so a port-80
	// listener could never pass the panel's strict Host/Origin checks.
	if portNum == 80 {
		return fmt.Errorf("web.listen port 80 is not allowed (browsers omit the default port in Host/Origin)")
	}
	canonicalHost := host
	if ip := net.ParseIP(host); ip != nil {
		if !ip.IsLoopback() {
			return fmt.Errorf("web.listen must be a loopback address, got %q", c.Web.Listen)
		}
		canonicalHost = ip.String()
	} else if host != "localhost" {
		return fmt.Errorf("web.listen must be a loopback address, got %q", c.Web.Listen)
	}
	c.Web.Listen = net.JoinHostPort(canonicalHost, strconv.Itoa(portNum))
	return nil
}

func isUpperHex32(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

// SplitHostPort splits a gateway address, defaulting the port to 441.
func SplitHostPort(addr string) (host string, port string, err error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", "", fmt.Errorf("empty address")
	}
	if !strings.Contains(addr, ":") {
		return addr, "441", nil
	}
	host, port, err = net.SplitHostPort(addr)
	if err != nil {
		return "", "", err
	}
	if port == "" {
		port = "441"
	}
	return host, port, nil
}

// GatewayServerName returns an explicit TLS certificate identity override.
func (c *Config) GatewayServerName() string {
	return c.GatewayTLSName
}

// SessionOptions translates the legacy file DTO to normalized session settings.
func (c *Config) SessionOptions() settings.Session {
	return settings.Session{BaseURL: c.BaseURL, DeviceID: c.DeviceID, Platform: c.Platform, ClientType: c.ClientType, LoginDomain: c.LoginDomain, Gateways: append([]string(nil), c.Gateways...), DNS: append([]string(nil), c.DNS...), Fallbacks: c.Fallbacks, GatewayFilter: c.Version == 2 && c.Gateways != nil, LegacyGatewayOverride: c.Version != 2 && len(c.Gateways) > 0, DNSConfigured: len(c.DNS) > 0}
}
