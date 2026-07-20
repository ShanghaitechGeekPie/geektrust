// Package config loads and validates geekTrust TOML configuration.
package config

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

// DefaultDeviceID is MD5("atrust-headless-client-v1").upper(). It must stay
// stable per installation because changing it makes the controller treat the
// client as a new device.
const DefaultDeviceID = "84B5B45FE73EC0036C3E97717308447F"

// DefaultAppID is the "电子资源" (library) application.
const DefaultAppID = "681165d0-1c77-11ed-8650-cd35a51aa42a"

// DefaultBaseURL is the ShanghaiTech aTrust controller.
const DefaultBaseURL = "https://vpn.shanghaitech.edu.cn"

// Config is the top-level configuration.
type Config struct {
	Keystore  string   `toml:"keystore"`
	DeviceID  string   `toml:"device_id"`
	BaseURL   string   `toml:"base_url"`
	Platform  string   `toml:"platform"`
	AppID     string   `toml:"app_id"`
	Gateways  []string `toml:"gateways"`
	DNS       []string `toml:"dns"`
	StateFile string   `toml:"state_file"`
	LogLevel  string   `toml:"log_level"`
	Inbound   Inbound  `toml:"inbound"`
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

// Load reads a TOML file, applies defaults and validates the result.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.DeviceID == "" {
		c.DeviceID = DefaultDeviceID
	}
	if c.BaseURL == "" {
		c.BaseURL = DefaultBaseURL
	}
	if c.Platform == "" {
		c.Platform = "Mac"
	}
	if c.AppID == "" {
		c.AppID = DefaultAppID
	}
	if c.StateFile == "" {
		c.StateFile = "./state.enc"
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	c.BaseURL = strings.TrimRight(c.BaseURL, "/")
}

func (c *Config) validate() error {
	if c.Keystore == "" {
		return fmt.Errorf("keystore path is required")
	}
	if !isUpperHex32(c.DeviceID) {
		return fmt.Errorf("device_id must be 32 uppercase hex chars, got %q", c.DeviceID)
	}
	if !strings.HasPrefix(c.BaseURL, "https://") && !strings.HasPrefix(c.BaseURL, "http://") {
		return fmt.Errorf("base_url must be an http(s) URL, got %q", c.BaseURL)
	}
	// platform is case sensitive server-side; catch the common mistakes early.
	if c.Platform != "Mac" {
		return fmt.Errorf("platform must be exactly \"Mac\" (case sensitive), got %q", c.Platform)
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
