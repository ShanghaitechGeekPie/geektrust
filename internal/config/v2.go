package config

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/BurntSushi/toml"
	public "github.com/ShanghaitechGeekPie/geektrust/compatibility"
	defaults "github.com/ShanghaitechGeekPie/geektrust/internal/compatibility"
	"github.com/ShanghaitechGeekPie/geektrust/internal/storage"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// FileV2 owns the CLI serialization contract; SDK types carry no TOML tags.
type FileV2 struct {
	Version    int `toml:"config_version"`
	Controller struct {
		URL           string `toml:"url"`
		Compatibility string `toml:"compatibility"`
		Platform      string `toml:"platform"`
	} `toml:"controller"`
	Auth struct {
		Mode        string `toml:"mode"`
		LoginDomain string `toml:"login_domain"`
		DeviceID    string `toml:"device_id"`
		Passkey     struct {
			Keystore string `toml:"keystore"`
		} `toml:"passkey"`
	} `toml:"auth"`
	Proxy struct {
		SOCKS5 struct {
			Listen string `toml:"listen"`
		} `toml:"socks5"`
		HTTP struct {
			Listen string `toml:"listen"`
		} `toml:"http"`
	} `toml:"proxy"`
	Web struct {
		Listen string `toml:"listen"`
	} `toml:"web"`
	DNS struct {
		Strategy string   `toml:"strategy"`
		Servers  []string `toml:"servers"`
	} `toml:"dns"`
	Storage struct {
		Directory string `toml:"directory"`
		StateFile string `toml:"state_file"`
	} `toml:"storage"`
	Logging struct {
		Level string `toml:"level"`
	} `toml:"logging"`
	TLS struct {
		Gateway struct {
			ServerName string `toml:"server_name"`
			CAFile     string `toml:"ca_file"`
		} `toml:"gateway"`
	} `toml:"tls"`
	Routing struct {
		GatewayFilter []string `toml:"gateway_filter"`
		FallbackAppID string   `toml:"fallback_app_id"`
	} `toml:"routing"`
}

func defaultDirectory() (string, error) {
	if runtime.GOOS == "linux" {
		if p := os.Getenv("XDG_STATE_HOME"); filepath.IsAbs(p) {
			return filepath.Join(p, "geektrust"), nil
		}
		h, e := os.UserHomeDir()
		return filepath.Join(h, ".local", "state", "geektrust"), e
	}
	if runtime.GOOS == "windows" {
		p := os.Getenv("LOCALAPPDATA")
		if !filepath.IsAbs(p) {
			return "", errors.New("LOCALAPPDATA must be an absolute user data directory")
		}
		return filepath.Join(p, "geektrust"), nil
	}
	p, e := os.UserConfigDir()
	return filepath.Join(p, "geektrust"), e
}
func loadV2(path string, data []byte) (*Config, error) {
	var f FileV2
	meta, e := toml.Decode(string(data), &f)
	if e != nil {
		return nil, e
	}
	if k := meta.Undecoded(); len(k) > 0 {
		return nil, fmt.Errorf("unknown configuration field %s", k[0])
	}
	if f.Controller.URL == "" {
		f.Controller.URL = DefaultBaseURL
	}
	u, e := url.Parse(f.Controller.URL)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.ForceQuery || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("controller.url must be an HTTPS origin")
	}
	profile := public.Profile(f.Controller.Compatibility)
	if f.Controller.Compatibility == "auto" {
		profile = public.Auto
	}
	if e := (public.Options{Profile: profile}).Validate(); e != nil {
		return nil, e
	}
	v := defaults.Resolve(f.Controller.URL, public.Options{Profile: profile, Protocol: public.ProtocolOptions{ControllerPlatform: f.Controller.Platform}})
	mode := f.Auth.Mode
	if mode == "" || mode == "auto" {
		mode = "browser"
		if v.Profile == public.ShanghaiTech {
			mode = "client"
		}
	}
	base, e := filepath.Abs(filepath.Dir(path))
	if e != nil {
		return nil, e
	}
	resolve := func(s string) string {
		if s != "" && !filepath.IsAbs(s) {
			return filepath.Join(base, s)
		}
		return s
	}
	directory := resolve(f.Storage.Directory)
	if directory == "" {
		directory, e = defaultDirectory()
		if e != nil {
			return nil, e
		}
	}
	id := f.Auth.DeviceID
	if id == "" {
		b, e := os.ReadFile(filepath.Join(directory, "device_id"))
		if e == nil {
			id = strings.TrimSpace(string(b))
		} else if !errors.Is(e, os.ErrNotExist) {
			return nil, e
		}
	}
	cfg := &Config{Version: 2, Directory: directory, DeviceID: id, Keystore: resolve(f.Auth.Passkey.Keystore), BaseURL: strings.TrimRight(f.Controller.URL, "/"), Platform: v.Platform, Compatibility: profile, ClientType: mode, LoginDomain: f.Auth.LoginDomain, Fallbacks: v.Fallbacks, GatewayTLSName: v.GatewayServerName, StateFile: filepath.Join(directory, "session.enc"), DNS: append([]string(nil), f.DNS.Servers...), DNSStrategy: f.DNS.Strategy, LogLevel: f.Logging.Level}
	if cfg.DNSStrategy == "" {
		cfg.DNSStrategy = "auto"
	}
	if cfg.DNSStrategy != "auto" && cfg.DNSStrategy != "controller" && cfg.DNSStrategy != "system" {
		return nil, errors.New("invalid dns.strategy")
	}
	if cfg.LoginDomain == "" {
		cfg.LoginDomain = v.LoginDomain
	}
	if f.Storage.StateFile != "" {
		cfg.StateFile = resolve(f.Storage.StateFile)
	}
	cfg.Gateways = f.Routing.GatewayFilter
	if f.Routing.FallbackAppID != "" {
		cfg.Fallbacks.ApplicationID = f.Routing.FallbackAppID
	}
	if f.TLS.Gateway.ServerName != "" {
		cfg.GatewayTLSName = f.TLS.Gateway.ServerName
	}
	cfg.CAFile = resolve(f.TLS.Gateway.CAFile)
	socks, http, web := "127.0.0.1:1080", "127.0.0.1:8080", DefaultWebListen
	if meta.IsDefined("proxy", "socks5", "listen") {
		socks = f.Proxy.SOCKS5.Listen
	}
	if meta.IsDefined("proxy", "http", "listen") {
		http = f.Proxy.HTTP.Listen
	}
	if meta.IsDefined("web", "listen") {
		web = f.Web.Listen
	}
	cfg.Inbound = Inbound{SOCKS5: Listener{Enabled: socks != "", Listen: socks}, HTTP: Listener{Enabled: http != "", Listen: http}}
	enabled := web != ""
	cfg.Web = WebConfig{Enabled: &enabled, Listen: web}
	cfg.applyDefaults()
	if e = cfg.validate(); e != nil {
		return nil, e
	}
	if e = cfg.ValidateListeners(); e != nil {
		return nil, e
	}
	return cfg, nil
}
func (c *Config) ValidateListeners() error {
	var addresses []string
	for _, l := range []Listener{c.Inbound.SOCKS5, c.Inbound.HTTP} {
		if !l.Enabled {
			continue
		}
		h, p, e := net.SplitHostPort(l.Listen)
		if e != nil {
			return fmt.Errorf("invalid proxy listener: %w", e)
		}
		n, e := strconv.Atoi(p)
		if e != nil || n < 1 || n > 65535 {
			return errors.New("invalid proxy port")
		}
		_ = h
		for _, a := range addresses {
			if listenerOverlap(a, l.Listen) {
				return errors.New("proxy listeners overlap")
			}
		}
		addresses = append(addresses, l.Listen)
	}
	return nil
}
func listenerOverlap(a, b string) bool {
	ah, ap, _ := net.SplitHostPort(a)
	bh, bp, _ := net.SplitHostPort(b)
	an, _ := strconv.Atoi(ap)
	bn, _ := strconv.Atoi(bp)
	if an != bn {
		return false
	}
	if ah == bh || ah == "" || bh == "" {
		return true
	}
	if ah == "localhost" {
		ah = "127.0.0.1"
	}
	if bh == "localhost" {
		bh = "127.0.0.1"
	}
	ai, bi := net.ParseIP(ah), net.ParseIP(bh)
	return ai != nil && bi != nil && (ai.Equal(bi) || ai.IsUnspecified() || bi.IsUnspecified())
}

// EnsureDeviceID is called only when starting a client, never by check/show.
func (c *Config) EnsureDeviceID() error {
	if c.DeviceID != "" {
		return nil
	}
	id, e := GenerateDeviceID()
	if e != nil {
		return e
	}
	p := filepath.Join(c.Directory, "device_id")
	if e = storage.CreateExclusive(p, []byte(id+"\n")); errors.Is(e, os.ErrExist) {
		b, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		id = strings.TrimSpace(string(b))
	} else if e != nil {
		return e
	}
	if !isUpperHex32(id) {
		return errors.New("invalid persisted device ID")
	}
	c.DeviceID = id
	return nil
}

// Migration writes only a new config. Credentials, device IDs and old encrypted caches are preserved.
func Migration(path string) ([]byte, error) {
	c, e := Load(path)
	if e != nil {
		return nil, e
	}
	if c.Version == 2 {
		return os.ReadFile(path)
	}
	if len(c.Gateways) > 0 {
		return nil, errors.New("legacy gateways override cannot be converted automatically; select permitted gateway filters explicitly")
	}
	var f FileV2
	f.Version = 2
	f.Controller.URL = c.BaseURL
	if c.GatewayTLSName == "" && c.Fallbacks.ApplicationID == "" && !c.Fallbacks.StreamToL3 && !c.Fallbacks.MissingGatewayGroup {
		f.Controller.Compatibility = "generic"
	}
	f.Controller.Platform = c.Platform
	f.Auth.Mode = c.ClientType
	f.Auth.DeviceID = c.DeviceID
	f.Auth.LoginDomain = c.LoginDomain
	f.Auth.Passkey.Keystore, e = filepath.Abs(c.Keystore)
	if e != nil {
		return nil, e
	}
	f.Storage.StateFile, e = filepath.Abs(c.StateFile)
	if e != nil {
		return nil, e
	}
	f.Proxy.SOCKS5.Listen = c.Inbound.SOCKS5.Listen
	if !c.Inbound.SOCKS5.Enabled {
		f.Proxy.SOCKS5.Listen = ""
	}
	f.Proxy.HTTP.Listen = c.Inbound.HTTP.Listen
	if !c.Inbound.HTTP.Enabled {
		f.Proxy.HTTP.Listen = ""
	}
	f.Web.Listen = c.Web.Listen
	if !c.WebEnabled() {
		f.Web.Listen = ""
	}
	f.DNS.Strategy = "auto"
	f.DNS.Servers = c.DNS
	f.Logging.Level = c.LogLevel
	f.Routing.FallbackAppID = c.AppID
	f.TLS.Gateway.ServerName = c.GatewayTLSName
	var b bytes.Buffer
	e = toml.NewEncoder(&b).Encode(f)
	return b.Bytes(), e
}
