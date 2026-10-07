package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLegacyConfigRejectsUnusableGatewayAndTunnelDNS(t *testing.T) {
	for _, extra := range []string{`gateways=["gateway.example:abc"]`, `gateways=[":441"]`, `dns=["2001:db8::53"]`} {
		t.Run(extra, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, []byte("keystore='fixture'\n"+extra+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("unusable gateway or tunnel DNS accepted")
			}
		})
	}
}
