package config

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestLegacyConfigRejectsControllerURLsRuntimeCannotUse(t *testing.T) {
	for _, origin := range []string{"http://vpn.example.edu.cn", "https://vpn.example.edu.cn/resource", "https://private:secret@vpn.example.edu.cn", "https://vpn.example.edu.cn?ticket=secret", "https://vpn.example.edu.cn#fragment"} {
		t.Run(origin, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, []byte("keystore='fixture'\nbase_url="+strconv.Quote(origin)+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("configuration passed validation with an unusable controller URL")
			}
		})
	}
}

func TestConfigRejectsEmptyQueryMarker(t *testing.T) {
	for _, data := range []string{"keystore='fixture'\nbase_url='https://vpn.example.edu.cn?'\n", "config_version=2\n[auth.passkey]\nkeystore='fixture'\n[controller]\nurl='https://vpn.example.edu.cn?'\n"} {
		p := filepath.Join(t.TempDir(), "config.toml")
		if err := os.WriteFile(p, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil {
			t.Fatal("URL ending in a query marker was accepted")
		}
	}
}
