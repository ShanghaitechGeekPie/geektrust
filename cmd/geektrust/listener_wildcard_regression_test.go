package main

import (
	"testing"

	"github.com/ShanghaitechGeekPie/geektrust/internal/config"
)

func TestWebListenConflictWithEmptyProxyHost(t *testing.T) {
	for _, web := range []string{"127.0.0.1:8081", "[::1]:8081", "localhost:8081"} {
		t.Run(web, func(t *testing.T) {
			cfg := &config.Config{Web: config.WebConfig{Listen: web}}
			cfg.Inbound.HTTP = config.Listener{Enabled: true, Listen: ":8081"}
			if !webListenConflict(cfg) {
				t.Fatal("panel must yield its port to a wildcard proxy listener")
			}
			cfg.Inbound.HTTP.Listen = ":8082"
			if webListenConflict(cfg) {
				t.Fatal("different ports must not conflict")
			}
		})
	}
}
