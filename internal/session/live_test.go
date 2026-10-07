package session

import (
	"context"
	"github.com/ShanghaitechGeekPie/geektrust/auth"
	"github.com/ShanghaitechGeekPie/geektrust/internal/storage"
	"io"
	"log/slog"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/ShanghaitechGeekPie/geektrust/internal/config"
)

func TestECNULiveSession(t *testing.T) {
	if os.Getenv("GEEKTRUST_LIVE_TESTS") != "1" {
		t.Skip("online tests require explicit GEEKTRUST_LIVE_TESTS=1")
	}
	path := os.Getenv("GEEKTRUST_ECNU_KEYSTORE")
	if path == "" {
		t.Skip("explicit live credential required")
	}
	device, err := config.GenerateDeviceID()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Keystore: path, BaseURL: "https://vpn.ecnu.edu.cn", Platform: "Mac", ClientType: "browser", DeviceID: device}
	p := NewProvider(cfg.SessionOptions(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	identity, err := auth.NewPasskey(storage.CredentialFile{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	p.Authenticate = func(ctx context.Context, h *http.Client) (string, error) {
		return "", identity.Authenticate(ctx, h, auth.IdentityRequest{AllowInteraction: true})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cred, err := p.Credential(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if cred.SID == "" || len(cred.Gateways) == 0 || cred.Policy == nil {
		t.Fatal("incomplete session")
	}
	t.Logf("session established; gateways=%d IP rules=%d domain rules=%d", len(cred.Gateways), len(cred.Policy.IPRules), len(cred.Policy.DomainRules))
}
