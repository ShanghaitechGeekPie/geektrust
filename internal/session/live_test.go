package session

import (
	"context"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/ShanghaitechGeekPie/geektrust/internal/config"
)

type ephemeralStore struct{}

func (ephemeralStore) Load(context.Context) (*State, error) { return nil, nil }
func (ephemeralStore) Save(context.Context, *State) error   { return nil }

func TestECNULiveSession(t *testing.T) {
	path := os.Getenv("GEEKTRUST_ECNU_KEYSTORE")
	if path == "" {
		t.Skip("explicit live credential required")
	}
	device, err := config.GenerateDeviceID()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Keystore: path, BaseURL: "https://vpn.ecnu.edu.cn", Platform: "Mac", ClientType: "browser", DeviceID: device}
	p := NewProvider(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	p.SetStore(ephemeralStore{})
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
