package runtime

import (
	"context"
	"errors"
	"github.com/ShanghaitechGeekPie/geektrust/internal/config"
	"github.com/ShanghaitechGeekPie/geektrust/internal/settings"
	"net"
	"net/http"
	"net/netip"
	"testing"
)

func TestTargetFilterRejectsBeforeGatewayDial(t *testing.T) {
	rejected := errors.New("route excludes destination")
	var seen []netip.Addr
	c, err := newLegacy(legacyOptions{
		Compatibility: settings.Compatibility{FallbackAppID: "app"},
		ControllerURL: config.DefaultBaseURL, DeviceID: "0123456789ABCDEF0123456789ABCDEF",
		Gateways: []string{"gateway.example:441"}, Transport: compatibilityTransport{},
		SessionStore:  compatibilityStore(`{"sid":"synthetic","device_id":"0123456789ABCDEF0123456789ABCDEF","client_type":"browser","cookies":[{"name":"sid","value":"synthetic"}]}`),
		Authenticator: AuthenticatorFunc(func(context.Context, *http.Client) (string, error) { return "", errors.New("unexpected login") }),
		CheckTarget:   func(ip netip.Addr) error { seen = append(seen, ip); return rejected },
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			t.Error("excluded target opened transport")
			return nil, errors.New("unexpected dial")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, network := range []string{"tcp", "udp"} {
		if _, err := c.DialContext(context.Background(), network, "192.0.2.1:443"); !errors.Is(err, rejected) {
			t.Fatalf("%s target filter: %v", network, err)
		}
	}
	packet := make([]byte, 28)
	packet[0] = 0x45
	copy(packet[16:20], []byte{192, 0, 2, 1})
	if _, err := c.ExchangeICMPEcho(context.Background(), packet); !errors.Is(err, rejected) {
		t.Fatalf("ICMP target filter: %v", err)
	}
	if len(seen) != 3 {
		t.Fatalf("checked %d targets", len(seen))
	}
	for _, ip := range seen {
		if ip != netip.MustParseAddr("192.0.2.1") {
			t.Fatal("wrong resolved destination")
		}
	}
}
