package runtime

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

func TestTargetFilterRejectsBeforeGatewayDial(t *testing.T) {
	rejected := errors.New("route excludes destination")
	var seen []netip.Addr
	o := contractOptions(&contractIdentity{subject: "account"}, &contractStore{state: validState()})
	o.CheckTarget = func(_ context.Context, t Target) error { seen = append(seen, t.IP); return rejected }
	o.Network.DialContext = func(context.Context, string, string) (net.Conn, error) {
		t.Error("rejected target opened a socket")
		return nil, errors.New("unexpected dial")
	}
	c, e := New(o)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	for _, n := range []string{"tcp", "udp"} {
		if _, e = c.DialContext(context.Background(), n, "192.0.2.1:443"); !errors.Is(e, rejected) {
			t.Fatal(e)
		}
	}
	packet := make([]byte, 28)
	packet[0] = 0x45
	copy(packet[16:20], []byte{192, 0, 2, 1})
	if _, e = c.ExchangeICMPEcho(context.Background(), packet); !errors.Is(e, rejected) {
		t.Fatal(e)
	}
	if len(seen) != 3 {
		t.Fatal("missing protocol target check")
	}
	for _, a := range seen {
		if a != netip.MustParseAddr("192.0.2.1") {
			t.Fatal("wrong target address")
		}
	}
}
