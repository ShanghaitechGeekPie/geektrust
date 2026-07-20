package resolver

import (
	"net"
	"testing"
)

func TestIsFakeIP(t *testing.T) {
	cases := map[string]bool{
		"198.18.0.1":     true,
		"198.18.10.205":  true,
		"198.19.255.255": true,
		"198.17.0.1":     false,
		"198.20.0.1":     false,
		"10.15.45.163":   false,
		"8.8.8.8":        false,
	}
	for s, want := range cases {
		if got := IsFakeIP(net.ParseIP(s)); got != want {
			t.Errorf("IsFakeIP(%s) = %v, want %v", s, got, want)
		}
	}
	if IsFakeIP(net.ParseIP("2001:db8::1")) {
		t.Error("IPv6 must not be flagged as fake-ip")
	}
}

func TestNewStages(t *testing.T) {
	// Empty config: public defaults + system fallback.
	r := New(nil, nil)
	if len(r.stages) != 2 {
		t.Fatalf("stages = %d, want 2 (public defaults + system)", len(r.stages))
	}
	// Explicit servers still keep the system stage as last resort.
	r = New(nil, []string{"1.2.3.4"})
	if len(r.stages) != 2 {
		t.Fatalf("stages = %d, want 2", len(r.stages))
	}
}
