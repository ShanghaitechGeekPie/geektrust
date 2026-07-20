package resolver

import (
	"net"
	"testing"

	"geektrust/internal/sdpc"
	"geektrust/internal/session"
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

func TestRouteDNSResultPrefersIPPolicy(t *testing.T) {
	ip := net.ParseIP("180.101.49.44")
	policy := &sdpc.Resource{
		IPRules: []sdpc.IPRule{{
			Net:   &net.IPNet{IP: net.IPv4(128, 0, 0, 0), Mask: net.CIDRMask(1, 32)},
			AppID: "ip-app",
			Port:  sdpc.PortRange{Min: 1, Max: 65535},
			Proto: "all",
		}},
		SuffixRules: []sdpc.SuffixRule{{
			Suffix: ".com",
			AppID:  "suffix-app",
			Port:   sdpc.PortRange{Min: 1, Max: 65535},
			Proto:  "all",
		}},
	}
	cred := &session.Credential{Policy: policy, AppID: "fallback-app"}

	got := routeDNSResult(cred, "www.baidu.com", 443, ip)
	if got.IP != "180.101.49.44" || got.AppID != "ip-app" || got.Domain != "" {
		t.Fatalf("IP-authorized resolution = %+v", got)
	}

	policy.IPRules = nil
	got = routeDNSResult(cred, "www.baidu.com", 443, ip)
	if got.AppID != "suffix-app" || got.Domain != "www.baidu.com" {
		t.Fatalf("suffix fallback resolution = %+v", got)
	}

	policy.SuffixRules = nil
	got = routeDNSResult(cred, "www.baidu.com", 443, ip)
	if got.AppID != "fallback-app" || got.Domain != "" {
		t.Fatalf("default resolution = %+v", got)
	}
}
