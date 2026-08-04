package sdpc

import (
	"encoding/json"
	"net"
	"testing"
)

const sampleResource = `{
  "code": 0,
  "data": {
    "appList": {
      "data": {
        "appInfo": [
          {
            "apps": [
              {
                "id": "681165d0-1c77-11ed-8650-cd35a51aa42a",
                "nodeGroupId": "2eb64590-0f24-11ed-8ff1-d9356cf2043a",
                "name": "电子资源",
                "addressList": [
                  {"protocol": "tcp", "port": "443", "host": "10.15.45.163"},
                  {"protocol": "tcp", "port": "443", "host": "library.shanghaitech.edu.cn"}
                ]
              },
              {
                "id": "c2fe8720-1c77-11ed-8650-cd35a51aa42a",
                "name": "Egate",
                "addressList": [
                  {"protocol": "tcp", "port": "443", "host": "user@10.15.44.192"},
                  {"protocol": "tcp", "port": "443", "host": "egate.shanghaitech.edu.cn"},
                  {"protocol": "tcp", "port": "1-65535", "host": "10.20.0.0/16"},
                  {"protocol": "tcp", "port": "80", "host": "*.wildcard.example"}
                ]
              }
            ]
          },
          {
            "apps": [
              {
                "id": "8b541db0-f776-11ec-9330-f55121c908de",
                "name": "外网资源",
                "addressList": [
                  {"protocol": "tcp", "port": "1-65535", "host": "0.0.0.0/0"},
                  {"protocol": "tcp", "port": "1-65535", "host": "*.cn"},
                  {"protocol": "tcp", "port": "1-65535", "host": "*.org"}
                ]
              },
              {
                "id": "64569440-f776-11ec-9330-f55121c908de",
                "name": "内网资源段",
                "addressList": [
                  {"protocol": "tcp", "port": "1-65535", "host": "10.0.0.0-10.255.255.255"},
                  {"protocol": "tcp", "port": "1-65535", "host": "*.com"},
                  {"protocol": "tcp", "port": "1-65535", "host": "*.org"}
                ]
              }
            ]
          }
        ],
        "config": {
          "nodeGroupConf": {
            "majorNodeGroup": {"id": "2eb64590-0f24-11ed-8ff1-d9356cf2043a"},
            "nodeGroupList": [
              {
                "id": "2eb64590-0f24-11ed-8ff1-d9356cf2043a",
                "addressInfo": [
                  {"address": "119.78.254.241:441", "type": "external"},
                  {"address": "59.78.171.241", "type": "external"},
                  {"address": "{{sdpcHost}}", "type": "sdpc"},
                  {"address": "119.78.254.241:441", "type": "duplicate"}
                ]
              }
            ]
          }
        }
      }
    },
    "sdpPolicy": {
      "data": {
        "clientOption": {
          "dnsOption": {"firstDNS": "10.0.0.53", "secondDNS": "not-an-ip"},
          "dnsOptionV2": {"firstDNS": "", "secondDNS": ""}
        }
      }
    }
  }
}`

func parseSample(t *testing.T) *Resource {
	t.Helper()
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal([]byte(sampleResource), &env); err != nil {
		t.Fatal(err)
	}
	var raw clientResource
	if err := json.Unmarshal(env.Data, &raw); err != nil {
		t.Fatal(err)
	}
	c := &Client{BaseURL: "https://vpn.shanghaitech.edu.cn", Platform: "Mac"}
	return c.parseResource(&raw)
}

func TestDomainRules(t *testing.T) {
	res := parseSample(t)

	// library:443 → 电子资源 with its internal IP.
	rule, ok := res.MatchDomain("library.shanghaitech.edu.cn", 443)
	if !ok || rule.IP != "10.15.45.163" || rule.AppID != "681165d0-1c77-11ed-8650-cd35a51aa42a" {
		t.Fatalf("library:443 = %+v, %v", rule, ok)
	}
	// @ prefix stripped.
	rule, ok = res.MatchDomain("egate.shanghaitech.edu.cn", 443)
	if !ok || rule.IP != "10.15.44.192" {
		t.Fatalf("egate:443 = %+v, %v", rule, ok)
	}
	// library:80 has no domain rule (电子资源 authorizes 443 only) — the
	// real client falls through to IP policy for it.
	if _, ok := res.MatchDomain("library.shanghaitech.edu.cn", 80); ok {
		t.Fatal("library:80 must not match a domain rule")
	}
	// Wildcards are not mapped.
	if _, ok := res.MatchDomain("wildcard.example", 80); ok {
		t.Fatal("wildcard host must not be mapped")
	}
}

func TestIPRules(t *testing.T) {
	res := parseSample(t)

	cases := []struct {
		ip    string
		port  int
		appID string
	}{
		// Exact IP beats the 10.0.0.0-10.255.255.255 range and 0.0.0.0/0.
		{"10.15.45.163", 443, "681165d0-1c77-11ed-8650-cd35a51aa42a"},
		// Same IP, unauthorized port: falls to the range rule (内网资源段).
		{"10.15.45.163", 80, "64569440-f776-11ec-9330-f55121c908de"},
		// CIDR app entry.
		{"10.20.1.2", 8080, "c2fe8720-1c77-11ed-8650-cd35a51aa42a"},
		// Internal range outside the CIDR.
		{"10.99.0.1", 22, "64569440-f776-11ec-9330-f55121c908de"},
		// Public IP → catch-all 外网资源.
		{"119.78.254.179", 443, "8b541db0-f776-11ec-9330-f55121c908de"},
		{"8.8.8.8", 53, "8b541db0-f776-11ec-9330-f55121c908de"},
	}
	for _, tc := range cases {
		rule, ok := res.MatchIP(net.ParseIP(tc.ip), tc.port)
		if !ok {
			t.Errorf("%s:%d: no match", tc.ip, tc.port)
			continue
		}
		if rule.AppID != tc.appID {
			t.Errorf("%s:%d appID = %s, want %s", tc.ip, tc.port, rule.AppID, tc.appID)
		}
	}

	// Port outside every rule → no match (AppIDFor falls back).
	if _, ok := res.MatchIP(net.ParseIP("10.20.1.2"), 0); ok {
		t.Error("port 0 must not match 1-65535")
	}
	if got := res.AppIDFor(net.ParseIP("1.2.3.4"), 65536, "fallback"); got != "fallback" {
		t.Errorf("AppIDFor out-of-range port = %q, want fallback", got)
	}
}

func TestIPRuleRangeUsesExactSpan(t *testing.T) {
	res := &Resource{IPRules: []IPRule{
		{
			IPMin: net.ParseIP("10.0.0.1"), IPMax: net.ParseIP("10.0.0.200"),
			AppID: "broad", Port: PortRange{Min: 1, Max: 65535}, Proto: "tcp",
		},
		{
			IPMin: net.ParseIP("10.0.0.50"), IPMax: net.ParseIP("10.0.0.179"),
			AppID: "narrow", Port: PortRange{Min: 1, Max: 65535}, Proto: "tcp",
		},
	}}
	rule, ok := res.MatchIP(net.ParseIP("10.0.0.100"), 443)
	if !ok || rule.AppID != "narrow" {
		t.Fatalf("range match = %+v, %v", rule, ok)
	}
}

func TestSuffixRules(t *testing.T) {
	res := parseSample(t)

	// *.org appears in both catch-all apps; appList order decides (外网资源
	// is first in the sample's second group).
	rule, ok := res.MatchSuffix("anything.org", 443)
	if !ok || rule.AppID != "8b541db0-f776-11ec-9330-f55121c908de" {
		t.Fatalf("anything.org = %+v, %v", rule, ok)
	}
	if _, ok := res.MatchSuffix("no.matching.tld", 443); ok {
		t.Fatal("unmatched suffix must not match")
	}
	// Case-insensitive host.
	if _, ok := res.MatchSuffix("WWW.EXAMPLE.ORG", 80); !ok {
		t.Fatal("suffix match must be case-insensitive")
	}
}

func TestProtocolSpecificRules(t *testing.T) {
	res := &Resource{
		DomainRules: []DomainRule{
			{Domain: "service.example", IP: "10.0.0.1", AppID: "tcp-app", Port: allPorts(), Proto: "tcp"},
			{Domain: "service.example", IP: "10.0.0.2", AppID: "udp-app", Port: allPorts(), Proto: "udp"},
		},
		SuffixRules: []SuffixRule{
			{Suffix: ".example", AppID: "tcp-app", Port: allPorts(), Proto: "tcp"},
			{Suffix: ".example", AppID: "udp-app", Port: allPorts(), Proto: "udp"},
		},
		IPRules: []IPRule{
			{IP: net.ParseIP("10.0.0.3"), AppID: "tcp-app", Port: allPorts(), Proto: "tcp"},
			{IP: net.ParseIP("10.0.0.3"), AppID: "udp-app", Port: allPorts(), Proto: "udp"},
		},
	}

	if rule, ok := res.MatchDomainProtocol("service.example", 53, "udp"); !ok || rule.AppID != "udp-app" {
		t.Fatalf("UDP domain rule = %+v, %v", rule, ok)
	}
	if rule, ok := res.MatchSuffixProtocol("other.example", 53, "udp"); !ok || rule.AppID != "udp-app" {
		t.Fatalf("UDP suffix rule = %+v, %v", rule, ok)
	}
	if rule, ok := res.MatchIPProtocol(net.ParseIP("10.0.0.3"), 53, "udp"); !ok || rule.AppID != "udp-app" {
		t.Fatalf("UDP IP rule = %+v, %v", rule, ok)
	}
	if got := res.AppIDForProtocol(net.ParseIP("10.0.0.3"), 53, "fallback", "udp"); got != "udp-app" {
		t.Fatalf("UDP appID = %q", got)
	}
	if rule, ok := res.MatchIP(net.ParseIP("10.0.0.3"), 53); !ok || rule.AppID != "tcp-app" {
		t.Fatalf("TCP compatibility wrapper = %+v, %v", rule, ok)
	}
}

func TestGatewaysAndDNS(t *testing.T) {
	res := parseSample(t)

	// Default port appended, {{sdpcHost}} substituted, deduped.
	wantGW := []string{"119.78.254.241:441", "59.78.171.241:441", "vpn.shanghaitech.edu.cn:441"}
	if len(res.Gateways) != len(wantGW) {
		t.Fatalf("gateways = %v, want %v", res.Gateways, wantGW)
	}
	for i := range wantGW {
		if res.Gateways[i] != wantGW[i] {
			t.Errorf("gateways[%d] = %q, want %q", i, res.Gateways[i], wantGW[i])
		}
	}
	if got := res.GatewaysForApp("681165d0-1c77-11ed-8650-cd35a51aa42a"); len(got) != len(wantGW) {
		t.Errorf("app node-group gateways = %v, want %v", got, wantGW)
	}
	// Only valid IPs survive.
	if len(res.DNS) != 1 || res.DNS[0] != "10.0.0.53" {
		t.Errorf("dns = %v", res.DNS)
	}
}

func TestGatewaysForApp(t *testing.T) {
	res := &Resource{
		Gateways:       []string{"flat:441"},
		MajorNodeGroup: "major",
		NodeGroups: map[string][]string{
			"major":    {"major:441"},
			"assigned": {"assigned:441"},
		},
		AppNodeGroups: map[string]string{"app": "assigned"},
	}
	if got := res.GatewaysForApp("app"); len(got) != 1 || got[0] != "assigned:441" {
		t.Fatalf("assigned gateways = %v", got)
	}
	if got := res.GatewaysForApp("unknown"); len(got) != 1 || got[0] != "major:441" {
		t.Fatalf("major fallback gateways = %v", got)
	}
	res.NodeGroups = nil
	if got := res.GatewaysForApp("app"); len(got) != 1 || got[0] != "flat:441" {
		t.Fatalf("flat fallback gateways = %v", got)
	}
}

func TestParsePortRange(t *testing.T) {
	cases := map[string]PortRange{
		"443":       {443, 443},
		"1-65535":   {1, 65535},
		"8000-9000": {8000, 9000},
		"":          {0, 65535},
		"all":       {0, 65535},
		"junk":      {0, 65535},
	}
	for in, want := range cases {
		if got := parsePortRange(in); got != want {
			t.Errorf("parsePortRange(%q) = %+v, want %+v", in, got, want)
		}
	}
}

func TestAPIErrorSessionExpired(t *testing.T) {
	for code, want := range map[int64]bool{
		CodeSessionInvalid: true,
		CodeAuthTimeout:    true,
		CodeSessionMissing: true,
		CodeTicketExpired:  true,
		CodeInvalidParam:   false,
		CodeOpAbnormal:     false,
	} {
		err := &APIError{Op: "test", Code: code, Message: "x"}
		if got := IsSessionExpired(err); got != want {
			t.Errorf("IsSessionExpired(code=%d) = %v, want %v", code, got, want)
		}
	}
}
