package sdpc

import (
	"encoding/json"
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
              },
              {
                "id": "e335af60-5a60-11ed-838c-bbadf788d6f3",
                "name": "security agent (shares the library IP)",
                "addressList": [
                  {"protocol": "tcp", "port": "443", "host": "10.15.45.163"},
                  {"protocol": "tcp", "port": "443", "host": "library.shanghaitech.edu.cn"}
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

func TestParseResource(t *testing.T) {
	// doJSON hands parseResource the envelope's data payload, so unwrap first.
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
	res := c.parseResource(&raw)

	// Domain → first internal IP of the same app (TECHNICAL.md §4.2).
	lib, ok := res.DomainMap["library.shanghaitech.edu.cn"]
	if !ok || lib.IP != "10.15.45.163" || lib.AppID != "681165d0-1c77-11ed-8650-cd35a51aa42a" {
		t.Errorf("library mapping = %+v", lib)
	}
	// "@" prefix is stripped before classification.
	egate, ok := res.DomainMap["egate.shanghaitech.edu.cn"]
	if !ok || egate.IP != "10.15.44.192" || egate.AppID != "c2fe8720-1c77-11ed-8650-cd35a51aa42a" {
		t.Errorf("egate mapping = %+v", egate)
	}
	// Wildcard/range hosts are never mapped.
	if _, ok := res.DomainMap["*.wildcard.example"]; ok {
		t.Error("wildcard host must not be mapped")
	}
	if _, ok := res.DomainMap["10.20.0.0/16"]; ok {
		t.Error("CIDR host must not be mapped as domain")
	}
	// Direct-IP lookup for per-connection auth appId: first-wins. The sample
	// security-agent app also lists 10.15.45.163 later; the gateway rejects
	// dials under the wrong app (code 10000005), so 电子资源 must keep it.
	if res.IPApps["10.15.45.163"] != "681165d0-1c77-11ed-8650-cd35a51aa42a" {
		t.Errorf("IPApps[10.15.45.163] = %q", res.IPApps["10.15.45.163"])
	}

	// Gateways: default port appended, {{sdpcHost}} substituted, deduped.
	wantGW := []string{"119.78.254.241:441", "59.78.171.241:441", "vpn.shanghaitech.edu.cn:441"}
	if len(res.Gateways) != len(wantGW) {
		t.Fatalf("gateways = %v, want %v", res.Gateways, wantGW)
	}
	for i := range wantGW {
		if res.Gateways[i] != wantGW[i] {
			t.Errorf("gateways[%d] = %q, want %q", i, res.Gateways[i], wantGW[i])
		}
	}

	// DNS: only valid IPs survive.
	if len(res.DNS) != 1 || res.DNS[0] != "10.0.0.53" {
		t.Errorf("dns = %v", res.DNS)
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
