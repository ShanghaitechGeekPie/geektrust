package l3

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestBuildAuthRequestIPShape(t *testing.T) {
	body, err := buildAuthRequestIP("sid", "681165d0-1c77-11ed-8650-cd35a51aa42a", "84B5B45FE73EC0036C3E97717308447F", "10.15.45.163", 443, net.IPv4(10, 19, 240, 43).To4(), 30001, 1, "")
	if err != nil {
		t.Fatal(err)
	}

	// Field order is protocol-significant.
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		t.Fatal("not an object")
	}
	var keys []string
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, key.(string))
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"sid", "appId", "url", "deviceId", "connectionId", "env",
		"conntrackHash", "lang", "ip", "procHash", "xRequestSig"}
	if len(keys) != len(want) {
		t.Fatalf("keys = %v", keys)
	}
	for i := range want {
		if keys[i] != want[i] {
			t.Fatalf("key[%d] = %q, want %q (full: %v)", i, keys[i], want[i], keys)
		}
	}

	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed["deviceId"] != "84B5B45FE73EC0036C3E97717308447F" {
		t.Errorf("deviceId = %v", parsed["deviceId"])
	}
	if parsed["url"] != "tcp:10.15.45.163:443" {
		t.Errorf("url = %v", parsed["url"])
	}
	if parsed["xRequestSig"] != "" {
		t.Errorf("xRequestSig = %v", parsed["xRequestSig"])
	}
	for _, banned := range []string{"appToken", "rcAppliedInfo"} {
		if _, ok := parsed[banned]; ok {
			t.Errorf("banned field %q present", banned)
		}
	}
	// procHash == env fingerprint, uppercase hex SHA-256 of the process path.
	env := parsed["env"].(map[string]any)
	fp := env["application"].(map[string]any)["runtime"].(map[string]any)["process"].(map[string]any)["fingerprint"]
	if fp != parsed["procHash"] || fp != procFingerprint {
		t.Errorf("fingerprint/procHash mismatch: %v vs %v", fp, parsed["procHash"])
	}
	if env["application"].(map[string]any)["runtime"].(map[string]any)["process_trusted"] != "TRUSTED" {
		t.Error("process_trusted must be TRUSTED")
	}
	ip := parsed["ip"].(map[string]any)
	if ip["atype"] != float64(2048) || ip["protocol"] != float64(6) ||
		ip["destAddr"] != "10.15.45.163" || ip["destPort"] != float64(443) ||
		ip["srcAddr"] != "10.19.240.43" || ip["srcPort"] != float64(30001) {
		t.Errorf("ip = %v", ip)
	}
	// connectionId = MD5(device_id).upper() + "-" + microseconds.
	cid := parsed["connectionId"].(string)
	wantPrefix := fmt.Sprintf("%X-", md5.Sum([]byte("84B5B45FE73EC0036C3E97717308447F")))
	if !strings.HasPrefix(cid, wantPrefix) {
		t.Errorf("connectionId = %q, want prefix %q", cid, wantPrefix)
	}

	// domain is omitted when empty; when set it sits between ip and procHash.
	withDomain, err := buildAuthRequestIP("sid", "app", "84B5B45FE73EC0036C3E97717308447F",
		"180.101.49.44", 443, net.IPv4(10, 19, 240, 43).To4(), 30002, 2, "www.baidu.com")
	if err != nil {
		t.Fatal(err)
	}
	var parsedDomain map[string]any
	if err := json.Unmarshal(withDomain, &parsedDomain); err != nil {
		t.Fatal(err)
	}
	if parsedDomain["domain"] != "www.baidu.com" {
		t.Errorf("domain = %v", parsedDomain["domain"])
	}
	dec = json.NewDecoder(strings.NewReader(string(withDomain)))
	if _, err := dec.Token(); err != nil {
		t.Fatal(err)
	}
	keys = keys[:0]
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, key.(string))
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			t.Fatal(err)
		}
	}
	want = []string{"sid", "appId", "url", "deviceId", "connectionId", "env",
		"conntrackHash", "lang", "ip", "domain", "procHash", "xRequestSig"}
	if len(keys) != len(want) {
		t.Fatalf("keys with domain = %v", keys)
	}
	for i := range want {
		if keys[i] != want[i] {
			t.Fatalf("key[%d] = %q, want %q", i, keys[i], want[i])
		}
	}
}
