package l3

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestChecksumRFC1071(t *testing.T) {
	// The checksum of a header that already contains its correct checksum
	// verifies to zero.
	pkt := ipPacket(net.IPv4(10, 19, 240, 43).To4(), net.IPv4(10, 15, 45, 163).To4(), 6,
		tcpSegment(net.IPv4(10, 19, 240, 43).To4(), net.IPv4(10, 15, 45, 163).To4(), 30001, 443, 1, 1, flagACK, 65535, nil))
	if got := checksum(pkt[:ipv4HeaderLen]); got != 0 {
		t.Errorf("IP header verify checksum = 0x%04x, want 0", got)
	}
	// TCP segment checksum verifies to zero over pseudo-header+segment.
	seg := tcpSegment(net.IPv4(10, 19, 240, 43).To4(), net.IPv4(10, 15, 45, 163).To4(), 30001, 443, 1, 1, flagPSH|flagACK, 65535, []byte("hello"))
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], net.IPv4(10, 19, 240, 43).To4())
	copy(pseudo[4:8], net.IPv4(10, 15, 45, 163).To4())
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(seg)))
	if got := checksum(append(pseudo, seg...)); got != 0 {
		t.Errorf("TCP verify checksum = 0x%04x, want 0", got)
	}
}

func TestIPPacketHeader(t *testing.T) {
	seg := tcpSegment(net.IPv4(10, 0, 0, 1).To4(), net.IPv4(10, 0, 0, 2).To4(), 1234, 443, 100, 200, flagACK, 65535, nil)
	pkt := ipPacket(net.IPv4(10, 0, 0, 1).To4(), net.IPv4(10, 0, 0, 2).To4(), 6, seg)

	if pkt[0] != 0x45 {
		t.Errorf("version/IHL = 0x%02x", pkt[0])
	}
	if total := binary.BigEndian.Uint16(pkt[2:4]); total != uint16(20+len(seg)) {
		t.Errorf("total length = %d", total)
	}
	if binary.BigEndian.Uint16(pkt[4:6]) != 0x1234 || binary.BigEndian.Uint16(pkt[6:8]) != 0x4000 {
		t.Errorf("id/flags = 0x%04x/0x%04x", binary.BigEndian.Uint16(pkt[4:6]), binary.BigEndian.Uint16(pkt[6:8]))
	}
	if pkt[8] != 64 || pkt[9] != 6 {
		t.Errorf("ttl/proto = %d/%d", pkt[8], pkt[9])
	}
	if net.IP(pkt[12:16]).String() != "10.0.0.1" || net.IP(pkt[16:20]).String() != "10.0.0.2" {
		t.Errorf("addrs = %v / %v", net.IP(pkt[12:16]), net.IP(pkt[16:20]))
	}
}

func TestParseTCPSkipsOptions(t *testing.T) {
	// Build a segment, then inflate its data offset with 4 option bytes.
	seg := tcpSegment(net.IPv4(10, 0, 0, 2).To4(), net.IPv4(10, 0, 0, 1).To4(), 443, 1234, 777, 888, flagPSH|flagACK, 65535, []byte("data"))
	withOpts := make([]byte, len(seg)+4)
	copy(withOpts, seg[:tcpHeaderLen])
	copy(withOpts[tcpHeaderLen+4:], seg[tcpHeaderLen:])
	withOpts[12] = 6 << 4 // data offset 6 → 24 bytes
	pkt := ipPacket(net.IPv4(10, 0, 0, 2).To4(), net.IPv4(10, 0, 0, 1).To4(), 6, withOpts)

	info, ok := parseTCP(pkt)
	if !ok {
		t.Fatal("parseTCP failed")
	}
	if info.seq != 777 || info.flags != flagPSH|flagACK || string(info.payload) != "data" {
		t.Errorf("parsed = %+v", info)
	}
}

func TestBuildAuthRequestIPShape(t *testing.T) {
	body, err := buildAuthRequestIP(
		"unit_sid", "681165d0-1c77-11ed-8650-cd35a51aa42a", "84B5B45FE73EC0036C3E97717308447F",
		"10.15.45.163", 443, net.IPv4(10, 19, 240, 43).To4(), 30001, 7)
	if err != nil {
		t.Fatal(err)
	}

	// Field order is protocol-significant (TECHNICAL.md §6.2).
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.UseNumber()
	tok, err := dec.Token() // {
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
}
