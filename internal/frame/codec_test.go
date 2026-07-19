package frame

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// fakeIP builds a minimal IPv4 header of totalLen bytes (payload zero-filled).
func fakeIP(totalLen int) []byte {
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[8] = 64 // TTL
	pkt[9] = 6  // TCP
	return pkt
}

func TestEncodeTunnelAuthBytes(t *testing.T) {
	raw, err := EncodeTunnelAuth("unit_sid")
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"sid":"unit_sid"}`)
	want := []byte{0x05, 0x01, 0xD0, 0x53, 0x00}
	want = binary.BigEndian.AppendUint16(want, uint16(len(body)))
	want = append(want, body...)
	want = append(want, 0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0)
	if !bytes.Equal(raw, want) {
		t.Errorf("EncodeTunnelAuth = %x\nwant %x", raw, want)
	}
}

func TestReadTunnelAuthReply(t *testing.T) {
	authJSON := []byte(`{"code":0,"data":{"deviceID":"596A7DAA"},"message":"OK"}`)
	var stream bytes.Buffer
	stream.Write([]byte{0x05, 0xD0})
	stream.Write([]byte{0x53, 0x00})
	stream.Write(binary.BigEndian.AppendUint16(nil, uint16(len(authJSON))))
	stream.Write(authJSON)
	// VIP frame: addrType 1 → 6 bytes, VIP 10.19.240.43 + 2 mask bytes.
	stream.Write([]byte{0x05, 0x00, 0x00, 0x01, 10, 19, 240, 43, 0xFF, 0xFF})

	reply, err := ReadTunnelAuthReply(bufio.NewReader(&stream))
	if err != nil {
		t.Fatal(err)
	}
	if reply.DeviceID != "596A7DAA" {
		t.Errorf("deviceID = %q", reply.DeviceID)
	}
	if reply.VIP.String() != "10.19.240.43" {
		t.Errorf("VIP = %s", reply.VIP)
	}
}

func TestReadTunnelAuthReplyFailure(t *testing.T) {
	authJSON := []byte(`{"code":10000003,"message":"line busy"}`)
	var stream bytes.Buffer
	stream.Write([]byte{0x05, 0xD0, 0x53, 0x00})
	stream.Write(binary.BigEndian.AppendUint16(nil, uint16(len(authJSON))))
	stream.Write(authJSON)

	_, err := ReadTunnelAuthReply(bufio.NewReader(&stream))
	var authErr *TunnelAuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("err = %v, want *TunnelAuthError", err)
	}
	if !authErr.ShouldSwitchLine() {
		t.Errorf("code %d must trigger line switch", authErr.Code)
	}
}

func TestReadFrameAuthResponse(t *testing.T) {
	payload := []byte(`{"code":0,"data":{"connectToken":"tok","conntrackHash":7}}`)
	var stream bytes.Buffer
	stream.Write([]byte{0x05, 0x93, 0x82})
	stream.Write(binary.BigEndian.AppendUint16(nil, uint16(len(payload))))
	stream.Write(payload)

	fr, err := NewReader(&stream).ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if fr.Cmd != CmdAuthResponse || fr.Status != 0x82 {
		t.Errorf("cmd/status = 0x%02x/0x%02x", fr.Cmd, fr.Status)
	}
	var parsed struct {
		Data struct {
			ConntrackHash uint64 `json:"conntrackHash"`
		} `json:"data"`
	}
	if err := json.Unmarshal(fr.Payload, &parsed); err != nil || parsed.Data.ConntrackHash != 7 {
		t.Errorf("payload parse: %v %+v", err, parsed)
	}
}

func TestReadFrameHeartbeat(t *testing.T) {
	fr, err := NewReader(bytes.NewReader([]byte{0x05, 0x95, 0x00, 0x00})).ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if fr.Cmd != CmdHeartbeatResp || len(fr.Payload) != 0 {
		t.Errorf("heartbeat frame = %+v", fr)
	}
}

func TestReadFrameDataLenMode(t *testing.T) {
	// Two concatenated IPv4 packets (60 and 40 bytes) in len-mode.
	blob := append(fakeIP(60), fakeIP(40)...)
	var stream bytes.Buffer
	stream.Write([]byte{0x05, 0x94})
	stream.Write(binary.BigEndian.AppendUint16(nil, uint16(len(blob))))
	stream.Write(blob)

	fr, err := NewReader(&stream).ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if fr.Cmd != CmdDataResponse {
		t.Fatalf("cmd = 0x%02x", fr.Cmd)
	}
	if len(fr.Packets) != 2 || len(fr.Packets[0]) != 60 || len(fr.Packets[1]) != 40 {
		t.Fatalf("packets = %d/%d", len(fr.Packets), lens(fr.Packets))
	}
}

func TestReadFrameDataTokenMode(t *testing.T) {
	// token-mode: first BE16 = 0x20XX (>4096), tokenLen=32.
	token := bytes.Repeat([]byte("t"), 32)
	pkt1, pkt2 := fakeIP(52), fakeIP(72)
	var stream bytes.Buffer
	stream.Write([]byte{0x05, 0x94, 0x20}) // 0x20 + first token byte → BE16 0x2074 > 4096
	stream.Write(token)
	stream.Write([]byte{0x00, 0x00, 0x02})
	stream.Write(binary.BigEndian.AppendUint16(nil, uint16(len(pkt1))))
	stream.Write(pkt1)
	stream.Write(binary.BigEndian.AppendUint16(nil, uint16(len(pkt2))))
	stream.Write(pkt2)

	fr, err := NewReader(&stream).ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if len(fr.Packets) != 2 || len(fr.Packets[0]) != 52 || len(fr.Packets[1]) != 72 {
		t.Fatalf("packets = %v", lens(fr.Packets))
	}
}

func TestSplitIPPackets(t *testing.T) {
	a, b, c := fakeIP(20), fakeIP(64), fakeIP(40)
	blob := append(append(append([]byte{}, a...), b...), c...)
	got := SplitIPPackets(blob)
	if len(got) != 3 {
		t.Fatalf("split into %d packets", len(got))
	}
	// Trailing garbage shorter than an IP header is dropped.
	got = SplitIPPackets(append(blob, 0x45, 0x00))
	if len(got) != 3 {
		t.Errorf("trailing runt: %d packets", len(got))
	}
	// Truncated final packet: take the rest.
	trunc := append(append([]byte{}, a...), fakeIP(64)[:30]...)
	got = SplitIPPackets(trunc)
	if len(got) != 2 || len(got[1]) != 30 {
		t.Errorf("truncated: %v", lens(got))
	}
	// Non-IPv4 stops splitting.
	got = SplitIPPackets([]byte{0x60, 0, 0, 0})
	if len(got) != 0 {
		t.Errorf("non-v4: %v", lens(got))
	}
}

func TestEncodeDataLayout(t *testing.T) {
	pkt := fakeIP(28)
	raw, err := EncodeData("abcd1234", pkt)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x05, 0x14, 8}
	want = append(want, "abcd1234"...)
	want = append(want, 0x00, 0x00, 0x01)
	want = binary.BigEndian.AppendUint16(want, uint16(len(pkt)))
	want = append(want, pkt...)
	if !bytes.Equal(raw, want) {
		t.Errorf("EncodeData mismatch:\ngot  %x\nwant %x", raw, want)
	}
}

func TestEncodeDataValidation(t *testing.T) {
	if _, err := EncodeData("", fakeIP(20)); err == nil {
		t.Error("empty token accepted")
	}
	if _, err := EncodeData(strings.Repeat("t", 256), fakeIP(20)); err == nil {
		t.Error("oversize token accepted")
	}
	if _, err := EncodeData("tok"); err == nil {
		t.Error("zero packets accepted")
	}
	if _, err := EncodeData("tok", make([]byte, 65536)); err == nil {
		t.Error("oversize packet accepted")
	}
}

func TestReadFrameDataLenModeZero(t *testing.T) {
	// A zero-length len-mode frame followed by a heartbeat must not desync
	// the stream (regression: x == 0 used to fall into token-mode).
	stream := append([]byte{0x05, 0x94, 0x00, 0x00}, 0x05, 0x95, 0x00, 0x00)
	r := NewReader(bytes.NewReader(stream))
	fr, err := r.ReadFrame()
	if err != nil || fr.Cmd != CmdDataResponse || len(fr.Packets) != 0 {
		t.Fatalf("empty data frame = %+v, %v", fr, err)
	}
	hb, err := r.ReadFrame()
	if err != nil || hb.Cmd != CmdHeartbeatResp {
		t.Fatalf("stream desynced: %+v, %v", hb, err)
	}
}

func TestEncodeAuthRequestLayout(t *testing.T) {
	body := []byte(`{"sid":"s"}`)
	raw := EncodeAuthRequest(body)
	want := append([]byte{0x05, 0x13, 0x00, byte(len(body))}, body...)
	if !bytes.Equal(raw, want) {
		t.Errorf("EncodeAuthRequest = %x, want %x", raw, want)
	}
}

func lens(pkts [][]byte) []int {
	out := make([]int, len(pkts))
	for i, p := range pkts {
		out[i] = len(p)
	}
	return out
}
