// Package frame implements the aTrust tunnel wire format: version 0x05
// frames, the one-shot tunnel authentication exchange, per-connection auth
// frames, heartbeat, and the two downlink data-frame layouts with IP-packet
// splitting.
package frame

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
)

// Version is the tunnel protocol version byte.
const Version = 0x05

// Frame commands. Responses generally set the 0x80 bit of the request cmd.
const (
	CmdMethodAuth    = 0x01 // C→S tunnel auth method negotiation
	CmdMethodAccept  = 0xD0 // S→C method accepted
	CmdVIPRequest    = 0x04 // C→S virtual IP request
	CmdAuthRequest   = 0x13 // C→S per-connection auth
	CmdAuthResponse  = 0x93 // S→C per-connection auth
	CmdDataRequest   = 0x14 // C→S uplink data
	CmdDataResponse  = 0x94 // S→C downlink data
	CmdHeartbeatReq  = 0x15 // C→S heartbeat
	CmdHeartbeatResp = 0x95 // S→C heartbeat
	CmdSecondVIPReq  = 0x16 // C→S second VIP request (dual stack)
	CmdSecondVIPResp = 0x96 // S→C second VIP response
	CmdSFrame        = 0x53 // "S" session frame (tunnel auth JSON carrier)

	maxDataLenMode = 4096
)

// Frame is one decoded tunnel frame.
type Frame struct {
	Cmd byte
	// Status is the 1-byte status field of 0x93/0x96 responses (observed
	// value 0x82; not validated).
	Status byte
	// Payload carries JSON for auth responses and raw bytes elsewhere.
	Payload []byte
	// Packets holds the split IPv4 packets of a 0x94 data frame.
	Packets [][]byte
}

// Reader reads frames from the tunnel stream.
type Reader struct {
	r *bufio.Reader
}

// NewReader wraps a stream (typically a TLS connection).
func NewReader(r io.Reader) *Reader {
	return &Reader{r: bufio.NewReader(r)}
}

// NewReaderBuf uses an existing bufio.Reader. The tunnel authentication
// exchange and the steady-state frame loop must share one buffer, or bytes
// read ahead during auth would be lost to the frame loop.
func NewReaderBuf(r *bufio.Reader) *Reader {
	return &Reader{r: r}
}

// ReadFrame decodes the next frame. Data frames (0x94) are returned with
// Packets already split by IP total-length.
func (fr *Reader) ReadFrame() (Frame, error) {
	header, err := fr.read(2)
	if err != nil {
		return Frame{}, err
	}

	// S-frames (0x53 0x00 …) carry tunnel-auth JSON outside the 0x05 envelope.
	if header[0] == CmdSFrame && header[1] == 0x00 {
		payload, err := fr.readLenPrefixed()
		if err != nil {
			return Frame{}, err
		}
		return Frame{Cmd: CmdSFrame, Payload: payload}, nil
	}

	if header[0] != Version {
		return Frame{}, fmt.Errorf("frame: unexpected header 0x%02x 0x%02x", header[0], header[1])
	}
	cmd := header[1]

	switch cmd {
	case CmdAuthResponse, CmdSecondVIPResp:
		// <status:1B> <BE16 len> <payload>
		head, err := fr.read(3)
		if err != nil {
			return Frame{}, err
		}
		payload, err := fr.read(int(binary.BigEndian.Uint16(head[1:3])))
		if err != nil {
			return Frame{}, err
		}
		return Frame{Cmd: cmd, Status: head[0], Payload: payload}, nil

	case CmdDataResponse:
		packets, err := fr.readDataResponse()
		if err != nil {
			return Frame{}, err
		}
		return Frame{Cmd: cmd, Packets: packets}, nil

	default:
		// Generic <BE16 len> <payload> (0x95 heartbeat carries len 0).
		payload, err := fr.readLenPrefixed()
		if err != nil {
			return Frame{}, err
		}
		return Frame{Cmd: cmd, Payload: payload}, nil
	}
}

// readDataResponse decodes the two 0x94 layouts, distinguished by the first
// BE16: ≤4096 → len-mode (payload = concatenated IPv4 packets); otherwise
// token-mode (<tokenLen=32> <token> 00 00 <count> [BE16 plen + pkt]×N).
func (fr *Reader) readDataResponse() ([][]byte, error) {
	peek, err := fr.r.Peek(2)
	if err != nil {
		return nil, err
	}
	if x := binary.BigEndian.Uint16(peek); x <= maxDataLenMode {
		// len-mode; x == 0 is a valid empty data frame (must not be
		// misread as token-mode, which would desync the stream).
		if _, err := fr.r.Discard(2); err != nil {
			return nil, err
		}
		payload, err := fr.read(int(x))
		if err != nil {
			return nil, err
		}
		return SplitIPPackets(payload), nil
	}

	// token-mode
	tokenLen, err := fr.r.ReadByte()
	if err != nil {
		return nil, err
	}
	if _, err := fr.read(int(tokenLen)); err != nil { // skip token
		return nil, err
	}
	if _, err := fr.read(2); err != nil { // reserved
		return nil, err
	}
	countByte, err := fr.read(1)
	if err != nil {
		return nil, err
	}
	var packets [][]byte
	for range int(countByte[0]) {
		lenBytes, err := fr.read(2)
		if err != nil {
			return nil, err
		}
		pkt, err := fr.read(int(binary.BigEndian.Uint16(lenBytes)))
		if err != nil {
			return nil, err
		}
		packets = append(packets, SplitIPPackets(pkt)...)
	}
	return packets, nil
}

func (fr *Reader) readLenPrefixed() ([]byte, error) {
	lenBytes, err := fr.read(2)
	if err != nil {
		return nil, err
	}
	return fr.read(int(binary.BigEndian.Uint16(lenBytes)))
}

func (fr *Reader) read(n int) ([]byte, error) {
	if n == 0 {
		return nil, nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(fr.r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// --- encoding ---

// EncodeTunnelAuth builds the one-shot three-segment tunnel authentication
// write: method 0xD0, S-frame {"sid":…}, VIP request. The JSON key must be
// lowercase "sid".
func EncodeTunnelAuth(sid string) ([]byte, error) {
	body, err := json.Marshal(struct {
		Sid string `json:"sid"`
	}{Sid: sid})
	if err != nil {
		return nil, err
	}
	if len(body) > 65535 {
		return nil, fmt.Errorf("frame: tunnel auth body length %d exceeds 65535", len(body))
	}
	out := make([]byte, 0, 3+4+len(body)+10)
	out = append(out, Version, CmdMethodAuth, CmdMethodAccept)
	out = append(out, CmdSFrame, 0x00)
	out = binary.BigEndian.AppendUint16(out, uint16(len(body)))
	out = append(out, body...)
	out = append(out, Version, CmdVIPRequest, 0x00, 0x01, 0, 0, 0, 0, 0, 0)
	return out, nil
}

// EncodeAuthRequest wraps an authRequestIP JSON body in a 0x13 frame.
func EncodeAuthRequest(body []byte) ([]byte, error) {
	if len(body) > 65535 {
		return nil, fmt.Errorf("frame: auth body length %d exceeds 65535", len(body))
	}
	out := make([]byte, 0, 4+len(body))
	out = append(out, Version, CmdAuthRequest)
	out = binary.BigEndian.AppendUint16(out, uint16(len(body)))
	return append(out, body...), nil
}

// EncodeData builds an uplink 0x14 data frame carrying one or more full IPv4
// packets under the given connectToken (sent as ASCII bytes). Field sizes are
// validated before narrowing to wire lengths.
func EncodeData(token string, packets ...[]byte) ([]byte, error) {
	tokenBytes := []byte(token)
	if len(tokenBytes) == 0 || len(tokenBytes) > 255 {
		return nil, fmt.Errorf("frame: token length %d out of range 1..255", len(tokenBytes))
	}
	if len(packets) == 0 || len(packets) > 255 {
		return nil, fmt.Errorf("frame: packet count %d out of range 1..255", len(packets))
	}
	size := 2 + 1 + len(tokenBytes) + 2 + 1
	for _, pkt := range packets {
		if len(pkt) > 65535 {
			return nil, fmt.Errorf("frame: packet length %d exceeds 65535", len(pkt))
		}
		size += 2 + len(pkt)
	}
	out := make([]byte, 0, size)
	out = append(out, Version, CmdDataRequest, byte(len(tokenBytes)))
	out = append(out, tokenBytes...)
	out = append(out, 0x00, 0x00, byte(len(packets)))
	for _, pkt := range packets {
		out = binary.BigEndian.AppendUint16(out, uint16(len(pkt)))
		out = append(out, pkt...)
	}
	return out, nil
}

// Heartbeat is the 4-byte heartbeat request frame.
var Heartbeat = []byte{Version, CmdHeartbeatReq, 0x00, 0x00}

// --- tunnel auth reply ---

// TunnelAuthReply is the parsed result of the tunnel authentication exchange.
type TunnelAuthReply struct {
	// DeviceID is the tunnel-internal device id (e.g. "596A7DAA"), distinct
	// from the login device_id.
	DeviceID string
	// VIP is the assigned virtual IPv4 address used as uplink source.
	VIP net.IP
}

// TunnelAuthError is a non-zero tunnel authentication code. Codes
// 10000002–10000004 and 99700001 mean the gateway line should be switched.
type TunnelAuthError struct {
	Code    int64
	Message string
}

func (e *TunnelAuthError) Error() string {
	return fmt.Sprintf("tunnel auth failed: code %d: %s", e.Code, e.Message)
}

// ShouldSwitchLine reports whether this code means "try another gateway line"
// rather than "the session is broken".
func (e *TunnelAuthError) ShouldSwitchLine() bool {
	switch e.Code {
	case 10000002, 10000003, 10000004, 99700001:
		return true
	}
	return false
}

// ReadTunnelAuthReply consumes the server's three-part reply to
// EncodeTunnelAuth: method accept (05 D0), S-frame JSON, VIP frame.
func ReadTunnelAuthReply(r *bufio.Reader) (*TunnelAuthReply, error) {
	method, err := readFull(r, 2)
	if err != nil {
		return nil, err
	}
	if method[0] != Version || method[1] != CmdMethodAccept {
		return nil, fmt.Errorf("tunnel auth: method rejected (got 0x%02x 0x%02x)", method[0], method[1])
	}

	sHead, err := readFull(r, 4)
	if err != nil {
		return nil, err
	}
	if sHead[0] != CmdSFrame {
		return nil, fmt.Errorf("tunnel auth: expected S-frame, got 0x%02x", sHead[0])
	}
	payload, err := readFull(r, int(binary.BigEndian.Uint16(sHead[2:4])))
	if err != nil {
		return nil, err
	}
	var resp struct {
		Code    int64  `json:"code"`
		Message string `json:"message"`
		Data    struct {
			DeviceID string `json:"deviceID"`
		} `json:"data"`
	}
	if err := json.Unmarshal(payload, &resp); err != nil {
		return nil, fmt.Errorf("tunnel auth: decode response: %w", err)
	}
	if resp.Code != 0 {
		return nil, &TunnelAuthError{Code: resp.Code, Message: resp.Message}
	}

	vipHead, err := readFull(r, 4)
	if err != nil {
		return nil, err
	}
	if vipHead[0] != Version {
		return nil, fmt.Errorf("tunnel auth: expected VIP frame, got 0x%02x", vipHead[0])
	}
	addrLen, err := vipAddrLen(vipHead[3])
	if err != nil {
		return nil, err
	}
	addr, err := readFull(r, addrLen)
	if err != nil {
		return nil, err
	}
	return &TunnelAuthReply{
		DeviceID: resp.Data.DeviceID,
		VIP:      net.IPv4(addr[0], addr[1], addr[2], addr[3]).To4(),
	}, nil
}

func vipAddrLen(addrType byte) (int, error) {
	switch addrType {
	case 1: // IPv4: 4 addr + 2 mask
		return 6, nil
	case 5: // dual stack: IPv4(6) + IPv6(16); the leading IPv4 is used
		return 22, nil
	case 4: // IPv6-only: this data plane is IPv4-only (ip.atype 2048)
		return 0, fmt.Errorf("tunnel auth: IPv6-only VIP assignment is not supported")
	default:
		return 0, fmt.Errorf("tunnel auth: unknown VIP addrType %d", addrType)
	}
}

// SplitIPPackets splits a buffer of concatenated IPv4 packets using each
// header's total-length field. Treating a concatenated blob as one packet
// corrupts the TCP stream.
func SplitIPPackets(data []byte) [][]byte {
	var out [][]byte
	i, n := 0, len(data)
	for i+20 <= n {
		if data[i]>>4 != 4 {
			break
		}
		total := int(binary.BigEndian.Uint16(data[i+2 : i+4]))
		if total < 20 || i+total > n {
			// Malformed or truncated: take the rest.
			out = append(out, data[i:])
			break
		}
		out = append(out, data[i:i+total])
		i += total
	}
	return out
}

func readFull(r *bufio.Reader, n int) ([]byte, error) {
	if n == 0 {
		return nil, nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
