// Package l3 implements the aTrust data plane: per-connection authentication
// and a userspace TCP endpoint carried inside tunnel IPv4 packets.
package l3

import (
	"encoding/binary"
	"net"
)

// TCP flag bits.
const (
	flagFIN = 0x01
	flagSYN = 0x02
	flagRST = 0x04
	flagPSH = 0x08
	flagACK = 0x10
)

// MSS is the maximum segment payload; 1400 leaves headroom under the 1500-byte MTU.
const MSS = 1400

// ipv4HeaderLen is the fixed header size we emit (IHL=5, no options).
const ipv4HeaderLen = 20

// tcpHeaderLen is the fixed TCP header size we emit (data offset=5).
const tcpHeaderLen = 20

// checksum computes the Internet checksum (RFC 1071) over data.
func checksum(data []byte) uint16 {
	var sum uint32
	i := 0
	for ; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	if i < len(data) {
		sum += uint32(data[i]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	return ^uint16(sum)
}

// tcpSegment builds a TCP segment with correct checksum (pseudo-header
// included): data offset 5, urgent 0. win advertises the receive window
// (backpressure).
func tcpSegment(srcIP, dstIP net.IP, sport, dport uint16, seq, ack uint32, flags byte, win uint16, payload []byte) []byte {
	src4, dst4 := srcIP.To4(), dstIP.To4()
	seg := make([]byte, tcpHeaderLen+len(payload))
	binary.BigEndian.PutUint16(seg[0:2], sport)
	binary.BigEndian.PutUint16(seg[2:4], dport)
	binary.BigEndian.PutUint32(seg[4:8], seq)
	binary.BigEndian.PutUint32(seg[8:12], ack)
	seg[12] = 5 << 4 // data offset
	seg[13] = flags
	binary.BigEndian.PutUint16(seg[14:16], win)

	pseudo := make([]byte, 12)
	copy(pseudo[0:4], src4)
	copy(pseudo[4:8], dst4)
	pseudo[9] = 6 // TCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(seg)))
	// Checksum covers pseudo-header + TCP header + payload. Hash only the
	// header slice here: seg's payload region is still zero-filled, and an
	// odd-length zero run would shift the payload's 16-bit alignment.
	csumInput := make([]byte, 0, 12+tcpHeaderLen+len(payload))
	csumInput = append(csumInput, pseudo...)
	csumInput = append(csumInput, seg[:tcpHeaderLen]...)
	csumInput = append(csumInput, payload...)
	binary.BigEndian.PutUint16(seg[16:18], checksum(csumInput))
	copy(seg[tcpHeaderLen:], payload)
	return seg
}

// ipPacket wraps a segment in an IPv4 header with fixed fields: 0x45,
// id 0x1234, DF, TTL 64.
func ipPacket(srcIP, dstIP net.IP, proto byte, segment []byte) []byte {
	src4, dst4 := srcIP.To4(), dstIP.To4()
	total := ipv4HeaderLen + len(segment)
	pkt := make([]byte, total)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	binary.BigEndian.PutUint16(pkt[4:6], 0x1234)
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000) // DF
	pkt[8] = 64                                  // TTL
	pkt[9] = proto
	copy(pkt[12:16], src4)
	copy(pkt[16:20], dst4)
	binary.BigEndian.PutUint16(pkt[10:12], checksum(pkt[:ipv4HeaderLen]))
	copy(pkt[ipv4HeaderLen:], segment)
	return pkt
}

// tcpInfo is the decoded part of a downlink TCP segment we act on.
type tcpInfo struct {
	seq     uint32
	flags   byte
	payload []byte
}

// parseTCP extracts seq/flags/payload from an IPv4 packet. doff-aware so
// options on incoming segments are skipped.
func parseTCP(pkt []byte) (tcpInfo, bool) {
	if len(pkt) < ipv4HeaderLen || pkt[0]>>4 != 4 || pkt[9] != 6 {
		return tcpInfo{}, false
	}
	ihl := int(pkt[0]&0x0F) * 4
	if ihl < ipv4HeaderLen || len(pkt) < ihl+tcpHeaderLen {
		return tcpInfo{}, false
	}
	tcp := pkt[ihl:]
	doff := int(tcp[12]>>4) * 4
	if doff < tcpHeaderLen || len(tcp) < doff {
		return tcpInfo{}, false
	}
	return tcpInfo{
		seq:     binary.BigEndian.Uint32(tcp[4:8]),
		flags:   tcp[13],
		payload: tcp[doff:],
	}, true
}
