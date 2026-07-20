package inbound

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"time"

	"geektrust/internal/resolver"
)

// SOCKS5 constants (RFC 1928).
const (
	socksVersion = 0x05

	socksCmdConnect = 0x01

	socksAtypIPv4   = 0x01
	socksAtypDomain = 0x03
	socksAtypIPv6   = 0x04

	socksReplySuccess         = 0x00
	socksReplyRefused         = 0x05 // connection refused (dial failed)
	socksReplyHostUnreachable = 0x04 // resolution failed
	socksReplyCmdUnsupported  = 0x07
	socksReplyAtypUnsupported = 0x08
)

// handleSOCKS5 serves one SOCKS5 client: no-auth greeting, CONNECT only.
// UDP ASSOCIATE is intentionally unsupported.
func (s *Server) handleSOCKS5(ctx context.Context, client net.Conn) {
	// Greeting: VER NMETHODS METHODS → VER METHOD. Select no-auth (0x00)
	// only if the client offers it; otherwise 0xFF (RFC 1928).
	head := make([]byte, 2)
	if _, err := io.ReadFull(client, head); err != nil || head[0] != socksVersion {
		return
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}
	offersNoAuth := false
	for _, m := range methods {
		if m == 0x00 {
			offersNoAuth = true
			break
		}
	}
	if !offersNoAuth {
		client.Write([]byte{socksVersion, 0xFF})
		return
	}
	if _, err := client.Write([]byte{socksVersion, 0x00}); err != nil {
		return
	}

	// Request: VER CMD RSV ATYP DST.ADDR DST.PORT
	req := make([]byte, 4)
	if _, err := io.ReadFull(client, req); err != nil {
		return
	}
	reply := func(code byte) {
		// BND.ADDR/BND.PORT are zeroed: 0.0.0.0:0.
		client.Write([]byte{socksVersion, code, 0x00, socksAtypIPv4, 0, 0, 0, 0, 0, 0})
	}

	if req[0] != socksVersion || req[2] != 0x00 {
		return // malformed request: wrong VER or nonzero RSV
	}
	if req[1] != socksCmdConnect {
		reply(socksReplyCmdUnsupported)
		return
	}

	var host string
	switch req[3] {
	case socksAtypIPv4:
		raw := make([]byte, 4)
		if _, err := io.ReadFull(client, raw); err != nil {
			return
		}
		host = net.IPv4(raw[0], raw[1], raw[2], raw[3]).String()
	case socksAtypDomain:
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(client, lenByte); err != nil {
			return
		}
		name := make([]byte, lenByte[0])
		if _, err := io.ReadFull(client, name); err != nil {
			return
		}
		host = string(name)
	default:
		// IPv6 (and anything else): the tunnel carries IPv4 only.
		reply(socksReplyAtypUnsupported)
		return
	}
	var portRaw [2]byte
	if _, err := io.ReadFull(client, portRaw[:]); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(portRaw[:]))

	s.logger.Info("socks5 CONNECT", "host", host, "port", port)

	// Resolve and dial under a bounded context so a disconnected client or
	// an unavailable gateway cannot hold the handler slot indefinitely.
	setupCtx, cancel := context.WithTimeout(ctx, handshakeLimit)
	defer cancel()
	target, err := s.resolver.Resolve(setupCtx, host, port)
	if err != nil {
		s.logger.Warn("socks5 resolve failed", "host", host, "err", err)
		if errors.Is(err, resolver.ErrUnresolvable) {
			reply(socksReplyHostUnreachable)
		} else {
			reply(socksReplyRefused)
		}
		return
	}

	upstream, err := s.dialer.Dial(setupCtx, target.IP, port, target.AppID, target.Domain)
	if err != nil {
		s.logger.Warn("socks5 dial failed", "target", net.JoinHostPort(target.IP, strconv.Itoa(port)), "err", err)
		reply(socksReplyRefused)
		return
	}
	reply(socksReplySuccess)
	s.logger.Debug("socks5 relaying", "target", net.JoinHostPort(target.IP, strconv.Itoa(port)))
	client.SetDeadline(time.Time{})
	relayPair(client, upstream)
}
