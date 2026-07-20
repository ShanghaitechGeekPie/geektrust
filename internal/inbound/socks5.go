package inbound

import (
	"bytes"
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

	socksCmdConnect      = 0x01
	socksCmdUDPAssociate = 0x03

	socksAtypIPv4   = 0x01
	socksAtypDomain = 0x03
	socksAtypIPv6   = 0x04

	socksReplySuccess         = 0x00
	socksReplyGeneralFailure  = 0x01
	socksReplyRefused         = 0x05
	socksReplyHostUnreachable = 0x04
	socksReplyCmdUnsupported  = 0x07
	socksReplyAtypUnsupported = 0x08
)

var errSOCKSAtypUnsupported = errors.New("SOCKS5 address type unsupported")

type socksAddress struct {
	host string
	port int
	atyp byte
}

// handleSOCKS5 serves one no-auth RFC 1928 CONNECT or UDP ASSOCIATE request.
func (s *Server) handleSOCKS5(ctx context.Context, client net.Conn) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(client, head); err != nil || head[0] != socksVersion {
		return
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}
	offersNoAuth := false
	for _, method := range methods {
		if method == 0x00 {
			offersNoAuth = true
			break
		}
	}
	if !offersNoAuth {
		_ = writeAll(client, []byte{socksVersion, 0xFF})
		return
	}
	if err := writeAll(client, []byte{socksVersion, 0x00}); err != nil {
		return
	}

	request := make([]byte, 4)
	if _, err := io.ReadFull(client, request); err != nil {
		return
	}
	if request[0] != socksVersion || request[2] != 0x00 {
		return
	}
	if request[1] != socksCmdConnect && request[1] != socksCmdUDPAssociate {
		_ = writeSOCKSReply(client, socksReplyCmdUnsupported, socksAddress{})
		return
	}
	target, err := readSOCKSAddress(client, request[3])
	if err != nil {
		if errors.Is(err, errSOCKSAtypUnsupported) {
			_ = writeSOCKSReply(client, socksReplyAtypUnsupported, socksAddress{})
		}
		return
	}

	switch request[1] {
	case socksCmdConnect:
		if target.atyp == socksAtypIPv6 {
			_ = writeSOCKSReply(client, socksReplyAtypUnsupported, socksAddress{})
			return
		}
		s.handleSOCKSConnect(ctx, client, target)
	default:
		s.handleSOCKSUDPAssociate(ctx, client, target)
	}
}

func (s *Server) handleSOCKSConnect(ctx context.Context, client net.Conn, destination socksAddress) {
	s.logger.Info("socks5 CONNECT", "host", destination.host, "port", destination.port)
	setupCtx, cancel := context.WithTimeout(ctx, handshakeLimit)
	defer cancel()
	target, err := s.resolver.Resolve(setupCtx, destination.host, destination.port)
	if err != nil {
		if errors.Is(err, resolver.ErrGatewayLoop) {
			s.logger.Debug("socks5 refused recursive gateway CONNECT", "host", destination.host, "port", destination.port)
		} else {
			s.logger.Warn("socks5 resolve failed", "host", destination.host, "err", err)
		}
		code := byte(socksReplyRefused)
		if errors.Is(err, resolver.ErrUnresolvable) {
			code = socksReplyHostUnreachable
		}
		_ = writeSOCKSReply(client, code, socksAddress{})
		return
	}

	upstream, err := s.dialer.Dial(setupCtx, target.IP, destination.port, target.AppID, target.Domain)
	if err != nil {
		s.logger.Warn("socks5 dial failed", "target", net.JoinHostPort(target.IP, strconv.Itoa(destination.port)), "err", err)
		_ = writeSOCKSReply(client, socksReplyRefused, socksAddress{})
		return
	}
	if err := writeSOCKSReply(client, socksReplySuccess, socksAddress{}); err != nil {
		upstream.Close()
		return
	}
	s.logger.Debug("socks5 relaying", "target", net.JoinHostPort(target.IP, strconv.Itoa(destination.port)))
	_ = client.SetDeadline(time.Time{})
	relayPair(client, upstream)
}

func (s *Server) handleSOCKSUDPAssociate(ctx context.Context, client net.Conn, requested socksAddress) {
	udpConn, clientIP, err := listenSOCKSUDP(client)
	if err != nil {
		_ = writeSOCKSReply(client, socksReplyGeneralFailure, socksAddress{})
		return
	}
	s.track(udpConn, true)
	defer func() {
		s.track(udpConn, false)
		udpConn.Close()
	}()

	bound := udpConn.LocalAddr().(*net.UDPAddr)
	if err := writeSOCKSReply(client, socksReplySuccess, socksAddress{host: bound.IP.String(), port: bound.Port}); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})
	s.logger.Info("socks5 UDP ASSOCIATE", "client", clientIP.String(), "bind", bound.String())

	go func() {
		_, _ = io.Copy(io.Discard, client)
		udpConn.Close()
	}()

	var clientPort int
	if requested.port != 0 {
		clientPort = requested.port
	}
	table := newUDPFlowTable(ctx, s, maxUDPFlows, func(target udpTarget, payload []byte) error {
		packet, err := marshalSOCKSUDPDatagram(target, payload)
		if err != nil {
			return err
		}
		_, err = udpConn.WriteToUDP(packet, &net.UDPAddr{IP: clientIP, Port: clientPort})
		if err != nil {
			udpConn.Close()
		}
		return err
	})
	defer table.Close()

	buffer := make([]byte, 65535)
	for {
		n, source, err := udpConn.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		if !source.IP.Equal(clientIP) || (clientPort != 0 && source.Port != clientPort) {
			continue
		}
		if clientPort == 0 {
			clientPort = source.Port
		}
		target, payload, err := parseSOCKSUDPDatagram(buffer[:n])
		if err != nil {
			continue
		}
		if err := table.Send(target, payload); err != nil && !errors.Is(err, errUDPDatagramTooLarge) {
			s.logger.Debug("socks5 UDP relay failed", "target", target.key(), "err", err)
		}
	}
}

func listenSOCKSUDP(client net.Conn) (*net.UDPConn, net.IP, error) {
	local, localOK := client.LocalAddr().(*net.TCPAddr)
	remote, remoteOK := client.RemoteAddr().(*net.TCPAddr)
	if !localOK || !remoteOK {
		return nil, nil, errors.New("SOCKS5 UDP requires TCP socket addresses")
	}
	network := "udp6"
	if local.IP.To4() != nil {
		network = "udp4"
	}
	conn, err := net.ListenUDP(network, &net.UDPAddr{IP: local.IP, Zone: local.Zone})
	if err != nil {
		return nil, nil, err
	}
	return conn, append(net.IP(nil), remote.IP...), nil
}

func readSOCKSAddress(r io.Reader, atyp byte) (socksAddress, error) {
	address := socksAddress{atyp: atyp}
	switch atyp {
	case socksAtypIPv4:
		raw := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(r, raw); err != nil {
			return socksAddress{}, err
		}
		address.host = net.IP(raw).String()
	case socksAtypDomain:
		var length [1]byte
		if _, err := io.ReadFull(r, length[:]); err != nil {
			return socksAddress{}, err
		}
		if length[0] == 0 {
			return socksAddress{}, errors.New("empty SOCKS5 domain")
		}
		raw := make([]byte, int(length[0]))
		if _, err := io.ReadFull(r, raw); err != nil {
			return socksAddress{}, err
		}
		address.host = string(raw)
	case socksAtypIPv6:
		raw := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(r, raw); err != nil {
			return socksAddress{}, err
		}
		address.host = net.IP(raw).String()
	default:
		return socksAddress{}, errSOCKSAtypUnsupported
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return socksAddress{}, err
	}
	address.port = int(binary.BigEndian.Uint16(port[:]))
	return address, nil
}

func writeSOCKSReply(w io.Writer, code byte, bound socksAddress) error {
	packet := []byte{socksVersion, code, 0x00}
	if bound.host == "" {
		bound = socksAddress{host: net.IPv4zero.String()}
	}
	packet, err := appendSOCKSAddress(packet, bound.host, bound.port)
	if err != nil {
		return err
	}
	return writeAll(w, packet)
}

func appendSOCKSAddress(dst []byte, host string, port int) ([]byte, error) {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			dst = append(dst, socksAtypIPv4)
			dst = append(dst, v4...)
		} else {
			dst = append(dst, socksAtypIPv6)
			dst = append(dst, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, errors.New("invalid SOCKS5 domain length")
		}
		dst = append(dst, socksAtypDomain, byte(len(host)))
		dst = append(dst, host...)
	}
	return binary.BigEndian.AppendUint16(dst, uint16(port)), nil
}

func parseSOCKSUDPDatagram(packet []byte) (udpTarget, []byte, error) {
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return udpTarget{}, nil, errors.New("invalid or fragmented SOCKS5 UDP datagram")
	}
	reader := bytes.NewReader(packet[4:])
	address, err := readSOCKSAddress(reader, packet[3])
	if err != nil {
		return udpTarget{}, nil, err
	}
	if address.atyp == socksAtypIPv6 {
		return udpTarget{}, nil, errSOCKSAtypUnsupported
	}
	target, err := newUDPTarget(address.host, address.port)
	if err != nil {
		return udpTarget{}, nil, err
	}
	payloadOffset := len(packet) - reader.Len()
	return target, packet[payloadOffset:], nil
}

func marshalSOCKSUDPDatagram(target udpTarget, payload []byte) ([]byte, error) {
	packet, err := appendSOCKSAddress([]byte{0x00, 0x00, 0x00}, target.host, target.port)
	if err != nil {
		return nil, err
	}
	return append(packet, payload...), nil
}
