package inbound

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"geektrust/internal/resolver"
)

const connectUDPPathPrefix = "/.well-known/masque/udp/"

// bufferedConn relays reads through the parser's bufio.Reader so bytes read
// ahead past CONNECT are not lost when the relay takes over.
type bufferedConn struct {
	*bufio.Reader
	net.Conn
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.Reader.Read(p) }

func (b *bufferedConn) CloseWrite() error {
	if writer, ok := b.Conn.(closeWriter); ok {
		return writer.CloseWrite()
	}
	return b.Conn.Close()
}

// handleHTTPConnect serves HTTP/1.1 CONNECT and RFC 9298 CONNECT-UDP.
func (s *Server) handleHTTPConnect(ctx context.Context, client net.Conn) {
	br := bufio.NewReader(client)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	defer req.Body.Close()

	if isConnectUDPIntent(req) {
		s.handleHTTPConnectUDP(ctx, client, br, req)
		return
	}
	if req.Method != http.MethodConnect {
		writeHTTPStatus(client, http.StatusMethodNotAllowed, "only CONNECT and CONNECT-UDP are supported")
		return
	}
	s.handleHTTPConnectTCP(ctx, client, br, req)
}

func (s *Server) handleHTTPConnectTCP(ctx context.Context, client net.Conn, br *bufio.Reader, req *http.Request) {
	host, portStr, err := net.SplitHostPort(req.Host)
	if err != nil {
		host, portStr = req.Host, "443"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		writeHTTPStatus(client, http.StatusBadRequest, "invalid port")
		return
	}

	s.logger.Info("http CONNECT", "host", host, "port", port)
	setupCtx, cancel := context.WithTimeout(ctx, handshakeLimit)
	defer cancel()
	target, err := s.resolver.Resolve(setupCtx, host, port)
	if err != nil {
		if errors.Is(err, resolver.ErrGatewayLoop) {
			s.logger.Debug("http refused recursive gateway CONNECT", "host", host, "port", port)
		} else {
			s.logger.Warn("http resolve failed", "host", host, "err", err)
		}
		writeHTTPStatus(client, http.StatusBadGateway, "host not resolvable")
		return
	}
	upstream, err := s.dialer.Dial(setupCtx, target.IP, port, target.AppID, target.Domain)
	if err != nil {
		s.logger.Warn("http dial failed", "host", host, "err", err)
		writeHTTPStatus(client, http.StatusBadGateway, "tunnel dial failed")
		return
	}

	if err := writeAll(client, []byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		upstream.Close()
		return
	}
	_ = client.SetDeadline(time.Time{})
	relayPair(&bufferedConn{Reader: br, Conn: client}, upstream)
}

func (s *Server) handleHTTPConnectUDP(ctx context.Context, client net.Conn, br *bufio.Reader, req *http.Request) {
	target, err := parseConnectUDPRequest(req)
	if err != nil {
		writeHTTPStatus(client, http.StatusBadRequest, err.Error())
		return
	}

	var writeMu sync.Mutex
	table := newUDPFlowTable(ctx, s, 1, func(_ udpTarget, payload []byte) error {
		writeMu.Lock()
		err := writeDatagramCapsule(client, payload)
		writeMu.Unlock()
		if err != nil {
			client.Close()
		}
		return err
	})
	defer table.Close()

	setupCtx, cancel := context.WithTimeout(ctx, handshakeLimit)
	err = table.Open(setupCtx, target)
	cancel()
	if err != nil {
		s.logger.Warn("http CONNECT-UDP dial failed", "target", target.key(), "err", err)
		writeHTTPStatus(client, http.StatusBadGateway, "UDP tunnel dial failed")
		return
	}
	if err := writeAll(client, []byte(
		"HTTP/1.1 101 Switching Protocols\r\n"+
			"Connection: Upgrade\r\n"+
			"Upgrade: connect-udp\r\n"+
			"Capsule-Protocol: ?1\r\n\r\n")); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})
	s.logger.Info("http CONNECT-UDP", "target", target.key())

	for {
		capsuleType, err := readQUICVarint(br)
		if err != nil {
			return
		}
		length, err := readQUICVarint(br)
		if err != nil {
			return
		}
		if capsuleType != 0 || length > maxUDPPayload+8 {
			if _, err := io.CopyN(io.Discard, br, int64(length)); err != nil {
				return
			}
			continue
		}
		value := make([]byte, int(length))
		if _, err := io.ReadFull(br, value); err != nil {
			return
		}
		valueReader := bytes.NewReader(value)
		contextID, err := readQUICVarint(valueReader)
		if err != nil {
			return
		}
		if contextID != 0 {
			continue
		}
		payload := value[len(value)-valueReader.Len():]
		if err := table.Send(target, payload); err != nil && !errors.Is(err, errUDPDatagramTooLarge) {
			s.logger.Debug("http CONNECT-UDP relay failed", "target", target.key(), "err", err)
		}
	}
}

func isConnectUDPIntent(req *http.Request) bool {
	return strings.HasPrefix(req.URL.Path, connectUDPPathPrefix) ||
		strings.EqualFold(strings.TrimSpace(req.Header.Get("Upgrade")), "connect-udp")
}

func parseConnectUDPRequest(req *http.Request) (udpTarget, error) {
	if req.ProtoMajor != 1 || req.ProtoMinor != 1 || req.Method != http.MethodGet ||
		req.Host == "" || !headerHasToken(req.Header.Values("Connection"), "upgrade") {
		return udpTarget{}, errors.New("malformed CONNECT-UDP request")
	}
	upgrades := req.Header.Values("Upgrade")
	if len(upgrades) != 1 || !strings.EqualFold(strings.TrimSpace(upgrades[0]), "connect-udp") {
		return udpTarget{}, errors.New("malformed CONNECT-UDP upgrade")
	}
	if len(req.Header.Values("Content-Length")) != 0 ||
		len(req.Header.Values("Content-Type")) != 0 ||
		len(req.TransferEncoding) != 0 {
		return udpTarget{}, errors.New("CONNECT-UDP cannot carry HTTP content")
	}
	if req.URL.RawQuery != "" {
		return udpTarget{}, errors.New("unsupported CONNECT-UDP URI template")
	}

	path := req.URL.EscapedPath()
	if !strings.HasPrefix(path, connectUDPPathPrefix) || !strings.HasSuffix(path, "/") {
		return udpTarget{}, errors.New("invalid CONNECT-UDP target path")
	}
	parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(path, connectUDPPathPrefix), "/"), "/")
	if len(parts) != 2 {
		return udpTarget{}, errors.New("invalid CONNECT-UDP target path")
	}
	host, err := url.PathUnescape(parts[0])
	if err != nil {
		return udpTarget{}, errors.New("invalid CONNECT-UDP target host")
	}
	portText, err := url.PathUnescape(parts[1])
	if err != nil {
		return udpTarget{}, errors.New("invalid CONNECT-UDP target port")
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return udpTarget{}, errors.New("invalid CONNECT-UDP target port")
	}
	return newUDPTarget(host, port)
}

func headerHasToken(values []string, target string) bool {
	for _, value := range values {
		for token := range strings.SplitSeq(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), target) {
				return true
			}
		}
	}
	return false
}

func readQUICVarint(r io.Reader) (uint64, error) {
	var first [1]byte
	if _, err := io.ReadFull(r, first[:]); err != nil {
		return 0, err
	}
	length := 1 << (first[0] >> 6)
	value := uint64(first[0] & 0x3f)
	var rest [7]byte
	if _, err := io.ReadFull(r, rest[:length-1]); err != nil {
		return 0, err
	}
	for _, octet := range rest[:length-1] {
		value = value<<8 | uint64(octet)
	}
	return value, nil
}

func appendQUICVarint(dst []byte, value uint64) ([]byte, error) {
	switch {
	case value < 1<<6:
		return append(dst, byte(value)), nil
	case value < 1<<14:
		return binary.BigEndian.AppendUint16(dst, uint16(value)|0x4000), nil
	case value < 1<<30:
		return binary.BigEndian.AppendUint32(dst, uint32(value)|0x80000000), nil
	case value < 1<<62:
		return binary.BigEndian.AppendUint64(dst, value|0xc000000000000000), nil
	default:
		return nil, errors.New("QUIC variable-length integer out of range")
	}
}

func writeDatagramCapsule(w io.Writer, payload []byte) error {
	packet := make([]byte, 0, len(payload)+10)
	packet, _ = appendQUICVarint(packet, 0)
	packet, _ = appendQUICVarint(packet, uint64(len(payload)+1))
	packet = append(packet, 0)
	packet = append(packet, payload...)
	return writeAll(w, packet)
}

func writeHTTPStatus(client net.Conn, code int, msg string) {
	fmt.Fprintf(client, "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s\n",
		code, http.StatusText(code), len(msg)+1, msg)
}
