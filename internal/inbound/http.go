package inbound

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"
)

// bufferedConn relays reads through the parser's bufio.Reader so bytes read
// ahead past the CONNECT request (e.g. the start of a TLS ClientHello sent
// in the same write) are not lost when the relay takes over.
type bufferedConn struct {
	*bufio.Reader
	net.Conn
}

// Read resolves the ambiguous promotion between bufio.Reader and net.Conn.
func (b *bufferedConn) Read(p []byte) (int, error) { return b.Reader.Read(p) }

// handleHTTPConnect serves one HTTP CONNECT client (PLAN.md §7). Plain HTTP
// forwarding is out of scope: this is a tunneling proxy.
func (s *Server) handleHTTPConnect(ctx context.Context, client net.Conn) {
	br := bufio.NewReader(client)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	defer req.Body.Close()

	if req.Method != http.MethodConnect {
		writeHTTPStatus(client, http.StatusMethodNotAllowed, "only CONNECT is supported")
		return
	}
	host, portStr, err := net.SplitHostPort(req.Host)
	if err != nil {
		host, portStr = req.Host, "443"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		writeHTTPStatus(client, http.StatusBadRequest, "invalid port")
		return
	}

	s.logger.Info("http CONNECT", "host", host, "port", port)

	ip, _, err := s.resolver.Resolve(ctx, host)
	if err != nil {
		s.logger.Warn("http resolve failed", "host", host, "err", err)
		writeHTTPStatus(client, http.StatusBadGateway, "host not resolvable")
		return
	}
	upstream, err := s.dialer.Dial(ctx, ip, port)
	if err != nil {
		s.logger.Warn("http dial failed", "host", host, "err", err)
		writeHTTPStatus(client, http.StatusBadGateway, "tunnel dial failed")
		return
	}

	if _, err := client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		upstream.Close()
		return
	}
	// Handshake done: lift the deadline and relay through the buffered
	// reader to preserve any read-ahead bytes.
	client.SetDeadline(time.Time{})
	relayPair(&bufferedConn{Reader: br, Conn: client}, upstream)
}

func writeHTTPStatus(client net.Conn, code int, msg string) {
	fmt.Fprintf(client, "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s\n",
		code, http.StatusText(code), len(msg)+1, msg)
}
