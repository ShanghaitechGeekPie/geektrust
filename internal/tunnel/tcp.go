package tunnel

import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ShanghaitechGeekPie/geektrust/compatibility"
	"io"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/ShanghaitechGeekPie/geektrust/internal/session"
)

const (
	tcpTunnelSetupTimeout = 18 * time.Second
	tcpFramePayloadMax    = 0xffff
	tcpCloseTimeout       = time.Second
)

const chromePath = "/usr/bin/google-chrome-stable"

var chromeFingerprint = fmt.Sprintf("%X", sha256.Sum256([]byte(chromePath)))

type tcpProcess struct {
	Name             string `json:"name"`
	DigitalSignature string `json:"digital_signature"`
	Platform         string `json:"platform"`
	Fingerprint      string `json:"fingerprint"`
	Description      string `json:"description"`
	Path             string `json:"path"`
	Version          string `json:"version"`
	SecurityEnv      string `json:"security_env"`
}

// tcpAuthRequest field order is protocol-significant. Authentication and the
// destination address are sent together in one gateway write.
type tcpAuthRequest struct {
	SID           string `json:"sid"`
	AppID         string `json:"appId"`
	URL           string `json:"url"`
	DeviceID      string `json:"deviceId"`
	ConnectionID  string `json:"connectionId"`
	ProcHash      string `json:"procHash"`
	Username      string `json:"userName"`
	RCAppliedInfo int    `json:"rcAppliedInfo"`
	Lang          string `json:"lang"`
	DestAddr      string `json:"destAddr"`
	Env           struct {
		Application struct {
			Runtime struct {
				Process        tcpProcess `json:"process"`
				ProcessTrusted string     `json:"process_trusted"`
			} `json:"runtime"`
		} `json:"application"`
	} `json:"env"`
	XRequestSig string `json:"xRequestSig"`
}

// TCPAuthError is an explicit gateway authentication rejection. It is terminal
// across both gateway selection and stream-to-L3 compatibility fallback.
type TCPSetupError struct{ Err error }

func (e *TCPSetupError) Error() string { return "TCP stream setup: " + e.Err.Error() }
func (e *TCPSetupError) Unwrap() error { return e.Err }

type TCPAuthError struct{ Code int64 }

func (e *TCPAuthError) Error() string {
	return fmt.Sprintf("direct TCP protocol rejected request: code %d", e.Code)
}

// TCPStatusError is the gateway's SOCKS-style result for opening the target.
type TCPStatusError struct {
	Status byte
}

func (e *TCPStatusError) Error() string {
	switch e.Status {
	case 0x01:
		return "TCP tunnel server failure"
	case 0x02:
		return "TCP tunnel connection not allowed"
	case 0x03:
		return "TCP tunnel network unreachable"
	case 0x04:
		return "TCP tunnel host unreachable"
	case 0x05:
		return "TCP tunnel connection refused"
	case 0x06:
		return "TCP tunnel TTL expired"
	case 0x07:
		return "TCP tunnel command not supported"
	case 0x08:
		return "TCP tunnel address type not supported"
	default:
		return fmt.Sprintf("TCP tunnel connect failed with status 0x%02x", e.Status)
	}
}

func (e *TCPStatusError) Unwrap() error {
	switch e.Status {
	case 0x03:
		return syscall.ENETUNREACH
	case 0x04:
		return syscall.EHOSTUNREACH
	case 0x05:
		return syscall.ECONNREFUSED
	case 0x06:
		return syscall.ETIMEDOUT
	default:
		return nil
	}
}

// ShouldFallbackToL3 reports whether the direct TCP setup failed before a
// definitive target-network result. It keeps compatibility with gateways that
// do not expose the TCP proxy command while preserving refusal/unreachable
// errors from gateways that do.
func ShouldFallbackToL3(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var setup *TCPSetupError
	if !errors.As(err, &setup) {
		return false
	}
	var rejected *TCPAuthError
	if errors.As(err, &rejected) {
		return false
	}
	var status *TCPStatusError
	if errors.As(err, &status) {
		return status.Status == 0x07 || status.Status == 0x08
	}
	// Only incomplete setup exchanges can indicate an unsupported stream path.
	// TLS verification, authentication rejection and unknown failures are terminal.
	return (errors.Is(setup.Err, io.EOF) || errors.Is(setup.Err, io.ErrUnexpectedEOF))
}

// DialTCP opens an aTrust TCP proxy connection. TCP uses the server's stream
// tunnel rather than the packet-oriented L3 tunnel; UDP remains on L3.
func (m *Manager) DialTCP(ctx context.Context, ip string, port int, appID, domain string) (net.Conn, error) {
	if net.ParseIP(ip).To4() == nil {
		return nil, fmt.Errorf("direct TCP target %s is not IPv4", ip)
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("direct TCP port %d is outside 1..65535", port)
	}
	cred, err := m.provider.Credential(ctx)
	if err != nil {
		return nil, err
	}
	if appID == "" && cred.Policy != nil {
		appID = cred.Policy.AppIDFor(net.ParseIP(ip).To4(), port, cred.AppID)
	}
	if appID == "" {
		return nil, errors.New("target has no authorizing application")
	}
	gateways := directGateways(cred, appID)
	lines := m.ensureDirectLines(gateways)
	attempts := len(lines.Addrs())
	if attempts == 0 {
		return nil, ErrNoLines
	}

	var lastErr error
	for range attempts {
		conn, addr, err := lines.DialTLS(ctx)
		if err != nil {
			return nil, fmt.Errorf("direct TCP gateway: %w", err)
		}
		tunneled, err := establishTCP(ctx, conn, cred, ip, port, appID, domain)
		if err == nil {
			m.logger.Debug("direct TCP tunnel established", "addr", addr, "target", net.JoinHostPort(ip, strconv.Itoa(port)))
			return tunneled, nil
		}
		lastErr = &TCPSetupError{Err: err}
		var rejected *TCPAuthError
		if errors.As(err, &rejected) {
			return nil, err
		}
		var status *TCPStatusError
		if errors.As(err, &status) && status.Status != 0x01 {
			return nil, lastErr
		}
		lines.ReportFailure(addr)
		m.logger.Debug("direct TCP line failed", "addr", addr, "err", err)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, fmt.Errorf("direct TCP setup failed on all gateway lines: %w", lastErr)
}

func directGateways(cred *session.Credential, appID string) []string {
	return cred.GatewaysForApp(appID)
}

func establishTCP(ctx context.Context, conn net.Conn, cred *session.Credential, ip string, port int, appID, domain string) (result net.Conn, err error) {
	if err := ctx.Err(); err != nil {
		conn.Close()
		return nil, err
	}
	request, err := buildTCPRequest(cred, ip, port, appID, domain)
	if err != nil {
		conn.Close()
		return nil, err
	}

	deadline := time.Now().Add(tcpTunnelSetupTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		conn.Close()
		return nil, fmt.Errorf("direct TCP setup deadline: %w", err)
	}
	stopCancel := context.AfterFunc(ctx, func() { conn.Close() })
	defer func() {
		stopCancel()
		if ctxErr := ctx.Err(); ctxErr != nil {
			if result != nil {
				result.Close()
			}
			result, err = nil, ctxErr
		}
		if err != nil {
			conn.Close()
		}
	}()

	// The official flow sends authentication and destination in one write.
	// Splitting these bytes or adding an empty data probe makes strict gateways
	// accept setup and then close the first application payload.
	n, err := conn.Write(request)
	if err == nil && n != len(request) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return nil, fmt.Errorf("direct TCP request: %w", err)
	}

	reader := bufio.NewReader(conn)
	if err := readTCPSetup(reader); err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("clear direct TCP setup deadline: %w", err)
	}
	result = &tcpTunnelConn{conn: conn, reader: reader}
	return result, nil
}

func buildTCPRequest(cred *session.Credential, ip string, port int, appID, domain string) ([]byte, error) {
	v4 := net.ParseIP(ip).To4()
	if v4 == nil {
		return nil, errors.New("direct TCP request requires IPv4")
	}
	destHost := ip
	if domain != "" {
		if len(domain) > 255 {
			return nil, errors.New("direct TCP domain exceeds 255 bytes")
		}
		destHost = domain
	}
	dest := net.JoinHostPort(destHost, strconv.Itoa(port))
	connectionID := cred.ConnectionID
	if connectionID == "" {
		connectionID = fmt.Sprintf("%X-%d", md5.Sum([]byte(cred.DeviceID)), time.Now().UnixMicro())
	}
	processName, processPath, fingerprint := "google-chrome-stable", chromePath, chromeFingerprint
	if port == 22 {
		processName, processPath = "ssh", "/usr/bin/ssh"
		fingerprint = fmt.Sprintf("%X", sha256.Sum256([]byte(processPath)))
	}
	processPlatform := "Linux"
	if identity := cred.ProcessIdentity; identity != nil {
		if err := (compatibility.Options{Protocol: compatibility.ProtocolOptions{Process: identity}}).Validate(); err != nil {
			return nil, err
		}
		processName, processPath, processPlatform = identity.Name, identity.Path, identity.Platform
		fingerprint = fmt.Sprintf("%X", sha256.Sum256([]byte(processPath)))
	}
	req := tcpAuthRequest{
		SID: cred.SID, AppID: appID, URL: "tcp://" + dest,
		DeviceID: cred.DeviceID, ConnectionID: connectionID,
		ProcHash: fingerprint, Username: cred.Username, Lang: "en-US", DestAddr: dest,
	}
	p := &req.Env.Application.Runtime.Process
	*p = tcpProcess{
		Name: processName, DigitalSignature: "TrustAppClosed", Platform: processPlatform,
		Fingerprint: fingerprint, Description: "TrustAppClosed", Path: processPath,
		Version: "TrustAppClosed", SecurityEnv: "normal",
	}
	req.Env.Application.Runtime.ProcessTrusted = "TRUSTED"
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if len(body) > 0xffff {
		return nil, fmt.Errorf("direct TCP auth body length %d exceeds 65535", len(body))
	}

	request := make([]byte, 0, 7+len(body)+4+1+len(domain)+net.IPv4len+2)
	request = append(request, 0x05, 0x01, 0x81, 0x53, 0x03)
	request = binary.BigEndian.AppendUint16(request, uint16(len(body)))
	request = append(request, body...)
	if domain == "" {
		request = append(request, 0x05, 0x01, 0x01, 0x01)
		request = append(request, v4...)
	} else {
		request = append(request, 0x05, 0x01, 0x01, 0x03, byte(len(domain)))
		request = append(request, domain...)
	}
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	return request, nil
}

func readTCPSetup(reader *bufio.Reader) error {
	for {
		var header [2]byte
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			return fmt.Errorf("direct TCP setup response: %w", err)
		}
		if header == [2]byte{0x05, 0x81} {
			continue
		}
		if header != [2]byte{0x53, 0x00} {
			return fmt.Errorf("direct TCP setup response header 0x%02x 0x%02x", header[0], header[1])
		}
		if err := readTCPProtocolResponse(reader); err != nil {
			return err
		}
		break
	}
	status, err := readTCPConnectReply(reader)
	if err != nil {
		return err
	}
	if status != 0 {
		return &TCPStatusError{Status: status}
	}
	return nil
}

func readTCPProtocolResponse(reader io.Reader) error {
	var length [2]byte
	if _, err := io.ReadFull(reader, length[:]); err != nil {
		return fmt.Errorf("direct TCP protocol response length: %w", err)
	}
	body := make([]byte, binary.BigEndian.Uint16(length[:]))
	if _, err := io.ReadFull(reader, body); err != nil {
		return fmt.Errorf("direct TCP protocol response: %w", err)
	}
	return parseTCPProtocolResponse(body)
}

func parseTCPProtocolResponse(body []byte) error {
	if string(body) == "OK" {
		return nil
	}
	var response struct {
		Code    int64  `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("decode direct TCP protocol response: %w", err)
	}
	if response.Code != 0 {
		return &TCPAuthError{Code: response.Code}
	}
	return nil
}

func readTCPConnectReply(reader io.Reader) (byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return 0, fmt.Errorf("direct TCP connect reply: %w", err)
	}
	if header[0] != 0x05 {
		return 0, fmt.Errorf("direct TCP connect reply header 0x%02x 0x%02x 0x%02x 0x%02x", header[0], header[1], header[2], header[3])
	}
	if header[1] != 0 {
		return header[1], nil
	}
	// The live gateway sets RSV to 0x01 rather than RFC 1928's 0x00, so RSV
	// must be consumed but not validated.
	addressType := header[3]
	addressLength := 0
	switch addressType {
	case 0x01:
		addressLength = net.IPv4len
	case 0x03:
		var length [1]byte
		if _, err := io.ReadFull(reader, length[:]); err != nil {
			return 0, fmt.Errorf("direct TCP bound-domain length: %w", err)
		}
		addressLength = int(length[0])
	case 0x04:
		addressLength = net.IPv6len
	default:
		return 0, fmt.Errorf("direct TCP bound address type 0x%02x", addressType)
	}
	if _, err := io.CopyN(io.Discard, reader, int64(addressLength+2)); err != nil {
		return 0, fmt.Errorf("direct TCP bound address: %w", err)
	}
	return 0, nil
}

type tcpTunnelConn struct {
	conn   net.Conn
	reader *bufio.Reader

	readMu        sync.Mutex
	readRemaining int
	readControl   []byte
	readClosed    bool
	writeMu       sync.Mutex
	// writeClosed is protected by writeMu. The protocol close frame half-closes
	// the target write direction while the TLS connection remains readable.
	writeClosed   bool
	closeWriteErr error

	closeOnce sync.Once
	closeErr  error
}

func (c *tcpTunnelConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.readClosed {
		return 0, io.EOF
	}
	for {
		if c.readControl != nil {
			offset := len(c.readControl) - c.readRemaining
			n, err := io.ReadFull(c.reader, c.readControl[offset:])
			c.readRemaining -= n
			if err != nil {
				if err == io.EOF && c.readRemaining > 0 {
					err = io.ErrUnexpectedEOF
				}
				return 0, err
			}
			err = parseTCPProtocolResponse(c.readControl)
			c.readControl = nil
			if err != nil {
				return 0, err
			}
			continue
		}
		if c.readRemaining > 0 {
			n, err := c.reader.Read(p[:min(len(p), c.readRemaining)])
			c.readRemaining -= n
			if err == io.EOF && c.readRemaining > 0 {
				err = io.ErrUnexpectedEOF
			}
			return n, err
		}
		// Peek retains a partial header across a retryable read timeout.
		header, err := c.reader.Peek(2)
		if err != nil {
			if err == io.EOF && len(header) > 0 {
				err = io.ErrUnexpectedEOF
			}
			return 0, err
		}
		kind := [2]byte{header[0], header[1]}
		if kind != [2]byte{0x01, 0x00} && kind != [2]byte{0x01, 0x01} && kind != [2]byte{0x53, 0x00} {
			return 0, fmt.Errorf("unexpected direct TCP frame 0x%02x 0x%02x", header[0], header[1])
		}
		header, err = c.reader.Peek(4)
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return 0, err
		}
		switch kind {
		case [2]byte{0x01, 0x00}:
			c.readRemaining = int(binary.BigEndian.Uint16(header[2:4]))
			c.reader.Discard(4)
		case [2]byte{0x01, 0x01}:
			c.reader.Discard(4)
			c.readClosed = true
			return 0, io.EOF
		case [2]byte{0x53, 0x00}:
			c.readRemaining = int(binary.BigEndian.Uint16(header[2:4]))
			c.readControl = make([]byte, c.readRemaining)
			c.reader.Discard(4)
		}
	}
}

func (c *tcpTunnelConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeClosed {
		return 0, net.ErrClosed
	}
	written := 0
	for len(p) > 0 {
		size := min(len(p), tcpFramePayloadMax)
		frame := make([]byte, size+4)
		frame[0], frame[1] = 0x01, 0x00
		binary.BigEndian.PutUint16(frame[2:4], uint16(size))
		copy(frame[4:], p[:size])
		n, err := writeTCPFrame(c.conn, frame)
		if err != nil {
			// A partial frame cannot be resumed with a new header.
			c.writeClosed, c.closeWriteErr = true, err
			c.conn.Close()
			return written + max(0, n-4), err
		}
		written += size
		p = p[size:]
	}
	return written, nil
}

func writeTCPFrame(w io.Writer, frame []byte) (int, error) {
	written := 0
	for len(frame) > 0 {
		n, err := w.Write(frame)
		if n > 0 {
			written += n
			frame = frame[n:]
		}
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrNoProgress
		}
	}
	return written, nil
}

// CloseWrite sends the stream close frame without closing the TLS socket, so
// callers can continue reading a response after sending an application EOF.
func (c *tcpTunnelConn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.closeWriteLocked()
}

func (c *tcpTunnelConn) closeWriteLocked() error {
	if c.writeClosed {
		return c.closeWriteErr
	}
	c.writeClosed = true
	_ = c.conn.SetWriteDeadline(time.Now().Add(tcpCloseTimeout))
	_, c.closeWriteErr = writeTCPFrame(c.conn, []byte{0x01, 0x01, 0x00, 0x00})
	if c.closeWriteErr != nil {
		c.conn.Close()
	}
	return c.closeWriteErr
}

func (c *tcpTunnelConn) Close() error {
	c.closeOnce.Do(func() {
		// Close must unblock a Write waiting on the socket. Send a graceful
		// close frame only when no writer currently owns the framed stream.
		var writeErr error
		if c.writeMu.TryLock() {
			writeErr = c.closeWriteLocked()
			c.writeMu.Unlock()
		}
		closeErr := c.conn.Close()
		if writeErr != nil {
			c.closeErr = writeErr
		} else {
			c.closeErr = closeErr
		}
	})
	return c.closeErr
}

func (c *tcpTunnelConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *tcpTunnelConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *tcpTunnelConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *tcpTunnelConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *tcpTunnelConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
