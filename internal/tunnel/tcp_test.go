package tunnel

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"syscall"
	"testing"

	"github.com/ShanghaitechGeekPie/geektrust/internal/sdpc"
	"github.com/ShanghaitechGeekPie/geektrust/internal/session"
	"github.com/ShanghaitechGeekPie/geektrust/internal/settings"
)

func TestBuildTCPRequestCombinesAuthAndDestination(t *testing.T) {
	cred := &session.Credential{
		SID:          "sid",
		DeviceID:     "device",
		Username:     "user",
		ConnectionID: "connection",
	}
	request, err := buildTCPRequest(cred, "192.0.2.10", 443, "app", "download.example")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(request[:5], []byte{0x05, 0x01, 0x81, 0x53, 0x03}) {
		t.Fatalf("request prefix = % X", request[:5])
	}
	bodyLength := int(binary.BigEndian.Uint16(request[5:7]))
	bodyEnd := 7 + bodyLength
	if bodyEnd >= len(request) {
		t.Fatalf("auth body length %d leaves no destination", bodyLength)
	}
	var body map[string]any
	if err := json.Unmarshal(request[7:bodyEnd], &body); err != nil {
		t.Fatal(err)
	}
	if body["connectionId"] != "connection" || body["destAddr"] != "download.example:443" {
		t.Fatalf("unexpected auth body: %#v", body)
	}
	if signature, _ := body["xRequestSig"].(string); signature != "" {
		t.Fatalf("xRequestSig = %q", signature)
	}
	wantDestination := append([]byte{0x05, 0x01, 0x01, 0x03, byte(len("download.example"))}, []byte("download.example")...)
	wantDestination = binary.BigEndian.AppendUint16(wantDestination, 443)
	if !bytes.Equal(request[bodyEnd:], wantDestination) {
		t.Fatalf("destination = % X, want % X", request[bodyEnd:], wantDestination)
	}
}

func TestEstablishTCPFramesApplicationData(t *testing.T) {
	client, server := net.Pipe()
	serverErr := make(chan error, 1)
	go func() {
		defer server.Close()
		if err := readTCPRequestForTest(server); err != nil {
			serverErr <- err
			return
		}
		setup := []byte{0x05, 0x81, 0x53, 0x00, 0x00, 0x19}
		setup = append(setup, []byte(`{"code":0,"message":"OK"}`)...)
		setup = append(setup, 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0)
		if _, err := server.Write(setup); err != nil {
			serverErr <- err
			return
		}
		wantWrite := []byte{0x01, 0x00, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'}
		gotWrite := make([]byte, len(wantWrite))
		if _, err := io.ReadFull(server, gotWrite); err != nil {
			serverErr <- err
			return
		}
		if !bytes.Equal(gotWrite, wantWrite) {
			serverErr <- errors.New("unexpected application data frame")
			return
		}
		closeFrame := make([]byte, 4)
		if _, err := io.ReadFull(server, closeFrame); err != nil {
			serverErr <- err
			return
		}
		if !bytes.Equal(closeFrame, []byte{0x01, 0x01, 0x00, 0x00}) {
			serverErr <- errors.New("unexpected close frame")
			return
		}
		if _, err := server.Write([]byte{0x01, 0x00, 0x00, 0x05, 'w', 'o', 'r', 'l', 'd'}); err != nil {
			serverErr <- err
			return
		}
		if _, err := server.Write([]byte{0x01, 0x01, 0x00, 0x00}); err != nil {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	cred := &session.Credential{SID: "sid", DeviceID: "device", ConnectionID: "connection"}
	conn, err := establishTCP(context.Background(), client, cred, "192.0.2.10", 443, "app", "")
	if err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Write([]byte("hello")); err != nil || n != 5 {
		t.Fatalf("Write() = %d, %v", n, err)
	}
	writer, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("direct TCP connection does not support CloseWrite")
	}
	if err := writer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "world" {
		t.Fatalf("Read() = %q", got)
	}
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("Read() after remote close = %v, want EOF", err)
	}
	if _, err := conn.Write([]byte("late")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Write() after CloseWrite = %v, want net.ErrClosed", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func readTCPRequestForTest(reader io.Reader) error {
	header := make([]byte, 7)
	if _, err := io.ReadFull(reader, header); err != nil {
		return err
	}
	if !bytes.Equal(header[:5], []byte{0x05, 0x01, 0x81, 0x53, 0x03}) {
		return errors.New("unexpected TCP request prefix")
	}
	if _, err := io.CopyN(io.Discard, reader, int64(binary.BigEndian.Uint16(header[5:7]))); err != nil {
		return err
	}
	destination := make([]byte, 10)
	_, err := io.ReadFull(reader, destination)
	return err
}

func TestReadTCPSetupStatus(t *testing.T) {
	response := []byte{0x05, 0x81, 0x53, 0x00, 0x00, 0x19}
	response = append(response, []byte(`{"code":0,"message":"OK"}`)...)
	response = append(response, 0x05, 0x05, 0x00, 0x01)
	err := readTCPSetup(bufio.NewReader(bytes.NewReader(response)))
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("error = %v, want ECONNREFUSED", err)
	}

}

func TestReadTCPSetupAcceptsOfficialPlainOK(t *testing.T) {
	response := []byte{0x05, 0x81, 0x53, 0x00, 0x00, 0x02, 'O', 'K'}
	response = append(response, 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0)
	if err := readTCPSetup(bufio.NewReader(bytes.NewReader(response))); err != nil {
		t.Fatal(err)
	}
}

func TestReadTCPSetupIgnoresNonzeroReservedByte(t *testing.T) {
	response := []byte{0x05, 0x81, 0x53, 0x00, 0x00, 0x02, 'O', 'K'}
	response = append(response, 0x05, 0x00, 0x01, 0x01, 0, 0, 0, 0, 0, 0)
	if err := readTCPSetup(bufio.NewReader(bytes.NewReader(response))); err != nil {
		t.Fatal(err)
	}
}

func TestDirectGatewaysUsesAssignedNodeGroup(t *testing.T) {
	cred := &session.Credential{
		Gateways: []string{"major:441", "assigned:441"},
		Policy: &sdpc.Resource{
			Gateways:       []string{"major:441", "assigned:441"},
			NodeGroups:     map[string][]string{"major": {"major:441"}, "assigned": {"assigned:441"}},
			AppNodeGroups:  map[string]string{"app": "assigned"},
			MajorNodeGroup: "major",
		},
	}
	if got := directGateways(cred, "app"); len(got) != 1 || got[0] != "assigned:441" {
		t.Fatalf("directGateways() = %v", got)
	}
	if got := directGateways(cred, "unknown"); len(got) != 1 || got[0] != "major:441" {
		t.Fatalf("major fallback = %v", got)
	}
	cred.Gateways = []string{"override:441"}
	if got := directGateways(cred, "app"); len(got) != 1 || got[0] != "assigned:441" {
		t.Fatalf("override escaped assigned group = %v", got)
	}
}

func TestTCPFallbackBoundaries(t *testing.T) {
	for _, err := range []error{io.EOF, io.ErrUnexpectedEOF, &TCPStatusError{Status: 0x07}, nil, errors.Join(&TCPAuthError{Code: 403}, io.EOF), errors.New("unclassified failure"), context.Canceled, context.DeadlineExceeded, &TCPStatusError{Status: 0x01}, &TCPStatusError{Status: 0x02}, &TCPStatusError{Status: 0x03}, &TCPStatusError{Status: 0x04}, &TCPStatusError{Status: 0x05}, &TCPStatusError{Status: 0x06}} {
		if ShouldFallbackToL3(err) {
			t.Fatalf("unexpected fallback: %v", err)
		}
	}
	if !ShouldFallbackToL3(&TCPSetupError{Err: &TCPStatusError{Status: 0x07}}) || !ShouldFallbackToL3(&TCPSetupError{Err: io.EOF}) {
		t.Fatal("legacy protocol/setup fallback removed")
	}
}

func TestTCPAuthenticationDenialNeverFallsBack(t *testing.T) {
	body := []byte(`{"code":403,"message":"sensitive-server-text"}`)
	packet := make([]byte, 2)
	binary.BigEndian.PutUint16(packet, uint16(len(body)))
	err := readTCPProtocolResponse(bytes.NewReader(append(packet, body...)))
	if err == nil || ShouldFallbackToL3(err) {
		t.Fatal("authentication denial was accepted or retried")
	}
	if strings.Contains(err.Error(), "sensitive-server-text") {
		t.Fatal("server response leaked")
	}
}

func TestTCPConfiguredProcessIdentity(t *testing.T) {
	identity := &settings.ProcessIdentity{Name: "custom-client", Platform: "Windows", Path: "custom-client.exe"}
	packet, err := buildTCPRequest(&session.Credential{ProcessIdentity: identity}, "192.0.2.1", 22, "app", "")
	if err != nil {
		t.Fatal(err)
	}
	length := int(binary.BigEndian.Uint16(packet[5:7]))
	var request tcpAuthRequest
	if err := json.Unmarshal(packet[7:7+length], &request); err != nil {
		t.Fatal(err)
	}
	process := request.Env.Application.Runtime.Process
	if process.Name != identity.Name || process.Platform != identity.Platform || process.Path != identity.Path || process.Fingerprint != request.ProcHash || process.Fingerprint == chromeFingerprint {
		t.Fatal("configured identity overridden by port heuristic")
	}
}
