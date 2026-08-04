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
	"syscall"
	"testing"

	"geektrust/internal/sdpc"
	"geektrust/internal/session"
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

func TestReadTCPSetupStatusAndFallback(t *testing.T) {
	response := []byte{0x05, 0x81, 0x53, 0x00, 0x00, 0x19}
	response = append(response, []byte(`{"code":0,"message":"OK"}`)...)
	response = append(response, 0x05, 0x05, 0x00, 0x01)
	err := readTCPSetup(bufio.NewReader(bytes.NewReader(response)))
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("error = %v, want ECONNREFUSED", err)
	}
	if ShouldFallbackToL3(err) {
		t.Fatal("target refusal must not fall back to L3")
	}
	if !ShouldFallbackToL3(&TCPStatusError{Status: 0x02}) {
		t.Fatal("unsupported or policy-rejected direct command should fall back to L3")
	}
	if ShouldFallbackToL3(context.Canceled) {
		t.Fatal("cancellation must not fall back to L3")
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
	if got := directGateways(cred, "app"); len(got) != 1 || got[0] != "override:441" {
		t.Fatalf("configured override = %v", got)
	}
}
