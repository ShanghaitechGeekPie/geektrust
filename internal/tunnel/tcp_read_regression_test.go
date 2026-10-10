package tunnel

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestTCPStreamReadKeepsRemoteEOF(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	stream := &tcpTunnelConn{conn: client, reader: bufio.NewReader(client)}
	go peer.Write([]byte{0x01, 0x01, 0, 0})
	if _, err := stream.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	stream.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, err := stream.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("second read after remote EOF = %v", err)
	}
}

func TestTCPStreamReadAcrossFrameBoundaries(t *testing.T) {
	payload := bytes.Repeat([]byte("stream-data"), 6000)
	for _, readSize := range []int{1, 31, 65536} {
		t.Run(strconv.Itoa(readSize), func(t *testing.T) {
			client, peer := net.Pipe()
			defer client.Close()
			defer peer.Close()
			stream := &tcpTunnelConn{conn: client, reader: bufio.NewReader(client)}
			go func() {
				// Empty data frames and protocol responses carry no application data.
				peer.Write([]byte{0x01, 0x00, 0, 0, 0x53, 0x00, 0, 2, 'O', 'K'})
				for remaining := payload; len(remaining) > 0; {
					n := min(len(remaining), 65535)
					header := binary.BigEndian.AppendUint16([]byte{0x01, 0x00}, uint16(n))
					peer.Write(append(header, remaining[:n]...))
					remaining = remaining[n:]
				}
				peer.Write([]byte{0x01, 0x01, 0, 0})
			}()
			stream.SetReadDeadline(time.Now().Add(3 * time.Second))
			var got []byte
			buffer := make([]byte, readSize)
			for {
				n, err := stream.Read(buffer)
				got = append(got, buffer[:n]...)
				if err != nil {
					if !errors.Is(err, io.EOF) {
						t.Fatal(err)
					}
					break
				}
			}
			if !bytes.Equal(got, payload) {
				t.Fatal("application bytes changed across frame boundaries")
			}
		})
	}
}

func TestTCPStreamReadRejectsInvalidHeader(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	stream := &tcpTunnelConn{conn: client, reader: bufio.NewReader(client)}
	go peer.Write([]byte{0xff, 0xff})
	stream.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := stream.Read(make([]byte, 1)); err == nil || !strings.Contains(err.Error(), "unexpected direct TCP frame") {
		t.Fatalf("invalid header = %v", err)
	}
}

func TestTCPStreamReadRejectsTruncatedFrame(t *testing.T) {
	for _, header := range [][]byte{{0x01}, {0x01, 0x00, 0x00}, {0x53, 0x00, 0x00, 3}, {0x53, 0x00, 0x00, 3, 'O'}} {
		client, peer := net.Pipe()
		stream := &tcpTunnelConn{conn: client, reader: bufio.NewReader(client)}
		go func() { peer.Write(header); peer.Close() }()
		_, err := stream.Read(make([]byte, 1))
		client.Close()
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("truncated header = %v", err)
		}
	}
}

func TestTCPStreamReadPreservesTruncatedPayload(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	stream := &tcpTunnelConn{conn: client, reader: bufio.NewReader(client)}
	go func() {
		peer.Write([]byte{0x01, 0x00, 0, 10, 'h', 'e', 'l', 'l', 'o'})
		peer.Close()
	}()
	var got []byte
	buffer := make([]byte, 2)
	for {
		n, err := stream.Read(buffer)
		got = append(got, buffer[:n]...)
		if err != nil {
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatal(err)
			}
			break
		}
	}
	if string(got) != "hello" {
		t.Fatalf("partial stream data lost: %q", got)
	}
}

func TestTCPStreamReadResumesAfterHeaderTimeout(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	stream := &tcpTunnelConn{conn: client, reader: bufio.NewReader(client)}
	go peer.Write([]byte{0x01})
	stream.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, err := stream.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
	stream.SetReadDeadline(time.Now().Add(time.Second))
	go peer.Write([]byte{0x00, 0, 1, 'x'})
	var payload [1]byte
	if _, err := io.ReadFull(stream, payload[:]); err != nil || payload[0] != 'x' {
		t.Fatalf("read after header timeout = %q, %v", payload, err)
	}
}

func TestTCPStreamReadResumesAfterPayloadTimeout(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	stream := &tcpTunnelConn{conn: client, reader: bufio.NewReader(client)}
	go peer.Write([]byte{0x01, 0x00, 0, 1})
	stream.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, err := stream.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
	stream.SetReadDeadline(time.Now().Add(time.Second))
	go peer.Write([]byte{'x'})
	var payload [1]byte
	if _, err := io.ReadFull(stream, payload[:]); err != nil || payload[0] != 'x' {
		t.Fatalf("read after payload timeout = %q, %v", payload, err)
	}
}

func TestTCPStreamReadResumesControlResponse(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	stream := &tcpTunnelConn{conn: client, reader: bufio.NewReader(client)}
	// A control response can be larger than the reader buffer and interrupted.
	control := append([]byte(`{"code":0,"message":"`), make([]byte, 5000)...)
	for i := len(`{"code":0,"message":"`); i < len(control); i++ {
		control[i] = 'a'
	}
	control = append(control, []byte(`"}`)...)
	header := binary.BigEndian.AppendUint16([]byte{0x53, 0x00}, uint16(len(control)))
	go peer.Write(append(header, control[:200]...))
	stream.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, err := stream.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
	stream.SetReadDeadline(time.Now().Add(time.Second))
	go peer.Write(append(control[200:], 0x01, 0x00, 0, 1, 'x'))
	var payload [1]byte
	if _, err := io.ReadFull(stream, payload[:]); err != nil || payload[0] != 'x' {
		t.Fatalf("read after control timeout = %q, %v", payload, err)
	}
}
