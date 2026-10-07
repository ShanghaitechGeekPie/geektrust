package tunnel

import (
	"bytes"
	"encoding/binary"
	"io"
	"log/slog"
	"testing"
)

func TestTCPAuthenticationRequiresResponseCode(t *testing.T) {
	for _, body := range []string{`{}`, `null`, `{"code":null}`} {
		t.Run(body, func(t *testing.T) {
			wire := binary.BigEndian.AppendUint16(nil, uint16(len(body)))
			wire = append(wire, body...)
			if err := readTCPProtocolResponse(bytes.NewReader(wire)); err == nil {
				t.Fatal("missing response code accepted TCP authentication")
			}
		})
	}
}

func TestFlowAuthenticationRequiresResponseCode(t *testing.T) {
	for _, body := range []string{`{"data":{"conntrackHash":1,"connectToken":"fixture"}}`, `{"code":null,"data":{"conntrackHash":1,"connectToken":"fixture"}}`} {
		t.Run(body, func(t *testing.T) {
			result := make(chan authResult, 1)
			tun := &Tunnel{pending: map[uint64]chan authResult{1: result}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
			tun.handleAuthResponse([]byte(body))
			select {
			case <-result:
				t.Fatal("missing response code authorized a flow")
			default:
			}
		})
	}
}
