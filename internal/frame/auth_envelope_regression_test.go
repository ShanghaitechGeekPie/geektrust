package frame

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"testing"
)

func TestTunnelAuthenticationRequiresResponseCode(t *testing.T) {
	for _, body := range []string{`{}`, `null`, `{"code":null,"data":{"deviceID":"fixture"}}`} {
		t.Run(body, func(t *testing.T) {
			wire := []byte{Version, CmdMethodAccept, CmdSFrame, 0}
			wire = binary.BigEndian.AppendUint16(wire, uint16(len(body)))
			wire = append(wire, body...)
			wire = append(wire, Version, 0, 0, 1, 192, 0, 2, 1, 0, 0)
			if _, err := ReadTunnelAuthReply(bufio.NewReader(bytes.NewReader(wire))); err == nil {
				t.Fatal("missing response code established a tunnel")
			}
		})
	}
}
