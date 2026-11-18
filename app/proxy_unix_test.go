package app

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

// captureConn records everything written to it.
type captureConn struct {
	net.Conn
	buf bytes.Buffer
}

func (c *captureConn) Write(b []byte) (int, error) {
	return c.buf.Write(b)
}

// TestWriteTrojanUnixHandshakePort verifies that the 2-byte big-endian port
// field carries the requested port and that ports which do not fit into it
// are rejected instead of being silently truncated (uint16(70000) == 4464).
func TestWriteTrojanUnixHandshakePort(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantErr bool
		want    uint16
	}{
		{name: "ipv4", addr: "127.0.0.1:8080", want: 8080},
		{name: "ipv4 max port", addr: "127.0.0.1:65535", want: 65535},
		{name: "domain", addr: "example.com:443", want: 443},
		{name: "port overflow", addr: "127.0.0.1:70000", wantErr: true},
		{name: "port above uint16", addr: "127.0.0.1:65536", wantErr: true},
		{name: "negative port", addr: "127.0.0.1:-1", wantErr: true},
		{name: "not a number", addr: "127.0.0.1:http", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conn := &captureConn{}
			err := writeTrojanUnixHandshake(conn, "tcp", tc.addr)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("writeTrojanUnixHandshake(%q) = nil, want error", tc.addr)
				}
				if conn.buf.Len() != 0 {
					t.Fatalf("wrote %d bytes for rejected address %q", conn.buf.Len(), tc.addr)
				}
				return
			}
			if err != nil {
				t.Fatalf("writeTrojanUnixHandshake(%q) error = %v", tc.addr, err)
			}

			b := conn.buf.Bytes()
			if len(b) < 2 {
				t.Fatalf("handshake too short: %d bytes", len(b))
			}
			got := binary.BigEndian.Uint16(b[len(b)-2:])
			if got != tc.want {
				t.Fatalf("port = %d, want %d", got, tc.want)
			}
		})
	}
}
