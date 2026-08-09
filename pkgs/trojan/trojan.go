package trojan

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/imgk/caddy-trojan/pkgs/socks"
	"github.com/imgk/caddy-trojan/pkgs/x"
)

const HeaderLen = 56

// errInvalidCRLF is returned when the protocol CRLF terminator is missing or
// malformed.
var errInvalidCRLF = errors.New("invalid CRLF terminator")

// allocByteErr, when non-nil, is returned by HandleTCP/HandleUDP instead of
// performing real memory.Alloc. Production leaves it nil; tests set it to
// simulate an mmap failure under the `malloc_syscall` build tag without
// actually exhausting memory. The B3 fix wires the check into HandleTCP
// and HandleUDP; without the check, a panic inside a goroutine would crash
// the whole process.
var allocByteErr error

// wakeReader sets an immediate read deadline on w's underlying connection so
// that a goroutine blocked reading from the same connection is released. It is
// used right before waiting on errCh so that a silent peer cannot deadlock
// HandleTCP/HandleUDP forever (each half-close would otherwise leave the other
// direction blocked and the deferred Close never runs). It applies to the
// raw TCP / WebSocket / UDP tunnel paths, where the reader and writer share
// the same net.Conn; the HTTP/2 and HTTP/3 CONNECT paths pass an http.Body /
// http.Flusher instead and are governed by the HTTP server's own timeouts.
func wakeReader(w io.Writer) {
	if c, ok := w.(net.Conn); ok {
		_ = c.SetReadDeadline(time.Now())
	}
}

const (
	CmdConnect   = 1
	CmdAssociate = 3
)

func GenKey(s string, key []byte) {
	hash := sha256.Sum224(x.StringToByteSlice(s))
	hex.Encode(key, hash[:])
}

type Dialer interface {
	Dial(string, string) (net.Conn, error)
	ListenPacket(string, string) (net.PacketConn, error)
}

func HandleWithDialer(r io.Reader, w io.Writer, d Dialer) (int64, int64, error) {
	b := [1 + socks.MaxAddrLen + 2]byte{}

	// read command
	if _, err := io.ReadFull(r, b[:1]); err != nil {
		return 0, 0, fmt.Errorf("read command error: %w", err)
	}
	if b[0] != CmdConnect && b[0] != CmdAssociate {
		return 0, 0, errors.New("command error")
	}

	// read address
	addr, err := socks.ReadAddrBuffer(r, b[3:])
	if err != nil {
		return 0, 0, fmt.Errorf("read addr error: %w", err)
	}

	// read 0x0d, 0x0a
	if _, err := io.ReadFull(r, b[1:3]); err != nil {
		return 0, 0, fmt.Errorf("read 0x0d 0x0a error: %w", err)
	}
	if b[1] != 0x0d || b[2] != 0x0a {
		return 0, 0, errInvalidCRLF
	}

	switch b[0] {
	case CmdConnect:
		nr, nw, err := HandleTCP(r, w, addr, d)
		if err != nil {
			return nr, nw, fmt.Errorf("handle tcp error: %w", err)
		}
		return nr, nw, nil
	case CmdAssociate:
		nr, nw, err := HandleUDP(r, w, time.Minute*10, d)
		if err != nil {
			return nr, nw, fmt.Errorf("handle udp error: %w", err)
		}
		return nr, nw, nil
	default:
	}
	return 0, 0, errors.New("command error")
}
