package trojan

import (
	"errors"
	"io"
	"net"
	"os"
	"time"

	pkgwebsocket "github.com/imgk/caddy-trojan/pkgs/websocket"
)

// wakeableConn lets HandleTCP/HandleUDP release a reader goroutine blocked in
// Read via a deadline change, regardless of how many wrappers sit between the
// writer and the underlying net.Conn. The method must be exported so types in
// other packages (notably pkgs/websocket.Conn) can satisfy the interface.
type wakeableConn interface {
	SetReadDeadline(time.Time) error
}

// trySetReadDeadline sets w's read deadline if w implements wakeableConn and
// reports whether the call was made. false means the writer is opaque and the
// caller cannot bound a silent peer's blocking read.
func trySetReadDeadline(w io.Writer, t time.Time) bool {
	if c, ok := w.(wakeableConn); ok {
		_ = c.SetReadDeadline(t)
		return true
	}
	return false
}

// trySetImmediateReadDeadline unblocks any pending Read on the connection that
// rw wraps. rw is typed any because the HandleUDP hard-error path passes an
// io.Reader here.
func trySetImmediateReadDeadline(rw any) bool {
	c, ok := rw.(wakeableConn)
	if !ok {
		return false
	}
	_ = c.SetReadDeadline(time.Now())
	return true
}

// wakeReader unblocks a pending Read on w's connection. It is the safety net
// used before waiting on errCh in HandleTCP/HandleUDP so a silent peer cannot
// keep the reader goroutine blocked forever. It is a no-op for writers that do
// not implement wakeableConn.
func wakeReader(w io.Writer) {
	_ = trySetImmediateReadDeadline(w)
}

// isTimeoutError reports whether err is a clean timeout: either the stdlib
// sentinel or a net.Error with Timeout()==true (e.g. gorilla/websocket's
// hideTempErr-wrapped *netError). Such errors mean the conn hit a deadline we
// set ourselves and should not propagate as a tunnel-level error.
func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return true
	}
	return false
}

// Compile-time guards that the types the wake protocol depends on still satisfy
// wakeableConn, so a future interface drift becomes a build failure instead of
// a silent runtime no-op.
var (
	_ wakeableConn = (*net.TCPConn)(nil)
	_ wakeableConn = (*net.UDPConn)(nil)
	_ wakeableConn = (*pkgwebsocket.Conn)(nil)
)
