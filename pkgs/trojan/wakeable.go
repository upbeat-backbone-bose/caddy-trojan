package trojan

import (
	"io"
	"net"
	"time"
)

// wakeableConn is the minimal abstraction over an io.Writer that lets
// HandleTCP/HandleUDP release a blocked reader goroutine from a deadline
// change, regardless of how many layers of wrapping sit between the
// writer and the underlying net.Conn.
//
// Pre-abstraction code used 'if c, ok := w.(net.Conn); ok' to detect the
// case and call c.SetReadDeadline(t). The check failed for any wrapper
// that did not expose net.Conn directly:
//   - *websocket.Conn (pkgs/websocket) wraps gorilla's *websocket.Conn and
//     does not implement net.Conn, even though it has access to the
//     underlying net.Conn via UnderlyingConn().
//   - *handler.FlushWriter (modules/handler) wraps an http.ResponseWriter
//     for HTTP/1 CONNECT; it never has a net.Conn to forward the deadline
//     to.
//
// Any writer that wants to participate in the half-close grace window
// (see HandleTCP's wakeGrace) and the wakeReader protocol implements
// wakeableConn. Callers use trySetReadDeadline rather than a direct type
// assertion so that missing implementations fall back to a no-op without
// panicking.
type wakeableConn interface {
	setReadDeadline(time.Time) error
}

// trySetReadDeadline invokes w's setReadDeadline(t) if w implements
// wakeableConn, and falls back to a direct net.Conn SetReadDeadline if
// w is a raw net.Conn. Returns whether the call landed. Callers use
// the return value to decide whether the half-close grace window is
// honored for this writer; false means the writer is opaque (e.g. an
// http.ResponseWriter over HTTP/1 CONNECT) and the caller cannot bound
// a silent peer's blocking read.
func trySetReadDeadline(w io.Writer, t time.Time) bool {
	if c, ok := w.(wakeableConn); ok {
		_ = c.setReadDeadline(t)
		return true
	}
	if c, ok := w.(net.Conn); ok {
		_ = c.SetReadDeadline(t)
		return true
	}
	return false
}

// trySetImmediateReadDeadline is the wakeReader path: it asks w to
// release any goroutine currently blocked in a Read on the same
// underlying connection, by setting the read deadline to "now". The
// previous direct-net.Conn-only behavior is preserved via the fallback
// below; the new wakeableConn dispatch handles the WebSocket and other
// wrapped-conn cases. The deadline is set to time.Now() (not the zero
// time) because wrapper implementations and the test fake both key off
// the "non-zero ⇒ release" branch.
func trySetImmediateReadDeadline(w io.Writer) bool {
	if c, ok := w.(wakeableConn); ok {
		_ = c.setReadDeadline(time.Now())
		return true
	}
	if c, ok := w.(net.Conn); ok {
		_ = c.SetReadDeadline(time.Now())
		return true
	}
	return false
}

// wakeReader forces a pending Read on w's underlying connection to
// return immediately. It is the safety net used right before waiting on
// errCh in HandleTCP/HandleUDP: a silent peer would otherwise keep the
// reader goroutine blocked after the writer goroutine has already
// finished, and the defer'd Close in the caller would never run. The
// fall-through to a direct net.Conn assertion keeps historical
// behavior for non-wrapper net.Conn writers.
func wakeReader(w io.Writer) {
	_ = trySetImmediateReadDeadline(w)
}
