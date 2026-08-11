package trojan

import (
	"io"
	"time"
)

// wakeableConn is the minimal abstraction over an io.Writer that lets
// HandleTCP/HandleUDP release a blocked reader goroutine from a deadline
// change, regardless of how many layers of wrapping sit between the
// writer and the underlying net.Conn.
//
// The method name MUST be exported (SetReadDeadline) so implementations
// in other packages (notably pkgs/websocket.Conn) can satisfy the
// interface via method-set promotion. An unexported method name
// (e.g. setReadDeadline) is package-private in Go: only types defined
// inside package trojan can satisfy it, and any cross-package
// implementation would be silently rejected by the type assertion in
// trySetReadDeadline. The audit caught exactly this shape: a
// wakeableConn with an unexported method satisfied only by types in
// the trojan package itself, with the cross-package WebSocket hook
// dead code.
//
// The signature intentionally matches net.Conn.SetReadDeadline, so any
// net.Conn (raw TCP, Unix, in-process pipes) satisfies the interface
// for free via method-set promotion — no extra wrapper is needed for
// the raw path. Wrappers that need to forward the deadline to a
// different underlying object only need to expose SetReadDeadline in
// their own method set; gorilla's *websocket.Conn already does so, so
// pkgs/websocket.Conn satisfies the interface through its embedded
// *gorilla.Conn.
//
// Pre-abstraction code used 'if c, ok := w.(net.Conn); ok' to detect
// the case. That check failed for any wrapper that did not expose
// net.Conn directly: *websocket.Conn (pkgs/websocket) embeds
// *gorilla.Conn and therefore was not a net.Conn, even though it has
// access to the underlying conn via UnderlyingConn().
type wakeableConn interface {
	SetReadDeadline(time.Time) error
}

// trySetReadDeadline invokes w's SetReadDeadline(t) if w implements
// wakeableConn, and returns whether the call was made. Callers use the
// return value to decide whether the half-close grace window is honored
// for this writer: false means the writer is opaque (e.g. an
// http.ResponseWriter over HTTP/1 CONNECT) and the caller cannot bound
// a silent peer's blocking read.
func trySetReadDeadline(w io.Writer, t time.Time) bool {
	if c, ok := w.(wakeableConn); ok {
		_ = c.SetReadDeadline(t)
		return true
	}
	return false
}

// trySetImmediateReadDeadline is the wakeReader path: it asks w to
// release any goroutine currently blocked in a Read on the same
// underlying connection, by setting the read deadline to "now". The
// deadline is set to time.Now() (not the zero time) because the
// wake_reader_test fake (and any real wrapper that gates on
// "non-zero deadline ⇒ release") keys off the non-zero branch.
func trySetImmediateReadDeadline(w io.Writer) bool {
	if c, ok := w.(wakeableConn); ok {
		_ = c.SetReadDeadline(time.Now())
		return true
	}
	return false
}

// wakeReader forces a pending Read on w's underlying connection to
// return immediately. It is the safety net used right before waiting
// on errCh in HandleTCP/HandleUDP: a silent peer would otherwise keep
// the reader goroutine blocked after the writer goroutine has already
// finished, and the defer'd Close in the caller would never run. For
// writers that do not implement wakeableConn, the call is a silent
// no-op (matching the pre-abstraction behavior for non-net.Conn
// writers on the HTTP/2/3 CONNECT path).
func wakeReader(w io.Writer) {
	_ = trySetImmediateReadDeadline(w)
}
