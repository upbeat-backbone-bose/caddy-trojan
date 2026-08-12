package trojan

import (
	"errors"
	"io"
	"net"
	"os"
	"time"

	pkgwebsocket "github.com/imgk/caddy-trojan/pkgs/websocket"
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

// trySetReadDeadline invokes w's SetReadDeadline(t) if w
// implements wakeableConn, and returns whether the call was
// made. Callers use the return value to decide whether the
// half-close grace window is honored for this writer: false
// means the writer is opaque (e.g. an *handler.FlushWriter
// over HTTP/1/2/3 CONNECT) and the caller cannot bound a
// silent peer's blocking read.
func trySetReadDeadline(w io.Writer, t time.Time) bool {
	if c, ok := w.(wakeableConn); ok {
		_ = c.SetReadDeadline(t)
		return true
	}
	return false
}

// trySetImmediateReadDeadline releases any goroutine currently
// blocked in a Read on the underlying connection that rw
// eventually wraps. The argument is typed as any (not io.Writer)
// because the call site that needs to release a reader-side
// block passes an io.Reader (the writer-loop hard-error break
// path in HandleUDP needs to release the reader goroutine
// blocked in r.Read; passing io.Reader through an io.Writer-
// typed helper would force an unsafe cast or a confusing
// interface{} at the call site). The dispatch remains a
// wakeableConn interface assertion at the helper boundary. The
// deadline is set to time.Now() (not the zero time) because the
// wake_reader_test fake (and any real wrapper that gates on
// "non-zero deadline ⇒ release") keys off the non-zero branch.
func trySetImmediateReadDeadline(rw any) bool {
	c, ok := rw.(wakeableConn)
	if !ok {
		return false
	}
	_ = c.SetReadDeadline(time.Now())
	return true
}

// wakeReader forces a pending Read on w's underlying connection to
// return immediately. It is the safety net used right before waiting
// on errCh in HandleTCP/HandleUDP: a silent peer would otherwise keep
// the reader goroutine blocked after the writer goroutine has already
// finished, and the defer'd Close in the caller would never run. For
// writers that do not implement wakeableConn, the call is a silent
// no-op (matching the pre-abstraction behavior for non-net.Conn
// writers on the HTTP/1/2/3 CONNECT path).
func wakeReader(w io.Writer) {
	_ = trySetImmediateReadDeadline(w)
}

// isTimeoutError reports whether err is a clean timeout that we should
// treat as a non-error exit: it matches the stdlib sentinel directly
// and also any wrapper that implements net.Error with Timeout()==true
// (e.g. gorilla/websocket's hideTempErr-wrapped *netError). Both
// shapes mean "we asked the underlying conn to give up; the peer
// didn't fail, the conn just hit a deadline", so neither should
// propagate as a tunnel-level error. Used by HandleUDP's reader
// defer and main goroutine cleanup paths to coalesce the reader's
// own exit (rc.SetReadDeadline(now)) and the writer's resulting
// ReadFrom timeout back into a single nil.
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

// Compile-time guards that the three types the wake protocol
// depends on still satisfy the wakeableConn interface.
// *net.TCPConn and *net.UDPConn implement SetReadDeadline
// via their embedded net.Conn; *pkgwebsocket.Conn embeds
// *gorilla.Conn, which implements SetReadDeadline, and
// method-set promotion gives the wrapper the same signature.
// Without these guards, a future stdlib rename of
// net.Conn.SetReadDeadline, a gorilla refactor that drops
// SetReadDeadline, or an unexported rename like
// setReadDeadline would silently break the wake protocol at
// runtime: the type assertion in trySetReadDeadline would
// return false, the helper would no-op, and the half-close
// grace window would silently fail. The compile-time guard
// turns that into a build failure at the dependency boundary.
var (
	_ wakeableConn = (*net.TCPConn)(nil)
	_ wakeableConn = (*net.UDPConn)(nil)
	_ wakeableConn = (*pkgwebsocket.Conn)(nil)
)
