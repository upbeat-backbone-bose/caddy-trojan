package rawconn

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
)

// RewindConn returns a connection that replays the already-read bytes
// (plaintext, for a *tls.Conn) before continuing to read from conn.
//
// The rewind is done with a wrapper rather than by reaching into the
// unexported internals of crypto/tls.Conn, whose layout is not stable across
// Go releases (the "input" field is a value type since Go 1.25 and is not
// addressable via its old pointer form). The wrapper replays plaintext above
// the TLS layer, which is data-preserving and does not depend on stdlib
// internals.
func RewindConn(conn net.Conn, read []byte) net.Conn {
	return NewConn(conn, read)
}

type conn struct {
	net.Conn
	Reader bytes.Reader
}

func NewConn(nc net.Conn, buf []byte) net.Conn {
	c := &conn{
		Conn: nc,
	}
	c.Reader.Reset(buf)
	return c
}

func (c *conn) Read(b []byte) (int, error) {
	if c.Reader.Size() == 0 {
		return c.Conn.Read(b)
	}
	n, err := c.Reader.Read(b)
	if errors.Is(err, io.EOF) {
		c.Reader.Reset([]byte{})
		return n, nil
	}
	return n, err
}

// CloseWrite implements net.CloseWriter on the wrapped conn when the
// underlying type supports half-close (e.g. *net.TCPConn) or exposes
// a CloseWrite() method. The wrapped conn is reachable via Conn, so
// the cast covers raw TCP, in-process pipes, and any future type that
// opts in.
//
// Limitation: *tls.Conn is not a CloseWriter. crypto/tls has never
// exposed half-close on its Conn type (the TLS record layer cannot
// signal a TLS-level half-close over a single direction), so this
// method returns "not supported" when the wrapper is asked to half-
// close a TLS conn. Callers that need TLS half-close must work around
// it (e.g. by shutting the read side of the underlying TCP conn
// directly). HTTP/2 listeners — which are the only consumer of
// rawconn on the listener path — never use TCP half-close, so this
// limitation is a documentation note rather than a functional gap.
func (c *conn) CloseWrite() error {
	if cc, ok := c.Conn.(*net.TCPConn); ok {
		return cc.CloseWrite()
	}
	if cw, ok := c.Conn.(interface {
		CloseWrite() error
	}); ok {
		return cw.CloseWrite()
	}
	return errors.New("not supported")
}

// ConnectionState forwards the TLS state when the wrapped connection is a
// *tls.Conn. caddy's http2listener checks the exported connectionStater
// interface and wraps the conn so its ConnContext can recover the TLS state;
// for non-TLS wrapped connections an empty (zero-version) state is returned,
// which is harmless.
func (c *conn) ConnectionState() tls.ConnectionState {
	if tc, ok := c.Conn.(*tls.Conn); ok {
		return tc.ConnectionState()
	}
	return tls.ConnectionState{}
}
