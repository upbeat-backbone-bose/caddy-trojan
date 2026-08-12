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
// Go releases. Replaying plaintext above the TLS layer is data-preserving and
// does not depend on stdlib internals.
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
// underlying type supports half-close (e.g. *net.TCPConn).
//
// *tls.Conn is not a CloseWriter (the TLS record layer cannot signal a
// half-close over a single direction), so the wrapper reports "not supported"
// for TLS conns. No current rawconn consumer on the listener path uses TCP
// half-close, so this is a documentation note rather than a functional gap.
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
// *tls.Conn, which caddy's http2listener uses to recover the TLS state. For
// non-TLS connections an empty state is returned.
func (c *conn) ConnectionState() tls.ConnectionState {
	if tc, ok := c.Conn.(*tls.Conn); ok {
		return tc.ConnectionState()
	}
	return tls.ConnectionState{}
}
