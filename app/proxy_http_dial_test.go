package app

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

// trackingProxy is a test-only caddy module that returns a countingConn on
// Dial so tests can assert HttpProxy.Dial called Close() on the underlying
// connection. The module is registered in init() below; tests load it as
// HttpProxy's pre_proxy and read closeCount back via the *trackingProxy
// stored in h.proxy after Provision.
type trackingProxy struct {
	Server     string `json:"server"`
	closed     atomic.Int32
	connClosed atomic.Int32 // conns that closed via our wrapper
}

func init() {
	caddy.RegisterModule(&trackingProxy{})
}

func (*trackingProxy) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "trojan.proxy.tracking",
		New: func() caddy.Module { return new(trackingProxy) },
	}
}

func (p *trackingProxy) Provision(_ caddy.Context) error { return nil }

func (p *trackingProxy) Dial(network, _ string) (net.Conn, error) {
	c, err := net.Dial(network, p.Server)
	if err != nil {
		return nil, err
	}
	return &countingConn{Conn: c, parent: p}, nil
}

func (p *trackingProxy) ListenPacket(_, _ string) (net.PacketConn, error) {
	return nil, errors.New("not supported")
}

func (p *trackingProxy) Close() error { return nil }

type countingConn struct {
	net.Conn
	parent *trackingProxy
}

func (c *countingConn) Close() error {
	c.parent.closed.Add(1)
	return c.Conn.Close()
}

// newHttpProxyWithTracking provisions an HttpProxy that uses trackingProxy
// as its pre_proxy dialer. Returns the HttpProxy and the *trackingProxy so
// tests can read closeCount after Dial returns.
func newHttpProxyWithTracking(t *testing.T, serverAddr string) (*HttpProxy, *trackingProxy) {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	// Embed the server address in the ProxyRaw JSON so the loaded
	// trackingProxy unmarshals it into its Server field. The pre-built tp
	// here is only used for sanity checks; the actual proxy that HttpProxy
	// stores in p.proxy is a fresh instance created by caddy.LoadModule.
	tp := &trackingProxy{Server: serverAddr}
	raw := []byte(`{"proxy":"tracking","server":"` + serverAddr + `"}`)
	h := &HttpProxy{
		Server:   serverAddr,
		ProxyRaw: json.RawMessage(raw),
	}
	if err := h.Provision(ctx); err != nil {
		t.Fatalf("HttpProxy.Provision: %v", err)
	}
	return h, tp
}

// fakeProxy is a tiny TCP server used only by HttpProxy.Dial tests. Each
// accepted connection is handed to onConn, which writes whatever response
// the test wants.
type fakeProxy struct {
	listener net.Listener
	onConn   func(c net.Conn)
}

func newFakeProxy(t *testing.T, onConn func(c net.Conn)) *fakeProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	fp := &fakeProxy{listener: ln, onConn: onConn}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go onConn(c)
		}
	}()
	return fp
}

func (fp *fakeProxy) addr() string { return fp.listener.Addr().String() }
func (fp *fakeProxy) close()       { fp.listener.Close() }

// newHttpProxyForTest provisions an HttpProxy pointing at the fake upstream
// directly (no pre_proxy chain, so NoProxy.Dial is used).
func newHttpProxyForTest(t *testing.T, serverAddr string) *HttpProxy {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	p := &HttpProxy{Server: serverAddr}
	if err := p.Provision(ctx); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	return p
}

// readExact reads exactly len(buf) bytes from c within timeout, or fails.
func readExact(c net.Conn, buf []byte, timeout time.Duration) error {
	type result struct {
		err error
	}
	done := make(chan result, 1)
	go func() {
		read := 0
		for read < len(buf) {
			n, err := c.Read(buf[read:])
			read += n
			if err != nil {
				done <- result{err}
				return
			}
		}
		done <- result{nil}
	}()
	select {
	case r := <-done:
		return r.err
	case <-time.After(timeout):
		return errors.New("read timeout")
	}
}

// TestHttpProxyDialClosesConnOnNonOKStatus covers the "server status code
// error" branch in HttpProxy.Dial: when the upstream returns anything but
// 200, the proxy conn must be closed (previously leaked).
func TestHttpProxyDialClosesConnOnNonOKStatus(t *testing.T) {
	t.Parallel()

	fp := newFakeProxy(t, func(c net.Conn) {
		// Drain the CONNECT request line + headers.
		buf := make([]byte, 4096)
		_, _ = c.Read(buf)
		// Reply with a non-200 status.
		_, _ = c.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n"))
		// Hold the conn open so the test can read whatever the client writes.
		_, _ = c.Read(make([]byte, 1))
	})
	defer fp.close()

	h, _ := newHttpProxyWithTracking(t, fp.addr())

	conn, err := h.Dial("tcp", "example.com:443")
	if err == nil {
		if conn != nil {
			conn.Close()
		}
		t.Fatal("Dial returned no error; want server status code error")
	}
	if conn != nil {
		t.Fatal("Dial returned non-nil conn on error; want nil")
	}

	tp := h.proxy.(*trackingProxy)
	if got := tp.closed.Load(); got != 1 {
		t.Errorf("trackingProxy.closed = %d, want 1 (HttpProxy.Dial must Close conn on non-200 path)", got)
	}
}

// TestHttpProxyDialClosesConnOnWriteError covers the "write request error"
// branch in HttpProxy.Dial: when req.WriteProxy fails, the dialer must
// explicitly close the conn. A fake proxy that reads the CONNECT request then
// closes immediately makes WriteProxy fail with a broken pipe; a
// trackingProxy counts Close calls to assert the fix.
func TestHttpProxyDialClosesConnOnWriteError(t *testing.T) {
	t.Parallel()

	// Use SetLinger=0 so Close sends RST, guaranteeing WriteProxy fails
	// rather than succeeding (kernel buffer would absorb FIN without RST).
	fp := newFakeProxy(t, func(c net.Conn) {
		// Wait for the client to start sending the CONNECT request before
		// RSTing. On Linux an immediate linger-0 close can reset the
		// connection during connect() itself (net.Dial returns ECONNRESET),
		// so the post-dial error path would never be exercised. Reading one
		// byte guarantees the client's connect completed and WriteProxy
		// began; the subsequent RST then fails either a remaining write
		// (EPIPE → write-error path) or the response read (ECONNRESET →
		// read-error path), both of which must close the conn.
		buf := make([]byte, 1)
		_, _ = c.Read(buf)
		if tcp, ok := c.(*net.TCPConn); ok {
			_ = tcp.SetLinger(0)
		}
		c.Close()
	})
	defer fp.close()

	h, _ := newHttpProxyWithTracking(t, fp.addr())

	conn, err := h.Dial("tcp", "example.com:443")
	if err == nil {
		if conn != nil {
			conn.Close()
		}
		t.Fatal("Dial returned no error; want write request error")
	}
	if conn != nil {
		t.Fatal("Dial returned non-nil conn on error; want nil")
	}

	tp := h.proxy.(*trackingProxy)
	if got := tp.closed.Load(); got != 1 {
		t.Errorf("trackingProxy.closed = %d, want 1 (HttpProxy.Dial must Close conn on write-error path); Dial err = %v", got, err)
	}
}

// TestHttpProxyDialClosesConnOnReadError covers the "read response error"
// branch in HttpProxy.Dial: when the upstream never sends a valid HTTP
// response, the dialer must close the conn.
func TestHttpProxyDialClosesConnOnReadError(t *testing.T) {
	t.Parallel()

	fp := newFakeProxy(t, func(c net.Conn) {
		// Drain the CONNECT request, then send garbage that isn't a valid
		// HTTP response so http.ReadResponse surfaces an error.
		buf := make([]byte, 4096)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte("not-a-valid-http-response\r\n\r\n"))
		c.Close()
	})
	defer fp.close()

	h, _ := newHttpProxyWithTracking(t, fp.addr())

	conn, err := h.Dial("tcp", "example.com:443")
	if err == nil {
		if conn != nil {
			conn.Close()
		}
		t.Fatal("Dial returned no error; want read response error")
	}
	if conn != nil {
		t.Fatal("Dial returned non-nil conn on error; want nil")
	}

	tp := h.proxy.(*trackingProxy)
	if got := tp.closed.Load(); got != 1 {
		t.Errorf("trackingProxy.closed = %d, want 1 (HttpProxy.Dial must Close conn on read-error path)", got)
	}
}

// TestHttpProxyDialReplaysBufferedBytes is a regression test for the bufio
// replay fix in HttpProxy.Dial: when bufio.NewReader(conn) reads past the
// HTTP response head into tunneled payload (because the proxy responded
// 200 OK and started sending tunnel data in the same TCP segment), those
// buffered bytes must be replayed to the caller. Without the replay, the
// first tunneled packet would be silently dropped.
func TestHttpProxyDialReplaysBufferedBytes(t *testing.T) {
	t.Parallel()

	const payload = "tunneled-bytes-immediately-after-200-ok"

	fp := newFakeProxy(t, func(c net.Conn) {
		// Drain the CONNECT request, then send 200 OK + payload in a single
		// Write so they arrive in one TCP segment and bufio (4 KiB default
		// buffer) reads past the response head into the payload.
		buf := make([]byte, 4096)
		_, _ = c.Read(buf)
		resp := "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n" + payload
		_, _ = c.Write([]byte(resp))
		// Hold the conn open until the test is done.
		_, _ = c.Read(make([]byte, 1))
	})
	defer fp.close()

	h := newHttpProxyForTest(t, fp.addr())

	conn, err := h.Dial("tcp", "example.com:443")
	if err != nil {
		t.Fatalf("Dial returned error: %v", err)
	}
	defer conn.Close()

	// The returned conn must expose the payload on its first Read. rawconn
	// wraps the real conn and replays the buffered bytes before falling
	// through to the underlying Read.
	got := make([]byte, len(payload))
	if err := readExact(conn, got, 2*time.Second); err != nil {
		t.Fatalf("read exact from Dial conn: %v", err)
	}
	if string(got) != payload {
		t.Errorf("replayed bytes = %q, want %q", got, payload)
	}
}

// keep the http import used (for completeness in the test file)
var _ = http.MethodConnect
