package trojan

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// wakeNetConn is a minimal net.Conn whose SetReadDeadline records the
// deadline and signals a channel so a blocked Read can return. It only
// implements the methods wakeReader touches.
type wakeNetConn struct {
	deadline atomic.Pointer[time.Time]
	armed    atomic.Bool
	read     atomic.Int32 // counts Read calls
	mu       sync.Mutex
	done     chan struct{}
}

func newWakeNetConn() *wakeNetConn {
	return &wakeNetConn{done: make(chan struct{})}
}

func (c *wakeNetConn) SetReadDeadline(t time.Time) error {
	c.deadline.Store(&t)
	if !t.IsZero() {
		c.armed.Store(true)
		select {
		case <-c.done:
		default:
			close(c.done)
		}
	}
	return nil
}

func (c *wakeNetConn) Read(b []byte) (int, error) {
	c.read.Add(1)
	if !c.armed.Load() {
		<-c.done
	}
	return 0, osErrDeadlineExceeded
}

func (c *wakeNetConn) Write(b []byte) (int, error)        { return len(b), nil }
func (c *wakeNetConn) Close() error                       { return nil }
func (c *wakeNetConn) LocalAddr() net.Addr                { return nil }
func (c *wakeNetConn) RemoteAddr() net.Addr               { return nil }
func (c *wakeNetConn) SetDeadline(t time.Time) error      { return c.SetReadDeadline(t) }
func (c *wakeNetConn) SetWriteDeadline(_ time.Time) error { return nil }

func (c *wakeNetConn) snapshot() (time.Time, bool) {
	p := c.deadline.Load()
	if p == nil {
		return time.Time{}, false
	}
	return *p, true
}

// osErrDeadlineExceeded matches the timeout error net.Conn returns when a
// Read fires after the read deadline has passed. We re-export os's
// sentinel here for clarity.
var osErrDeadlineExceeded = timeoutError{}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// TestWakeReaderSetsImmediateDeadlineOnNetConn verifies that wakeReader
// applies an immediate read deadline (≈ now) to a net.Conn. The fix is in
// HandleTCP/HandleUDP's half-close recovery: when one direction finishes,
// wakeReader releases any goroutine blocked reading on the same conn so
// the other goroutine can exit instead of deadlocking on errCh forever.
func TestWakeReaderSetsImmediateDeadlineOnNetConn(t *testing.T) {
	t.Parallel()

	fc := newWakeNetConn()
	before := time.Now()
	wakeReader(fc)
	after := time.Now()

	d, ok := fc.snapshot()
	if !ok {
		t.Fatal("SetReadDeadline was not called")
	}
	if d.Before(before) || d.After(after) {
		t.Errorf("deadline = %v, want in [%v, %v] (immediate, not future)", d, before, after)
	}
}

// TestWakeReaderIsNoopOnNonConn verifies that wakeReader does not panic
// when given an io.Writer that is not a net.Conn. This protects the
// HTTP/2 / HTTP/3 path in HandleWithDialer where w is an http.Body /
// FlushWriter rather than a net.Conn.
func TestWakeReaderIsNoopOnNonConn(t *testing.T) {
	t.Parallel()

	wakeReader(io.Discard) // must not panic
}

// TestWakeReaderReleasesBlockedReader verifies the end-to-end behavior the
// fix is supposed to deliver: a goroutine blocked on Read is released when
// wakeReader sets a deadline. The fake conn's Read blocks until
// SetReadDeadline is called.
func TestWakeReaderReleasesBlockedReader(t *testing.T) {
	t.Parallel()

	fc := newWakeNetConn()

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		_, err := fc.Read(buf)
		done <- err
	}()

	// Let the goroutine start blocking on Read.
	time.Sleep(10 * time.Millisecond)

	wakeReader(fc)

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Read returned nil error after wakeReader; want timeout error")
		}
		if !isTimeoutErr(err) {
			t.Errorf("Read after wakeReader = %v, want a timeout error", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Read did not return within 1s; wakeReader did not release the blocked reader")
	}
}

// isTimeoutErr returns true if err implements net.Error and Timeout() is true.
func isTimeoutErr(err error) bool {
	type timeoutErr interface{ Timeout() bool }
	te, ok := err.(timeoutErr)
	return ok && te.Timeout()
}
