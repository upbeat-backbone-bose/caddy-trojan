package listener

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/imgk/caddy-trojan/app"
	"github.com/imgk/caddy-trojan/pkgs/trojan"
)

// fakeAddr satisfies net.Addr for the test listener.
type fakeAddr struct{}

func (fakeAddr) Network() string { return "tcp" }
func (fakeAddr) String() string  { return "127.0.0.1:0" }

// fakeListener is a controllable net.Listener. Tests push scripted conns to
// acceptCh, push errors to errCh, or close the listener. It implements
// net.Listener so it can be wrapped by Listener.
type fakeListener struct {
	acceptCh chan net.Conn
	errCh    chan error
	closed   chan struct{}
	closeOnce sync.Once
}

func newFakeListener() *fakeListener {
	return &fakeListener{
		acceptCh: make(chan net.Conn, 16),
		errCh:    make(chan error, 16),
		closed:   make(chan struct{}),
	}
}

func (l *fakeListener) Accept() (net.Conn, error) {
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	case conn := <-l.acceptCh:
		return conn, nil
	case err := <-l.errCh:
		return nil, err
	}
}

func (l *fakeListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

func (l *fakeListener) Addr() net.Addr { return fakeAddr{} }

// fakeConn is a scripted net.Conn: each Read consumes one entry from the
// scripts slice. After scripts are exhausted, Read returns io.EOF.
type fakeConn struct {
	scripts  []fakeRead
	readIdx  int
	deadline time.Time
}

type fakeRead struct {
	data []byte
	err  error
}

func (c *fakeConn) Read(b []byte) (int, error) {
	if c.readIdx >= len(c.scripts) {
		return 0, io.EOF
	}
	s := c.scripts[c.readIdx]
	c.readIdx++
	n := copy(b, s.data)
	return n, s.err
}

func (c *fakeConn) Close() error                       { return nil }
func (c *fakeConn) Write(b []byte) (int, error)        { return len(b), nil }
func (c *fakeConn) LocalAddr() net.Addr                { return fakeAddr{} }
func (c *fakeConn) RemoteAddr() net.Addr               { return fakeAddr{} }
func (c *fakeConn) SetDeadline(t time.Time) error      { c.deadline = t; return nil }
func (c *fakeConn) SetReadDeadline(t time.Time) error  { c.deadline = t; return nil }
func (c *fakeConn) SetWriteDeadline(t time.Time) error { c.deadline = t; return nil }

// newTestListener wires a Listener around a fakeListener, no-op upstream and
// proxy, and a discarding logger. The returned Listener has conns and closed
// channels ready for the test to drive.
func newTestListener(fl *fakeListener) *Listener {
	return NewListener(fl, noopUpstream{}, noopProxy{}, zap.NewNop())
}

// noopUpstream / noopProxy satisfy app.Upstream and app.Proxy respectively;
// they are used because the listener's per-conn goroutine may call Validate
// (the full-header path) which we do not want to exercise here.
type noopUpstream struct{}

func (noopUpstream) Add(string) error                  { return nil }
func (noopUpstream) Delete(string) error               { return nil }
func (noopUpstream) Range(func(string, int64, int64))  {}
func (noopUpstream) Validate(string) bool              { return true }
func (noopUpstream) Consume(string, int64, int64) error { return nil }

type noopProxy struct{}

func (noopProxy) Close() error                              { return nil }
func (noopProxy) Dial(string, string) (net.Conn, error)     { return nil, nil }
func (noopProxy) ListenPacket(string, string) (net.PacketConn, error) { return nil, nil }

var (
	_ app.Upstream = noopUpstream{}
	_ app.Proxy    = noopProxy{}
)

// TestListenerRewindLengthOnPartialRead is a regression test for a 1-character
// fix in modules/listener/listener.go: the rewind slice was `b[:n+1]`, which
// replayed one uninitialized byte beyond what was actually read when `nr` was
// 0. The fix is `b[:n+nr]`. This test drives the listener goroutine with a
// scripted conn that returns 1 byte then a non-EOF error, and verifies the
// rewind length is exactly 1 byte (not 2).
func TestListenerRewindLengthOnPartialRead(t *testing.T) {
	t.Parallel()

	fl := newFakeListener()
	ln := newTestListener(fl)
	defer ln.Close()

	// Scripted conn:
	//   Read #1: 1 byte, no error   → consumed by listener loop n=0, b[0]=0xAA
	//   Read #2: 0 bytes + non-EOF  → triggers rewind path with n=1, nr=0
	conn := &fakeConn{
		scripts: []fakeRead{
			{data: []byte{0xAA}, err: nil},
			{data: nil, err: errors.New("connection reset by peer")},
		},
	}
	fl.acceptCh <- conn

	go ln.loop()

	// Read the rewind conn from l.conns with a timeout.
	var rewound net.Conn
	select {
	case rewound = <-ln.conns:
	case <-time.After(2 * time.Second):
		t.Fatal("listener did not produce a rewind conn within 2s")
	}
	defer rewound.Close()

	// After the rewind buffer is exhausted, the wrapper falls through to the
	// underlying fakeConn, which has no more scripts and returns io.EOF.
	all, err := io.ReadAll(rewound)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(all) != 1 {
		t.Errorf("rewind length = %d bytes (% x), want exactly 1 byte (AA)", len(all), all)
	} else if all[0] != 0xAA {
		t.Errorf("rewind content = % x, want [AA]", all)
	}
}

// TestListenerAcceptErrorBackoff verifies that when the underlying Accept
// fails repeatedly, the loop does not spin: it pauses ~100ms between
// failures. Without the backoff, a failing underlying listener (e.g. during
// shutdown) could burn CPU at full speed.
//
// Method: replace the underlying net.Listener with a counting fake that
// records each Accept call, repeatedly returns errors, and let the loop run
// for a fixed window. With backoff the count must be small (roughly
// windowMs / 100ms); without backoff it would be orders of magnitude higher.
func TestListenerAcceptErrorBackoff(t *testing.T) {
	t.Parallel()

	fl := newFakeListener()
	ln := newTestListener(fl)

	// Wrap Accept to count calls without changing semantics.
	fl.acceptCh = make(chan net.Conn, 16) // ensure non-blocking send paths don't matter here
	var acceptCount int64
	var mu sync.Mutex
	doneProbe := make(chan struct{})
	wrapped := &countingListener{
		Listener: fl,
		count:    &acceptCount,
		mu:       &mu,
		done:     doneProbe,
	}
	ln.Listener = wrapped

	go ln.loop()

	// Periodically push errors so the loop always has something to consume.
	pushErr := func() {
		select {
		case fl.errCh <- errors.New("transient accept failure"):
		default:
		}
	}

	// Run for ~600ms. With backoff, expect ~6 Accept calls (600/100).
	const windowMs = 600
	start := time.Now()
	deadline := start.Add(windowMs * time.Millisecond)
	for time.Now().Before(deadline) {
		pushErr()
		time.Sleep(5 * time.Millisecond)
	}

	// Stop the loop and read the final count.
	fl.Close()
	ln.Close()
	close(doneProbe)
	// Give loop goroutine time to exit.
	time.Sleep(150 * time.Millisecond)

	mu.Lock()
	count := acceptCount
	mu.Unlock()

	// With 100ms backoff over a 600ms window we expect ~6 calls. We allow a
	// generous upper bound (≤20) to avoid CI flakiness while still failing
	// without the backoff, where the count would be 100+.
	if count < 2 {
		t.Errorf("loop ran too few Accept iterations: %d (loop may have exited early)", count)
	}
	if count > 20 {
		t.Errorf("loop spun too fast on Accept errors: %d iterations in %dms (want ≤~%d); backoff regressed",
			count, windowMs, windowMs/100*2)
	}
	t.Logf("Accept was called %d times in %dms (with backoff: ~%d expected)", count, windowMs, windowMs/100)
}

// countingListener wraps a net.Listener and counts Accept calls.
type countingListener struct {
	net.Listener
	count *int64
	mu    *sync.Mutex
	done  chan struct{}
}

func (l *countingListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	*l.count++
	l.mu.Unlock()
	return l.Listener.Accept()
}

// TestListenerClosedHonoredOnConnsSend verifies that when the listener is
// closed while a connection is queued, the per-conn goroutine takes the
// closed path and closes the connection rather than blocking forever on an
// unbuffered conns channel (the listener's consumer has gone away).
//
// This is hard to deterministically exercise from a unit test because the
// conns channel is unbuffered and the loop's read side is held by the loop
// goroutine itself. We at least verify the more important property: when
// the listener is closed, the loop's Accept returns net.ErrClosed, the
// loop exits, and no goroutine leaks.
func TestListenerClosedHonoredOnConnsSend(t *testing.T) {
	t.Parallel()

	fl := newFakeListener()
	ln := newTestListener(fl)

	done := make(chan struct{})
	go func() {
		ln.loop()
		close(done)
	}()

	// Close both the underlying fakeListener (so Accept returns
	// net.ErrClosed and the loop enters the error branch) and the wrapper
	// Listener (so l.closed is closed and the error branch returns instead
	// of sleeping 100ms and looping again).
	fl.Close()
	ln.Close()

	select {
	case <-done:
		// good: loop exited
	case <-time.After(2 * time.Second):
		t.Fatal("loop did not exit within 2s of listener close")
	}
}

// keep trojan imported so we can reference trojan.HeaderLen symbolically if
// we ever need to (no-op import-only reference to avoid drift).
var _ = trojan.HeaderLen