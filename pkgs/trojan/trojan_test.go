package trojan

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type mockDialer struct{}

func (mockDialer) Dial(string, string) (net.Conn, error) {
	return nil, nil // must not be reached by the invalid-CRLF tests
}

func (mockDialer) ListenPacket(string, string) (net.PacketConn, error) {
	return net.ListenPacket("udp", "127.0.0.1:0")
}

// pipeDialer returns a fixed connection from Dial, simulating the upstream
// endpoint of a CONNECT tunnel.
type pipeDialer struct {
	conn net.Conn
}

func (d *pipeDialer) Dial(string, string) (net.Conn, error) {
	return d.conn, nil
}

func (d *pipeDialer) ListenPacket(string, string) (net.PacketConn, error) {
	return nil, errors.New("not supported")
}

// TestHandleWithDialerRejectsInvalidCRLF verifies the TCP header CRLF
// terminator is checked before any dial happens.
func TestHandleWithDialerRejectsInvalidCRLF(t *testing.T) {
	// [CMD=1][ATYP=1 IPv4][127.0.0.1][port 8080][CRLF=0x00 0x00]
	stream := []byte{0x01, 0x01, 127, 0, 0, 1, 0x1f, 0x90, 0x00, 0x00}
	_, _, err := HandleWithDialer(bytes.NewReader(stream), io.Discard, mockDialer{})
	if err == nil {
		t.Fatal("HandleWithDialer accepted invalid CRLF terminator")
	}
	if !strings.Contains(err.Error(), "CRLF") {
		t.Errorf("HandleWithDialer error = %v, want CRLF-related error", err)
	}
}

// TestHandleTCPNoDeadlockOnHalfClose is a regression test for the F1
// deadlock: when the upstream closes first (half-close) and the client stays
// silent, HandleWithDialer must return instead of blocking on errCh forever.
func TestHandleTCPNoDeadlockOnHalfClose(t *testing.T) {
	// Real loopback TCP pairs: net.Pipe does not support CloseWrite, which is
	// needed to simulate the upstream half-close.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	// srv is the connection handed to HandleWithDialer; the client peer stays
	// silent after sending the header.
	srv, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	tln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tln.Close()
	target, err := net.Dial("tcp", tln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	tpeer, err := tln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer tpeer.Close()

	d := &pipeDialer{conn: target}
	done := make(chan error, 1)
	go func() {
		_, _, err := HandleWithDialer(srv, srv, d)
		done <- err
	}()

	// CONNECT to 127.0.0.1:80 with a valid CRLF terminator.
	header := []byte{0x01, 0x01, 127, 0, 0, 1, 0x1f, 0x90, 0x0d, 0x0a}
	if _, err := client.Write(header); err != nil {
		t.Fatalf("write header: %v", err)
	}

	// Let HandleTCP start, then half-close the upstream side: tpeer.CloseWrite
	// makes target.Read return EOF while the client stays silent.
	time.Sleep(100 * time.Millisecond)
	if err := tpeer.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("tpeer CloseWrite: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Logf("HandleWithDialer returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("HandleWithDialer deadlocked after upstream half-close with silent client")
	}
}

// TestHandleUDPNoDeadlockOnIdle is a regression test for the F2 deadlock: an
// idle client that never sends a UDP packet must not leave HandleUDP blocked
// on errCh after the socket deadline expires.
func TestHandleUDPNoDeadlockOnIdle(t *testing.T) {
	client, _ := net.Pipe()
	defer client.Close()

	done := make(chan error, 1)
	go func() {
		_, _, err := HandleUDP(client, client, 500*time.Millisecond, mockDialer{})
		done <- err
	}()

	// The client sends nothing; the write side times out after 500ms and must
	// wake the blocked reader instead of waiting on errCh forever.
	select {
	case err := <-done:
		// F2 follow-up: the writer loop's deadline timeout, surfaced
		// as the writer goroutine's os.ErrDeadlineExceeded after the
		// reader defer's rc.SetReadDeadline-now call, must be coalesced
		// to nil by HandleUDP's main-goroutine cleanup branch. Otherwise
		// every normal UDP session close logs a spurious 'i/o timeout'.
		if err != nil {
			t.Errorf("HandleUDP returned %v, want nil on idle timeout", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("HandleUDP deadlocked on idle client")
	}
}

// TestHandleUDPCleanExitOnClientClose verifies that a client closing
// the read side of the conn produces a nil error from HandleUDP: the
// reader's io.EOF is coalesced in the reader defer, the writer loop
// then sees a deadline timeout from its blocked ReadFrom, and the
// main goroutine's cleanup branch folds that timeout back to nil.
// Pre-F2-followup, the writer-side deadline would propagate up as
// "i/o timeout" and every normal UDP teardown would log a spurious
// error.
func TestHandleUDPCleanExitOnClientClose(t *testing.T) {
	client, _ := net.Pipe()
	defer client.Close()

	done := make(chan error, 1)
	go func() {
		_, _, err := HandleUDP(client, client, 5*time.Second, mockDialer{})
		done <- err
	}()

	// Give HandleUDP time to start; the writer loop sets a 5s read
	// deadline on the UDP socket. Then close the client side and
	// expect HandleUDP to exit within the deadline.
	time.Sleep(100 * time.Millisecond)
	client.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("HandleUDP returned %v, want nil on client close", err)
		}
	case <-time.After(7 * time.Second):
		t.Fatal("HandleUDP did not return within 7s after client close")
	}
}

// TestHandleUDPRejectsInvalidCRLF verifies the UDP packet CRLF terminator is
// checked and reported through the error channel.
func TestHandleUDPRejectsInvalidCRLF(t *testing.T) {
	// [ATYP=1 IPv4][127.0.0.1][port 8080][Len=0x0004][CRLF=0x00 0x00][data]
	stream := []byte{
		0x01, 127, 0, 0, 1, 0x1f, 0x90,
		0x00, 0x04, 0x00, 0x00,
		'd', 'a', 't', 'a',
	}
	_, _, err := HandleUDP(bytes.NewReader(stream), io.Discard, time.Second, mockDialer{})
	if err == nil {
		t.Fatal("HandleUDP accepted invalid CRLF terminator")
	}
	if !strings.Contains(err.Error(), "CRLF") {
		t.Errorf("HandleUDP error = %v, want CRLF-related error", err)
	}
	if !errors.Is(err, errInvalidCRLF) {
		t.Errorf("HandleUDP error = %v, want errInvalidCRLF sentinel", err)
	}
}

// failingAddr is a net.Addr that returns a fixed string; used only so
// HandleTCP's Dial path has a syntactically valid target.
type failingAddr struct{}

func (failingAddr) Network() string { return "tcp" }
func (failingAddr) String() string  { return "127.0.0.1:0" }

// dialReturningPipe is a Dialer whose Dial returns the half of a net.Pipe
// already set up by the test, so HandleTCP's Dial succeeds and we exercise
// the post-dial memory.Alloc path.
type dialReturningPipe struct{ conn net.Conn }

func (d *dialReturningPipe) Dial(string, string) (net.Conn, error) { return d.conn, nil }
func (d *dialReturningPipe) ListenPacket(string, string) (net.PacketConn, error) {
	return nil, errors.New("not supported")
}

// withAllocErr temporarily sets the package-level allocByteErr to the given
// error and registers a cleanup that restores it. It is the test hook for
// the B3 (mmap failure propagation) fix: production leaves allocByteErr
// nil, so HandleTCP/HandleUDP call the real memory.Alloc.
func withAllocErr(t *testing.T, err error) {
	t.Helper()
	orig := allocByteErr
	t.Cleanup(func() { allocByteErr = orig })
	allocByteErr = err
}

// TestHandleTCPAllocFailureReturnsError verifies that HandleTCP returns an
// error instead of panicking when memory.Alloc fails (e.g. mmap() under
// memory pressure in the `malloc_syscall` build). Pre-fix the goroutines
// contain `panic(err)`; a real mmap failure would crash the whole process.
// Post-fix the failure surfaces as a (0, 0, err) return without a panic.
//
// This test runs without t.Parallel() because it mutates package-level
// state (allocByteErr); parallel runs would race on that variable.
func TestHandleTCPAllocFailureReturnsError(t *testing.T) {
	client, srv := net.Pipe()
	defer client.Close()
	defer srv.Close()

	withAllocErr(t, errors.New("simulated alloc failure"))

	d := &dialReturningPipe{conn: srv}
	done := make(chan struct{})
	var nr, nw int64
	var err error
	go func() {
		defer close(done)
		defer func() {
			if r := recover(); r != nil {
				err = errors.New("HandleTCP panicked instead of returning an error")
			}
		}()
		nr, nw, err = HandleTCP(client, client, failingAddr{}, d)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("HandleTCP did not return within 2s on alloc failure; possible deadlock or panic")
	}

	if err == nil {
		t.Fatalf("HandleTCP returned (nr=%d, nw=%d, err=nil) on alloc failure; want non-nil error", nr, nw)
	}
	if nr != 0 || nw != 0 {
		t.Errorf("HandleTCP on alloc failure returned nr=%d nw=%d; want 0/0", nr, nw)
	}
}

// TestHandleUDPAllocFailureReturnsError is the UDP counterpart of the TCP
// alloc-failure test: HandleUDP must return (0, 0, err) without panicking
// if memory.Alloc fails. mockDialer in this package implements ListenPacket
// by binding a real UDP socket; we reuse it so Alloc is reached.
func TestHandleUDPAllocFailureReturnsError(t *testing.T) {
	client, _ := net.Pipe()
	defer client.Close()

	withAllocErr(t, errors.New("simulated alloc failure"))

	d := mockDialer{}
	done := make(chan struct{})
	var nr, nw int64
	var err error
	go func() {
		defer close(done)
		defer func() {
			if r := recover(); r != nil {
				err = errors.New("HandleUDP panicked instead of returning an error")
			}
		}()
		nr, nw, err = HandleUDP(client, client, 200*time.Millisecond, d)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("HandleUDP did not return within 2s on alloc failure; possible deadlock or panic")
	}

	if err == nil {
		t.Fatalf("HandleUDP returned (nr=%d, nw=%d, err=nil) on alloc failure; want non-nil error", nr, nw)
	}
	if nr != 0 || nw != 0 {
		t.Errorf("HandleUDP on alloc failure returned nr=%d nw=%d; want 0/0", nr, nw)
	}
}

// TestHandleTCPNormalPathUnaffected sanity-checks that under the default
// (real) allocator, HandleTCP can still complete a small round trip —
// guarding against the B3 fix accidentally breaking the happy path.
//
// This test is intentionally not Parallel() because it shares package state
// with the alloc-failure test, but a t.Cleanup guarantees allocByteErr is
// restored to nil before any other test runs.
func TestHandleTCPNormalPathUnaffected(t *testing.T) {
	withAllocErr(t, nil) // explicit: real allocator

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	upstream, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		c, _ := ln.Accept()
		_ = c.Close()
	}()

	d := &dialReturningPipe{conn: upstream}
	done := make(chan error, 1)
	go func() {
		_, _, err := HandleTCP(upstream, upstream, failingAddr{}, d)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Logf("HandleTCP returned (expected EOF or similar): %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("HandleTCP deadlocked under default allocator")
	}
}

// TestHandleTCPHalfCloseDrainsClientData is a regression test for the
// half-close handling in HandleTCP: when the remote side closes its write
// direction (TCP half-close, e.g. an SSH server sending FIN), data the
// client still has in flight must be delivered, not truncated. The fix
// replaced an immediate wakeReader deadline on this path with a grace
// window (wakeGrace); pre-fix, the immediate read deadline killed the
// client→remote direction and dropped the final packets, causing spurious
// disconnects on long-lived tunnels.
func TestHandleTCPHalfCloseDrainsClientData(t *testing.T) {
	// Tunnel client-side pair: tcTest (test holds) <-> tcTunnel (passed to
	// HandleTCP as r and w).
	lnT, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lnT.Close()
	tcTunnel, err := net.Dial("tcp", lnT.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer tcTunnel.Close()
	tcTest, err := lnT.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer tcTest.Close()

	// Remote (rc) pair, standing in for the SSH server: rcTunnel is what
	// HandleTCP dials, rcTest is the "server" the test controls.
	lnR, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lnR.Close()
	rcTunnel, err := net.Dial("tcp", lnR.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer rcTunnel.Close()
	rcTest, err := lnR.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer rcTest.Close()

	d := &dialReturningPipe{conn: rcTunnel}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = HandleTCP(tcTunnel, tcTunnel, failingAddr{}, d)
	}()

	// SSH server half-closes its write direction.
	if err := rcTest.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("rc CloseWrite: %v", err)
	}

	// Give HandleTCP a moment to observe the remote EOF and enter the
	// grace-window path.
	time.Sleep(100 * time.Millisecond)

	// The client still has a final packet in flight; it must arrive.
	if _, err := tcTest.Write([]byte("final-packet")); err != nil {
		t.Fatalf("client Write after half-close: %v", err)
	}

	got := make([]byte, len("final-packet"))
	if _, err := io.ReadFull(rcTest, got); err != nil {
		t.Fatalf("rc did not receive post-FIN data (truncated by immediate wake): %v", err)
	}
	if string(got) != "final-packet" {
		t.Errorf("rc received %q, want %q", got, "final-packet")
	}

	// Unwind: close both sides so HandleTCP returns.
	tcTest.Close()
	rcTest.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("HandleTCP did not return after both sides closed")
	}
}
