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
		if err != nil {
			t.Logf("HandleUDP returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("HandleUDP deadlocked on idle client")
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
