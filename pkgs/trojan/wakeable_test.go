package trojan

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	pkgwebsocket "github.com/imgk/caddy-trojan/pkgs/websocket"
)

// TestWakeableConnDispatchesToWebSocketWrapper is the cross-package
// integration test for the wakeableConn abstraction on the HandleTCP
// path. It uses a real loopback TCP pair (not net.Pipe, which has
// no half-close support and no SetReadDeadline propagation) and
// half-closes the dial side. HandleTCP's writer loop sees io.EOF
// on rc.Read, takes the grace path, trySetReadDeadline sets a
// 2-second read deadline on the wrapper, the wrapper forwards
// the deadline to the underlying TCP conn, the reader goroutine's
// blocked wrapper.Read returns within the wakeGrace 2s budget, the
// defer folds the timeout to nil, the main goroutine's
// isTimeoutError check coalesces both back to nil. Asserts both the
// timing (within wakeGrace + 1s margin) AND the error value
// (HandleWithDialer must return nil, not 'i/o timeout'). The
// error capture is via the gotErr channel so a future regression
// that folds the timeout incorrectly is caught by t.Errorf,
// not silently by t.Logf.
func TestWakeableConnDispatchesToWebSocketWrapper(t *testing.T) {
	t.Parallel()

	tln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tln.Close()

	upstreamTarget, err := net.Dial("tcp", tln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer upstreamTarget.Close()
	upstreamPeer, err := tln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer upstreamPeer.Close()

	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	gotErr := make(chan error, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/tunnel", func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		wrapper := pkgwebsocket.NewConn(c)
		defer wrapper.Close()

		d := &pipeDialer{conn: upstreamPeer}
		_, _, err = HandleWithDialer(wrapper, wrapper, d)
		gotErr <- err
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	u.Scheme = "ws"
	u.Path = "/tunnel"

	dialer := *websocket.DefaultDialer
	dialer.HandshakeTimeout = 5 * time.Second
	clientConn, _, err := dialer.Dial(u.String(), nil)
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	defer clientConn.Close()

	header := []byte{0x01, 0x01, 127, 0, 0, 1, 0x1f, 0x90, 0x0d, 0x0a}
	if err := clientConn.WriteMessage(websocket.BinaryMessage, header); err != nil {
		t.Fatalf("write header: %v", err)
	}

	time.Sleep(200 * time.Millisecond)
	if err := upstreamTarget.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("upstreamTarget CloseWrite: %v", err)
	}

	start := time.Now()
	select {
	case e := <-gotErr:
		elapsed := time.Since(start)
		if elapsed > 3*time.Second {
			t.Errorf("HandleWithDialer returned in %v, "+
				"expected < 3s (wakeGrace + scheduling margin). "+
				"A slow return suggests the clean-shutdown chain is degraded.", elapsed)
		}
		if e != nil {
			t.Errorf("HandleWithDialer returned %v, want nil for a clean WS teardown. "+
				"A non-nil return means the reader-defer or main-goroutine cleanup did "+
				"not fold the writer-side deadline to nil (F2-followup regression).", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("HandleWithDialer did not return within 5s after upstream half-close. " +
			"This indicates either (a) the wakeableConn method is unexported so " +
			"the cross-package WebSocket hook cannot satisfy the interface, or " +
			"(b) the reader goroutine does not recognize gorilla's hideTempErr-" +
			"wrapped timeout as a clean exit.")
	}
}

// TestWakeableConnClientToUpstreamFlow is the inverse-direction
// integration test: upstream pushes data and then half-closes;
// HandleTCP's main goroutine reads from rc and writes to the WS
// wrapper. Asserts both the timing (within wakeGrace + margin)
// AND that HandleWithDialer returns nil.
func TestWakeableConnClientToUpstreamFlow(t *testing.T) {
	t.Parallel()

	tln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tln.Close()
	upstreamTarget, err := net.Dial("tcp", tln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer upstreamTarget.Close()
	upstreamPeer, err := tln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer upstreamPeer.Close()

	if _, err := upstreamTarget.Write([]byte("hello, world\n")); err != nil {
		t.Fatal(err)
	}
	if err := upstreamTarget.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}

	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	gotErr := make(chan error, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/tunnel", func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		wrapper := pkgwebsocket.NewConn(c)
		defer wrapper.Close()

		d := &pipeDialer{conn: upstreamPeer}
		_, _, err = HandleWithDialer(wrapper, wrapper, d)
		gotErr <- err
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	u.Scheme = "ws"
	u.Path = "/tunnel"

	clientConn, _, err := (*websocket.DefaultDialer).Dial(u.String(), nil)
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	defer clientConn.Close()

	header := []byte{0x01, 0x01, 127, 0, 0, 1, 0x1f, 0x90, 0x0d, 0x0a}
	if err := clientConn.WriteMessage(websocket.BinaryMessage, header); err != nil {
		t.Fatalf("write header: %v", err)
	}

	start := time.Now()
	select {
	case e := <-gotErr:
		elapsed := time.Since(start)
		if elapsed > 3*time.Second {
			t.Errorf("HandleWithDialer returned in %v, "+
				"expected < 3s (wakeGrace + scheduling margin).", elapsed)
		}
		if e != nil {
			t.Errorf("HandleWithDialer returned %v, want nil for a clean WS teardown. "+
				"A non-nil return means the cleanup did not fold the writer-side "+
				"deadline to nil.", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("HandleWithDialer did not return within 5s after upstream write+half-close.")
	}
}

// TestHandleUDPOverWebSocketWrapperCleanExit exercises the
// HandleUDP path with a real gorilla WebSocket wrapper for both
// r and w. The client writes the CmdAssociate header and
// immediately closes; the server-side wrapper's NextReader
// returns io.EOF (the client stream EOFs), the reader goroutine's
// defer folds the EOF to nil, the writer loop's blocked ReadFrom
// then sees a deadline timeout via rc.SetReadDeadline(now), and
// the main goroutine's isTimeoutError check coalesces both back
// to nil. Asserts BOTH the timing (within WS close round-trip +
// margin) AND that HandleWithDialer returns nil (F2-followup
// invariant).
func TestHandleUDPOverWebSocketWrapperCleanExit(t *testing.T) {
	t.Parallel()

	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	gotErr := make(chan error, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/tunnel", func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		wrapper := pkgwebsocket.NewConn(c)
		defer wrapper.Close()

		_, _, e := HandleWithDialer(wrapper, wrapper, mockDialerUDP{})
		gotErr <- e
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	u.Scheme = "ws"
	u.Path = "/tunnel"

	clientConn, _, err := (*websocket.DefaultDialer).Dial(u.String(), nil)
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}

	// CmdAssociate (0x03) header for the UDP ASSOCIATE command.
	header := []byte{0x03, 0x01, 127, 0, 0, 1, 0x1f, 0x90, 0x0d, 0x0a}
	if err := clientConn.WriteMessage(websocket.BinaryMessage, header); err != nil {
		t.Fatalf("write header: %v", err)
	}
	clientConn.Close()

	start := time.Now()
	select {
	case e := <-gotErr:
		elapsed := time.Since(start)
		if elapsed > 1*time.Second {
			t.Errorf("HandleWithDialer took %v, expected < 1s for a "+
				"clean WS-over-UDP teardown. A slow return suggests "+
				"the clean-shutdown chain is degraded.", elapsed)
		}
		if e != nil {
			t.Errorf("HandleWithDialer returned %v, want nil for a "+
				"clean WS-over-UDP teardown. A non-nil return means the "+
				"reader-defer or main-goroutine cleanup did not fold "+
				"the writer-side deadline to nil (F2-followup regression).", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("HandleWithDialer did not return within 5s for WS-over-UDP.")
	}
}

// mockDialerUDP is a Dialer that returns a real UDP socket from
// ListenPacket so HandleUDP's writer loop has a valid PacketConn
// to wait on. Dial is unused.
type mockDialerUDP struct{}

func (mockDialerUDP) Dial(string, string) (net.Conn, error) {
	return nil, nil
}

func (mockDialerUDP) ListenPacket(string, string) (net.PacketConn, error) {
	return net.ListenPacket("udp", "127.0.0.1:0")
}
