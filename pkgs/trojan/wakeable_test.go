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
// integration test for the wakeableConn abstraction. It uses a real
// gorilla WebSocket server and client, wraps the server-side conn in
// pkgs/websocket.Conn, and runs HandleTCP with that wrapper as the
// writer. When the simulated upstream half-closes, the client stays
// silent: HandleTCP's wakeGrace must release the blocked reader on
// the underlying TCP conn through the wrapper within ~2s. Without
// the cross-package interface hook, the wrapper's SetReadDeadline
// would never be called and HandleTCP would block on errCh until the
// OS TCP keepalive (~hours by default) closed the socket.
//
// The test catches the F1 regression shape: an unexported wakeableConn
// method (e.g. setReadDeadline) can only be implemented by types in
// the trojan package itself, so the type assertion in
// trySetReadDeadline would silently fail for *pkgswebsocket.Conn and
// the grace window would not apply on the WS path. With an exported
// method (SetReadDeadline), *pkgswebsocket.Conn satisfies the
// interface via method-set promotion from its embedded *gorilla.Conn.
func TestWakeableConnDispatchesToWebSocketWrapper(t *testing.T) {
	t.Parallel()

	// Simulated upstream. The dial side (upstreamTarget) is what the
	// test half-closes to drive the HandleTCP EOF path; the accept
	// side (upstreamPeer) is what HandleTCP reads from as rc.
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

	// handleDone is closed when HandleWithDialer returns. The handler
	// goroutine is the only writer; closing it signals completion.
	handleDone := make(chan struct{})

	mux := http.NewServeMux()
	mux.HandleFunc("/tunnel", func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		wrapper := pkgwebsocket.NewConn(c)
		defer wrapper.Close()

		// Dialer hands the already-accepted upstreamPeer back to
		// HandleTCP; HandleTCP dials once at startup, gets
		// upstreamPeer, and then reads/writes through it as rc.
		d := &pipeDialer{conn: upstreamPeer}

		HandleWithDialer(wrapper, wrapper, d)
		close(handleDone)
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

	// Send a valid trojan CONNECT header to 127.0.0.1:80.
	header := []byte{0x01, 0x01, 127, 0, 0, 1, 0x1f, 0x90, 0x0d, 0x0a}
	if err := clientConn.WriteMessage(websocket.BinaryMessage, header); err != nil {
		t.Fatalf("write header: %v", err)
	}

	// Give HandleTCP time to start, then half-close the upstream. The
	// critical detail: we CloseWrite the DIAL side (upstreamTarget),
	// not the ACCEPT side (upstreamPeer). TCP half-close only signals
	// EOF to the opposite side; closing our own write side leaves our
	// own Read direction untouched. The dial side is what upstreamPeer
	// is reading from, so the test must CloseWrite the dial side.
	time.Sleep(200 * time.Millisecond)
	if err := upstreamTarget.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("upstreamTarget CloseWrite: %v", err)
	}

	// wakeGrace is 2s; allow up to 5s for scheduling noise. With the
	// exported SetReadDeadline and the gorilla hideTempErr-aware
	// reader goroutine, HandleWithDialer must return within this
	// budget.
	select {
	case <-handleDone:
		// HandleWithDialer returned within the budget. The
		// wakeableConn dispatch reached the WS wrapper and the
		// reader goroutine correctly classified the gorilla-wrapped
		// timeout as a clean exit.
	case <-time.After(5 * time.Second):
		t.Fatal("HandleWithDialer did not return within 5s after upstream half-close with silent client. " +
			"This indicates either (a) the wakeableConn method is unexported so the " +
			"cross-package WebSocket hook cannot satisfy the interface, or (b) the reader " +
			"goroutine does not recognize gorilla's hideTempErr-wrapped timeout as a clean exit.")
	}
}

// TestWakeableConnClientToUpstreamFlow exercises the main goroutine's
// 'rc -> wrapper' write path through a real gorilla WebSocket. The
// upstream pushes some data and then half-closes; HandleTCP's main
// goroutine reads from rc and writes to the WS wrapper. The test
// asserts HandleWithDialer returns within (wakeGrace + margin) once
// the reader goroutine has seen the upstream's EOF and the grace
// path has had a chance to release any blocking reads on the wrapper
// side. This is the inverse of
// TestWakeableConnDispatchesToWebSocketWrapper: there, the
// upstream half-closes and the client stays silent; here, the
// upstream pushes data and the client can drain it normally. The
// test catches a regression where the main goroutine's
// errors.Is(err, os.ErrDeadlineExceeded) checks in the
// 'rc.SetReadDeadline(time.Minute)' drain loop (line 161) might be
// triggered by a wrapper that wraps the rc read path — they are
// not, today, but the test pins the no-deadlock invariant on this
// direction as well.
func TestWakeableConnClientToUpstreamFlow(t *testing.T) {
	t.Parallel()

	// Upstream side, same shape as the half-close test.
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

	// Push a small payload upstream and then half-close. HandleTCP
	// will read these bytes from rc and write them through the WS
	// wrapper to the client; once the upstream half-closes, rc.Read
	// returns io.EOF and the main goroutine's 'err == nil' branch
	// takes the grace path.
	if _, err := upstreamTarget.Write([]byte("hello, world\n")); err != nil {
		t.Fatal(err)
	}
	if err := upstreamTarget.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}

	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	handleDone := make(chan struct{})

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
		HandleWithDialer(wrapper, wrapper, d)
		close(handleDone)
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

	select {
	case <-handleDone:
		// HandleWithDialer returned. The main goroutine saw the
		// upstream's EOF on rc, the grace path was honored, and
		// the reader goroutine's release propagated cleanly.
	case <-time.After(5 * time.Second):
		t.Fatal("HandleWithDialer did not return within 5s after upstream write+half-close. " +
			"This indicates the 'rc -> wrapper' write direction may have a deadline handling gap.")
	}
}
