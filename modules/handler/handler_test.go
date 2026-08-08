package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

func TestCheckOrigin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		origin string // empty means no Origin header
		host   string
		allow  []string
		want   bool
	}{
		{"no origin (non-browser client)", "", "example.com", nil, true},
		{"same origin", "https://example.com", "example.com", nil, true},
		{"same origin with port", "https://example.com:443", "example.com:443", nil, true},
		{"cross origin", "https://evil.com", "example.com", nil, false},
		{"cross origin with port", "https://evil.com:8080", "example.com", nil, false},
		{"cross origin blocked despite no whitelist match", "https://cdn.example.com", "example.com", []string{"cdn.other.com"}, false},
		{"whitelisted origin", "https://cdn.example.com", "example.com", []string{"cdn.example.com"}, true},
		{"whitelisted origin case-insensitive host", "https://CDN.EXAMPLE.COM", "example.com", []string{"cdn.example.com"}, true},
		{"malformed origin", "://bad", "example.com", nil, false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := &Handler{OriginAllow: tt.allow}
			r := httptest.NewRequest(http.MethodGet, "https://"+tt.host+"/", nil)
			if tt.origin != "" {
				r.Header.Set("Origin", tt.origin)
			}
			if got := m.checkOrigin(r); got != tt.want {
				t.Errorf("checkOrigin(origin=%q, host=%q, allow=%v) = %v, want %v",
					tt.origin, tt.host, tt.allow, got, tt.want)
			}
		})
	}
}

// TestHandlerWebSocketRejectsInvalidCRLF verifies the CRLF terminator check in
// the WebSocket path: a client that upgrades and sends 56 key bytes followed
// by a malformed terminator must be rejected without panicking — and the
// check runs before Validate, so even an unprovisioned handler (nil upstream)
// is safe.
func TestHandlerWebSocketRejectsInvalidCRLF(t *testing.T) {
	t.Parallel()

	h := &Handler{
		WebSocket:     true,
		headerTimeout: 2 * time.Second,
		logger:        zap.NewNop(),
	}
	h.upgrader.CheckOrigin = h.checkOrigin

	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r, nil)
		close(done)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("upgrade failed: %v", err)
	}
	defer conn.Close()

	// 56 key bytes + invalid CRLF (0x00 0x00).
	header := append(make([]byte, 56), 0x00, 0x00)
	if err := conn.WriteMessage(websocket.BinaryMessage, header); err != nil {
		t.Fatalf("write header: %v", err)
	}

	select {
	case <-done:
		// good: the malformed terminator was rejected before Validate
		// (upstream is nil in this test).
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not return after invalid CRLF; check placement of the check")
	}
}

// TestHandlerWebSocketHeaderTimeoutFires is a regression test for the
// headerTimeout fix in ServeHTTP: after a WebSocket upgrade, the handler
// must bound how long it will wait for the trojan header. Without the
// deadline, an unauthenticated peer could connect, upgrade, and then stall
// forever, holding the handler goroutine and a file descriptor.
//
// The test stands up a real HTTP server backed by ServeHTTP, dials it with
// gorilla's DefaultDialer (completing the upgrade), then does not write
// anything. The handler is configured with headerTimeout=100ms (via the
// unexported field, since the const is 10s for production) and must
// return within ~1s of the upgrade; we detect completion via a `done`
// channel closed by the wrapper handler.
func TestHandlerWebSocketHeaderTimeoutFires(t *testing.T) {
	t.Parallel()

	h := &Handler{
		WebSocket:     true,
		headerTimeout: 100 * time.Millisecond,
		logger:        zap.NewNop(),
	}
	h.upgrader.CheckOrigin = h.checkOrigin

	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r, nil)
		close(done)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"

	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("upgrade failed: %v", err)
	}
	defer conn.Close()

	// Stalling is the point: do not WriteMessage. The handler must time out
	// and return on its own.
	select {
	case <-done:
		// handler returned; the timeout fired before the client closed.
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not return within 2s of upgrade; headerTimeout did not fire")
	}
}
