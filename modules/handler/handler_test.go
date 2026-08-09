package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
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

// countingUpstream records every call to Validate / Consume so tests can
// detect fast-fail behavior under DoS-style flood (rate-limit).
type countingUpstream struct {
	validateCalls atomic.Int64
	consumeCalls  atomic.Int64
	fail          bool // Validate returns this; Consume is a no-op
}

func (c *countingUpstream) Validate(_ string) bool {
	c.validateCalls.Add(1)
	return !c.fail
}
func (c *countingUpstream) Consume(_ string, _, _ int64) error {
	c.consumeCalls.Add(1)
	return nil
}
func (c *countingUpstream) Add(_ string) error                 { return nil }
func (c *countingUpstream) Delete(_ string) error              { return nil }
func (c *countingUpstream) Range(_ func(string, int64, int64)) {}

// TestHandlerConnectRateLimitsAfterRepeatedFailures verifies that the HTTP/2/3
// CONNECT path rate-limits unauthenticated floods: after a small number of
// failed Validate calls from the same source, subsequent requests from that
// source must fast-fail (skip the Validate call and its 250 ms constant-time
// delay plus storage I/O). The test uses unexported fields to dial the
// threshold and window down to a tiny value (1 failure ⇒ blocked) so the
// test runs in milliseconds, not the production second-scale window.
func TestHandlerConnectRateLimitsAfterRepeatedFailures(t *testing.T) {
	t.Parallel()

	up := &countingUpstream{fail: true}

	h := &Handler{
		Connect: true,
		upstream: up,
		logger:  zap.NewNop(),
		failThreshold:           1,
		failWindow:              1 * time.Hour, // long enough to stay tripped
		failCooldown:            1 * time.Hour,
	}

	// Helper: build a CONNECT request that simulates HTTP/2 by setting
	// ProtoMajor=2. The handler accepts a non-empty body; we just need the
	// auth header to be present (and wrong, since up.fail=true).
	badAuth := "Basic " + strings.Repeat("0", 56)
	newReq := func() *http.Request {
		r := httptest.NewRequest(http.MethodConnect, "https://example.com:443/", nil)
		r.ProtoMajor = 2
		r.ProtoMinor = 0
		r.Header.Set("Proxy-Authorization", badAuth)
		return r
	}

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		// next.ServeHTTP is the fall-through path. When rate-limit blocks, the
		// handler should return next.ServeHTTP without having touched up.
		return nil
	})

	// First failure must reach the upstream (no rate limit applied yet).
	if err := h.ServeHTTP(httptest.NewRecorder(), newReq(), next); err != nil {
		t.Fatalf("1st ServeHTTP error: %v", err)
	}
	if got := up.validateCalls.Load(); got != 1 {
		t.Fatalf("after 1st request validateCalls = %d, want 1", got)
	}

	// Second request from same source must fast-fail (NOT call Validate),
	// short-circuit before storage I/O. We use httptest.NewRequest which
	// yields a deterministic RemoteAddr; both requests share the same addr.
	if err := h.ServeHTTP(httptest.NewRecorder(), newReq(), next); err != nil {
		t.Fatalf("2nd ServeHTTP error: %v", err)
	}
	if got := up.validateCalls.Load(); got != 1 {
		t.Fatalf("after 2nd request validateCalls = %d, want still 1 (fast-fail)", got)
	}
}

// TestHandlerConnectDoesNotRateLimitValidKey verifies the rate-limiter only
// trips on failure: a request that would otherwise Validate-success must
// keep being processed. This guards against a degenerate rate-limit
// implementation that triggers on any traffic, not just on failures.
func TestHandlerConnectDoesNotRateLimitValidKey(t *testing.T) {
	t.Parallel()

	up := &countingUpstream{fail: false} // always succeed
	h := &Handler{
		Connect: true,
		upstream: up,
		logger:  zap.NewNop(),
		failThreshold: 1,
		failWindow:    1 * time.Hour,
		failCooldown:  1 * time.Hour,
	}

	goodAuth := "Basic " + strings.Repeat("a", 56)
	newReq := func() *http.Request {
		r := httptest.NewRequest(http.MethodConnect, "https://example.com:443/", nil)
		r.ProtoMajor = 2
		r.Header.Set("Proxy-Authorization", goodAuth)
		return r
	}

	next := caddyhttp.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) error { return nil })

	for i := 1; i <= 3; i++ {
		rec := httptest.NewRecorder()
		_ = h.ServeHTTP(rec, newReq(), next)
	}
	if got := up.validateCalls.Load(); got < 3 {
		t.Fatalf("validateCalls = %d after 3 valid requests, want ≥3 (rate-limit must not trip on success)", got)
	}
}

// TestHandlerConnectRateLimitResetsAfterCooldown verifies that fast-fail
// releases after the cooldown so legitimate clients aren't permanently
// locked out. The test uses tiny timeouts (10 ms cooldown) and asserts
// that a request after the cooldown reaches the upstream again.
func TestHandlerConnectRateLimitResetsAfterCooldown(t *testing.T) {
	t.Parallel()

	up := &countingUpstream{fail: true}
	h := &Handler{
		Connect: true,
		upstream: up,
		logger:  zap.NewNop(),
		failThreshold: 1,
		failWindow:    1 * time.Hour,
		failCooldown:  10 * time.Millisecond,
	}

	badAuth := "Basic " + strings.Repeat("0", 56)
	newReq := func() *http.Request {
		r := httptest.NewRequest(http.MethodConnect, "https://example.com:443/", nil)
		r.ProtoMajor = 2
		r.Header.Set("Proxy-Authorization", badAuth)
		return r
	}
	next := caddyhttp.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) error { return nil })

	// 1st request: reaches upstream and trips the limiter.
	if err := h.ServeHTTP(httptest.NewRecorder(), newReq(), next); err != nil {
		t.Fatalf("1st ServeHTTP error: %v", err)
	}
	// 2nd request: must fast-fail (still within cooldown).
	if err := h.ServeHTTP(httptest.NewRecorder(), newReq(), next); err != nil {
		t.Fatalf("2nd ServeHTTP error: %v", err)
	}
	if got := up.validateCalls.Load(); got != 1 {
		t.Fatalf("validateCalls after 2nd request = %d, want still 1", got)
	}

	// Wait past the cooldown, then verify Validate is invoked again.
	time.Sleep(20 * time.Millisecond)
	if err := h.ServeHTTP(httptest.NewRecorder(), newReq(), next); err != nil {
		t.Fatalf("3rd ServeHTTP error: %v", err)
	}
	if got := up.validateCalls.Load(); got <= 1 {
		t.Fatalf("validateCalls after cooldown = %d, want >1 (limiter must release)", got)
	}
}

// TestHandlerRateLimitWindowResets verifies the sliding-window reset path:
// a record created earlier but whose firstFailure falls outside the window
// must have its count and blockedUntil cleared before incrementing. This
// guards against a class of bugs where the window check is missing or
// one-directional, and it pushes recordFailure / isRateLimited branch
// coverage to a higher percentage.
//
// This test intentionally does NOT use t.Parallel() because it mutates
// package-level-style state on the Handler instance owned by this test.
func TestHandlerRateLimitWindowResets(t *testing.T) {
	const addr = "192.0.2.1:1234"

	h := &Handler{
		Connect:      true,
		upstream:      &countingUpstream{fail: true},
		logger:        zap.NewNop(),
		failThreshold: 3,
		failWindow:    100 * time.Millisecond,
		failCooldown:  1 * time.Hour,
	}

	newReq := func() *http.Request {
		r := httptest.NewRequest(http.MethodConnect, "https://example.com:443/", nil)
		r.ProtoMajor = 2
		r.Header.Set("Proxy-Authorization", "Basic "+strings.Repeat("0", 56))
		return r
	}
	next := caddyhttp.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) error { return nil })

	// First call: creates the record with count=1, blockedUntil=zero
	// (count<threshold). isRateLimited must return false (blockedUntil zero).
	if err := h.ServeHTTP(httptest.NewRecorder(), newReq(), next); err != nil {
		t.Fatalf("1st ServeHTTP error: %v", err)
	}
	// 2nd call: count=2, still below threshold=3, blockedUntil still zero.
	// isRateLimited must still return false.
	if err := h.ServeHTTP(httptest.NewRecorder(), newReq(), next); err != nil {
		t.Fatalf("2nd ServeHTTP error: %v", err)
	}
	if r := h.isRateLimited(addr); r {
		t.Fatalf("isRateLimited after 2 failures (threshold=3) = true, want false")
	}

	// Wait past the window.
	time.Sleep(150 * time.Millisecond)

	// 3rd call (after window): window-reset branch must fire — count cleared,
	// firstFailure updated, then incremented to 1.
	if err := h.ServeHTTP(httptest.NewRecorder(), newReq(), next); err != nil {
		t.Fatalf("3rd ServeHTTP error: %v", err)
	}
	if r := h.isRateLimited(addr); r {
		t.Fatalf("isRateLimited after window-reset = true, want false (count restarted)")
	}
}


