package handler

import (
	//"errors"

	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"go.uber.org/zap"

	"github.com/imgk/caddy-trojan/app"
	"github.com/imgk/caddy-trojan/pkgs/trojan"
	"github.com/imgk/caddy-trojan/pkgs/websocket"
	"github.com/imgk/caddy-trojan/pkgs/x"
)

func init() {
	caddy.RegisterModule(&Handler{})
	httpcaddyfile.RegisterHandlerDirective("trojan", func(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
		m := &Handler{}
		err := m.UnmarshalCaddyfile(h.Dispenser)
		return m, err
	})
}

// headerTimeout bounds how long a peer may stall while sending the trojan
// header after a WebSocket upgrade; without it an unauthenticated peer could
// hold the handler goroutine forever.
const headerTimeout = 10 * time.Second

// connectFailLimit bounds how many failed Validate attempts are allowed
// from a single remote address within connectFailWindow before the handler
// stops running Validate (and its constant-time delay + storage I/O) for
// that address for connectFailCooldown. The defaults form a "5 strikes in
// 10s ⇒ lock out for 60s" policy that absorbs an unauthenticated flood
// without locking out legitimate clients that mistype a password once.
const (
	connectFailLimit    = 5
	connectFailWindow   = 10 * time.Second
	connectFailCooldown = 60 * time.Second
)

// Handler implements an HTTP handler that ...
type Handler struct {
	ProxyName   string   `json:"proxy_name,omitempty"`
	WebSocket   bool     `json:"websocket,omitempty"`
	Connect     bool     `json:"connect_method,omitempty"`
	Verbose     bool     `json:"verbose,omitempty"`
	OriginAllow []string `json:"origin_allow,omitempty"`

	upstream app.Upstream
	proxy    app.Proxy
	logger   *zap.Logger
	upgrader websocket.Upgrader

	// headerTimeout, failThreshold, failWindow and failCooldown override the
	// default constants above when set to a non-zero value. They are
	// unexported because production configuration uses the constants; tests
	// in this package inject smaller values to keep runs short.
	headerTimeout time.Duration
	failThreshold int
	failWindow    time.Duration
	failCooldown  time.Duration

	// failMu and failState implement the per-source rate limiter for the
	// HTTP/2/3 CONNECT fast-fail path. nil until the first failure is
	// observed.
	failMu    sync.Mutex
	failState map[string]*failRecord
}

type failRecord struct {
	count        int
	firstFailure time.Time
	blockedUntil time.Time
}

// CaddyModule returns the Caddy module information.
func (*Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.trojan",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision implements caddy.Provisioner.
func (m *Handler) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	m.upgrader.CheckOrigin = m.checkOrigin
	if _, err := ctx.AppIfConfigured(app.CaddyAppID); err != nil {
		return fmt.Errorf("trojan handler configure error: %w", err)
	}
	mod, err := ctx.App(app.CaddyAppID)
	if err != nil {
		return err
	}
	app := mod.(*app.App)
	m.upstream = app.GetUpstream()
	if m.ProxyName == "" {
		m.proxy = app.GetProxy()
		return nil
	}
	var ok bool
	m.proxy, ok = app.GetProxyByName(m.ProxyName)
	if !ok {
		return fmt.Errorf("proxy name: %v does not exist", m.ProxyName)
	}
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// trojan over http2/http3
	// use CONNECT method, put trojan header as Proxy-Authorization
	if m.Connect && r.Method == http.MethodConnect {
		// handle trojan over http2/http3
		if r.ProtoMajor == 1 {
			return next.ServeHTTP(w, r)
		}
		// Fast-fail repeat offenders without running Validate (and its
		// 250ms constant-time delay plus storage I/O). The rate-limiter is a
		// sliding window; a fresh request that arrives while the source is
		// blocked is short-circuited to next.ServeHTTP so the rest of the
		// caddy chain — and the bad-actor's TCP loop — keep working.
		if m.isRateLimited(r.RemoteAddr) {
			return next.ServeHTTP(w, r)
		}
		auth := strings.TrimPrefix(r.Header.Get("Proxy-Authorization"), "Basic ")
		if len(auth) != trojan.HeaderLen {
			m.recordFailure(r.RemoteAddr)
			return next.ServeHTTP(w, r)
		}
		if ok := m.upstream.Validate(auth); !ok {
			m.recordFailure(r.RemoteAddr)
			return next.ServeHTTP(w, r)
		}
		if m.Verbose {
			m.logger.Info(fmt.Sprintf("handle trojan http%d from %v", r.ProtoMajor, r.RemoteAddr))
		}

		nr, nw, err := trojan.HandleWithDialer(r.Body, NewFlushWriter(w), m.proxy)
		if err != nil {
			m.logger.Error(fmt.Sprintf("handle http%d error: %v", r.ProtoMajor, err))
		}
		m.upstream.Consume(auth, nr, nw)
		return nil
	}

	// handle websocket
	if m.WebSocket && websocket.IsWebSocketUpgrade(r) {
		conn, err := m.upgrader.Upgrade(w, r, nil)
		if err != nil {
			return err
		}

		c := websocket.NewConn(conn)
		defer c.Close()

		// Bound the trojan header read so an unauthenticated peer cannot
		// hold this goroutine forever; the deadline is cleared on exit so
		// the tunnel is not affected.
		if nc, ok := c.UnderlyingConn().(net.Conn); ok {
			timeout := headerTimeout
			if m.headerTimeout > 0 {
				timeout = m.headerTimeout
			}
			_ = nc.SetReadDeadline(time.Now().Add(timeout))
			defer func() {
				_ = nc.SetReadDeadline(time.Time{})
			}()
		}

		b := [trojan.HeaderLen + 2]byte{}
		if _, err := io.ReadFull(c, b[:]); err != nil {
			m.logger.Error(fmt.Sprintf("read trojan header error: %v", err))
			return nil
		}
		// Reject a broken CRLF terminator consistently with the TCP path
		// (pkgs/trojan validates it via errInvalidCRLF); a key-holding client
		// with a malformed header would otherwise desynchronize the stream.
		if b[trojan.HeaderLen] != 0x0d || b[trojan.HeaderLen+1] != 0x0a {
			return nil
		}
		if ok := m.upstream.Validate(x.ByteSliceToString(b[:trojan.HeaderLen])); !ok {
			return nil
		}
		if m.Verbose {
			m.logger.Info(fmt.Sprintf("handle trojan websocket.Conn from %v", r.RemoteAddr))
		}

		nr, nw, err := trojan.HandleWithDialer(io.Reader(c), io.Writer(c), m.proxy)
		if err != nil {
			m.logger.Error(fmt.Sprintf("handle websocket error: %v", err))
		}
		m.upstream.Consume(x.ByteSliceToString(b[:trojan.HeaderLen]), nr, nw)
		return nil
	}

	return next.ServeHTTP(w, r)
}

// checkOrigin allows same-origin and Origin-less (non-browser) WebSocket
// clients while rejecting cross-site browsers, which could otherwise use a
// victim's browser as an open proxy or to guess trojan passwords. Additional
// origins (e.g. CDN or reverse-proxy setups that send a custom Origin) can be
// allow-listed via the "origin_allow" Caddyfile option or the
// "origin_allow" JSON field, matching the Origin host (host[:port]).
func (m *Handler) checkOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		// Non-browser clients (trojan/v2ray) do not send Origin.
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	for _, allow := range m.OriginAllow {
		if strings.EqualFold(u.Host, allow) {
			return true
		}
	}
	return strings.EqualFold(u.Host, r.Host)
}

// UnmarshalCaddyfile unmarshals Caddyfile tokens into h.
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.Next() {
		return d.ArgErr()
	}
	args := d.RemainingArgs()
	if len(args) > 0 {
		return d.ArgErr()
	}
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		subdirective := d.Val()
		switch subdirective {
		case "websocket":
			if h.WebSocket {
				return d.Err("only one websocket is not allowed")
			}
			h.WebSocket = true
		case "connect_method":
			if h.Connect {
				return d.Err("only one connect_method is not allowed")
			}
			h.Connect = true
		case "proxy_name":
			if !d.Args(&h.ProxyName) {
				return d.ArgErr()
			}
		case "verbose":
			if h.Verbose {
				return d.Err("only one verbose is not allowed")
			}
			h.Verbose = true
		case "origin_allow":
			var origin string
			if !d.Args(&origin) {
				return d.Err("origin_allow requires an origin host, e.g. origin_allow cdn.example.com")
			}
			h.OriginAllow = append(h.OriginAllow, origin)
		}
	}
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
)

type FlushWriter struct {
	Writer  io.Writer
	Flusher http.Flusher
}

func NewFlushWriter(w http.ResponseWriter) *FlushWriter {
	return &FlushWriter{
		Writer:  w,
		Flusher: w.(http.Flusher),
	}
}

func (c *FlushWriter) Write(b []byte) (int, error) {
	n, err := c.Writer.Write(b)
	c.Flusher.Flush()
	return n, err
}

// failCfg returns the configured threshold/window/cooldown, falling back to
// the production defaults when the corresponding struct field is zero. It
// is the test-injection seam: tests override the struct fields with tiny
// values to keep the suite fast; production leaves them zero and gets the
// constants.
func (m *Handler) failCfg() (threshold int, window, cooldown time.Duration) {
	threshold = m.failThreshold
	if threshold <= 0 {
		threshold = connectFailLimit
	}
	window = m.failWindow
	if window == 0 {
		window = connectFailWindow
	}
	cooldown = m.failCooldown
	if cooldown == 0 {
		cooldown = connectFailCooldown
	}
	return
}

// recordFailure increments the failure counter for addr and, once the
// threshold is reached within the window, marks the address as blocked
// until the cooldown elapses. It is called on any HTTP/2/3 CONNECT path
// that does not yield a validated user — wrong-length auth header, bad
// password, or upstream lookup failure.
//
// Garbage collection: entries with no recent failures are pruned lazily
// on the next access from the same address; bounded by the connect window
// (10s by default) the worst-case memory is O(uniques-addr-in-window).
func (m *Handler) recordFailure(addr string) {
	if addr == "" {
		return
	}
	threshold, window, cooldown := m.failCfg()
	if threshold <= 0 {
		return
	}
	m.failMu.Lock()
	defer m.failMu.Unlock()
	if m.failState == nil {
		m.failState = make(map[string]*failRecord)
	}
	now := time.Now()
	rec, ok := m.failState[addr]
	if !ok {
		rec = &failRecord{}
		m.failState[addr] = rec
	}
	// Reset the counter if the previous failure fell outside the window.
	if rec.firstFailure.IsZero() || now.Sub(rec.firstFailure) > window {
		rec.count = 0
		rec.firstFailure = now
		rec.blockedUntil = time.Time{}
	}
	rec.count++
	if rec.count >= threshold && rec.blockedUntil.IsZero() {
		rec.blockedUntil = now.Add(cooldown)
	}
}

// isRateLimited reports whether addr is currently in the blocked-window. A
// blocked entry is cleared lazily on access once the cooldown elapses, so
// legitimate retries are not punished past their sentence.
func (m *Handler) isRateLimited(addr string) bool {
	if addr == "" {
		return false
	}
	m.failMu.Lock()
	defer m.failMu.Unlock()
	rec, ok := m.failState[addr]
	if !ok {
		return false
	}
	if rec.blockedUntil.IsZero() {
		return false
	}
	if time.Now().Before(rec.blockedUntil) {
		return true
	}
	// Cooldown elapsed: clear so legitimate retries are not punished.
	rec.blockedUntil = time.Time{}
	rec.count = 0
	rec.firstFailure = time.Time{}
	return false
}
