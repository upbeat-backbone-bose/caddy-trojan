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
// header after a WebSocket upgrade, so an unauthenticated peer cannot hold the
// handler goroutine forever.
const headerTimeout = 10 * time.Second

// CONNECT fast-fail rate limiting: "5 failed auth attempts in 10s ⇒ lock the
// source out for 60s". Absorbs unauthenticated floods without locking out
// clients that mistype a password once.
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

	// Test-injection seam: override the constants above when non-zero.
	headerTimeout time.Duration
	failThreshold int
	failWindow    time.Duration
	failCooldown  time.Duration

	// Per-source rate limiter for the CONNECT fast-fail path. nil until the
	// first failure is observed.
	failMu      sync.Mutex
	failState   map[string]*failRecord
	cleanupOnce sync.Once
	cleanupDone chan struct{}
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
		// Fast-fail repeat offenders without running Validate (its 250ms
		// constant-time delay plus storage I/O) by short-circuiting to the
		// rest of the caddy chain.
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

		// Bound the trojan header read so an unauthenticated peer cannot hold
		// this goroutine forever. The deadline must be cleared before
		// HandleWithDialer, or it would kill long-lived idle tunnels.
		var headerConn net.Conn
		if nc, ok := c.UnderlyingConn().(net.Conn); ok {
			headerConn = nc
			timeout := headerTimeout
			if m.headerTimeout > 0 {
				timeout = m.headerTimeout
			}
			_ = nc.SetReadDeadline(time.Now().Add(timeout))
			defer func() {
				_ = nc.SetReadDeadline(time.Time{})
			}()
		}
		// Cancels the header-timeout on the current path; called before
		// HandleWithDialer so the tunnel inherits no read deadline.
		clearHeaderDeadline := func() {
			if headerConn != nil {
				_ = headerConn.SetReadDeadline(time.Time{})
			}
		}

		b := [trojan.HeaderLen + 2]byte{}
		if _, err := io.ReadFull(c, b[:]); err != nil {
			m.logger.Error(fmt.Sprintf("read trojan header error: %v", err))
			return nil
		}
		// Reject a broken CRLF terminator consistently with the TCP path.
		if b[trojan.HeaderLen] != 0x0d || b[trojan.HeaderLen+1] != 0x0a {
			return nil
		}
		if ok := m.upstream.Validate(x.ByteSliceToString(b[:trojan.HeaderLen])); !ok {
			return nil
		}
		// Header fully read and validated: drop the deadline so the tunnel
		// has no deadline bleeding in.
		clearHeaderDeadline()
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
// clients while rejecting cross-site browsers, which could otherwise be used
// as an open proxy or to guess trojan passwords. Extra origins (CDN, reverse
// proxy) can be allow-listed via the "origin_allow" Caddyfile option.
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
	_ caddy.CleanerUpper          = (*Handler)(nil)
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
// the production defaults when the corresponding field is zero. Tests inject
// tiny values via the struct fields; production leaves them zero.
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

// recordFailure counts an auth failure for addr and blocks the address once
// the threshold is reached within the window, until the cooldown elapses. It
// is called on any CONNECT path that does not yield a validated user.
// Expired entries are dropped by the background cleanup goroutine and lazily
// by isRateLimited, so the map cannot grow unbounded.
func (m *Handler) recordFailure(addr string) {
	if addr == "" {
		return
	}
	threshold, window, cooldown := m.failCfg()
	if threshold <= 0 {
		return
	}
	m.spawnCleanupLoop()
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

// isRateLimited reports whether addr is currently blocked. Expired entries
// are cleared lazily on access so retries are not punished past the cooldown.
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
	// Cooldown elapsed: drop the entry so the map doesn't grow unbounded.
	delete(m.failState, addr)
	return false
}

// Cleanup stops the background cleanup goroutine and releases failState.
// Called by caddy when the handler is unloaded.
func (m *Handler) Cleanup() error {
	m.failMu.Lock()
	if m.cleanupDone != nil {
		select {
		case <-m.cleanupDone:
		default:
			close(m.cleanupDone)
		}
	}
	m.failState = nil
	m.failMu.Unlock()
	return nil
}

// spawnCleanupLoop starts one background goroutine per Handler that
// periodically drops expired failState entries, so unique-source failures
// cannot exhaust memory.
func (m *Handler) spawnCleanupLoop() {
	m.cleanupOnce.Do(func() {
		m.cleanupDone = make(chan struct{})
		go m.cleanupLoop()
	})
}

// cleanupLoop is the cleanup goroutine body. It ticks at cooldown/2 (clamped
// to [1s, 1m]) until Cleanup closes cleanupDone. The lower clamp guards
// time.NewTicker against a non-positive interval when cooldown is tiny.
func (m *Handler) cleanupLoop() {
	_, _, cooldown := m.failCfg()
	interval := cooldown / 2
	if interval <= 0 {
		interval = time.Second
	}
	if interval > time.Minute {
		interval = time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-m.cleanupDone:
			return
		case <-t.C:
			m.cleanupTick(time.Now())
		}
	}
}

// cleanupTick removes entries whose firstFailure is older than the cooldown:
// stale single-failure entries and expired blocks never revisited by
// isRateLimited.
func (m *Handler) cleanupTick(now time.Time) {
	_, _, cooldown := m.failCfg()
	m.failMu.Lock()
	defer m.failMu.Unlock()
	if m.failState == nil {
		return
	}
	for addr, rec := range m.failState {
		if !rec.firstFailure.IsZero() && now.Sub(rec.firstFailure) > cooldown {
			delete(m.failState, addr)
		}
	}
}
