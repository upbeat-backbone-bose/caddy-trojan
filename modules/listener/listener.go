package listener

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

	"go.uber.org/zap"

	"github.com/imgk/caddy-trojan/app"
	"github.com/imgk/caddy-trojan/pkgs/rawconn"
	"github.com/imgk/caddy-trojan/pkgs/trojan"
	"github.com/imgk/caddy-trojan/pkgs/x"
)

func init() {
	caddy.RegisterModule(ListenerWrapper{})
}

// ListenerWrapper implements an TLS wrapper that it accept connections
// from clients and check the connection with pre-defined password
// and aead cipher defined by go-shadowsocks2, and return a normal page if
// failed.
type ListenerWrapper struct {
	upstream app.Upstream
	proxy    app.Proxy
	logger   *zap.Logger

	ProxyName string `json:"proxy_name,omitempty"`
	Verbose   bool   `json:"verbose,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (ListenerWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.trojan",
		New: func() caddy.Module { return new(ListenerWrapper) },
	}
}

// Provision implements caddy.Provisioner.
func (m *ListenerWrapper) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	if _, err := ctx.AppIfConfigured(app.CaddyAppID); err != nil {
		return fmt.Errorf("trojan configure error: %w", err)
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

// WrapListener implements caddy.ListenWrapper
func (m *ListenerWrapper) WrapListener(l net.Listener) net.Listener {
	ln := NewListener(l, m.upstream, m.proxy, m.logger)
	ln.Verbose = m.Verbose
	go ln.loop()
	return ln
}

// UnmarshalCaddyfile unmarshals Caddyfile tokens into h.
func (m *ListenerWrapper) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
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
		case "verbose":
			m.Verbose = true
		case "proxy_name":
			if !d.Args(&m.ProxyName) {
				return d.ArgErr()
			}
		}
	}
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner     = (*ListenerWrapper)(nil)
	_ caddy.ListenerWrapper = (*ListenerWrapper)(nil)
	_ caddyfile.Unmarshaler = (*ListenerWrapper)(nil)
)

// sniffTimeout bounds how long a connection may stall while the listener
// reads the trojan header prefix. Without it, an unauthenticated peer could
// hold a goroutine and a file descriptor forever by sending a few bytes (or
// nothing) after the TLS handshake.
const sniffTimeout = 10 * time.Second

type Listener struct {
	Verbose bool

	net.Listener
	Upstream app.Upstream
	Proxy    app.Proxy
	Logger   *zap.Logger

	conns  chan net.Conn
	closed chan struct{}
}

func NewListener(ln net.Listener, up app.Upstream, px app.Proxy, logger *zap.Logger) *Listener {
	l := &Listener{
		Listener: ln,
		Upstream: up,
		Proxy:    px,
		Logger:   logger,
		conns:    make(chan net.Conn, 8),
		closed:   make(chan struct{}),
	}
	return l
}

func (l *Listener) Accept() (net.Conn, error) {
	select {
	case <-l.closed:
		return nil, os.ErrClosed
	case c := <-l.conns:
		return c, nil
	}
}

func (l *Listener) Close() error {
	select {
	case <-l.closed:
		return nil
	default:
		close(l.closed)
	}
	return nil
}

func (l *Listener) loop() {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			select {
			case <-l.closed:
				return
			default:
				l.Logger.Error(fmt.Sprintf("accept net.Conn error: %v", err))
				// Back off briefly so a failing underlying listener (e.g.
				// during shutdown) does not spin the loop at full speed.
				time.Sleep(100 * time.Millisecond)
			}
			continue
		}

		go func(c net.Conn, lg *zap.Logger, up app.Upstream) {
			b := make([]byte, trojan.HeaderLen+2)
			// Bound the sniff read so a stalled peer cannot hold this
			// goroutine forever. The deadline MUST be cleared before any
			// path that hands the conn off to caddy (rewind) or to
			// HandleWithDialer (tunnel); otherwise the sniff timeout would
			// kill long-lived idle SSH/SCP tunnels ~sniffTimeout after the
			// last byte arrived, with no warning. The defer below is the
			// safety net for the read-error paths, where the conn is being
			// closed anyway.
			_ = c.SetReadDeadline(time.Now().Add(sniffTimeout))
			defer func() {
				_ = c.SetReadDeadline(time.Time{})
			}()
			// clearDeadline cancels the sniff timeout on the current path.
			// Call it before any handoff (rewind to caddy, or to
			// HandleWithDialer) so the deadline never bleeds past the sniff.
			clearDeadline := func() { _ = c.SetReadDeadline(time.Time{}) }

			for n := 0; n < trojan.HeaderLen+2; n += 1 {
				nr, err := c.Read(b[n : n+1])
				if err != nil {
					if errors.Is(err, io.EOF) {
						lg.Error(fmt.Sprintf("read prefix error: read tcp %v -> %v: read: %v", c.RemoteAddr(), c.LocalAddr(), err))
					} else {
						lg.Error(fmt.Sprintf("read prefix error, not io, rewind and let normal caddy deal with it: %v", err))
						clearDeadline()
						select {
						case <-l.closed:
							c.Close()
						case l.conns <- rawconn.RewindConn(c, b[:n+nr]):
							// Rewind only the bytes actually read; on a partial
							// read (nr > 0) that includes b[n], otherwise b[n]
							// is uninitialized and must not be replayed.
						}
						return
					}
					c.Close()
					return
				}
				if nr == 0 {
					continue
				}
				// mimic nginx
				if b[n] == 0x0a && n < trojan.HeaderLen+1 {
					clearDeadline()
					select {
					case <-l.closed:
						c.Close()
					case l.conns <- rawconn.RewindConn(c, b[:n+1]):
					}
					return
				}
			}

			// Sniff is complete. Clear the deadline BEFORE Validate (so the
			// 250ms validateDelay doesn't burn into the session deadline)
			// and BEFORE HandleWithDialer (so the trojan tunnel inherits
			// no read deadline at all and can stay idle as long as the
			// client and upstream want). Without this clear, the 10s
			// sniff deadline kills SSH/SCP tunnels during normal idle gaps
			// (SSH keepalive is typically 60s+).
			clearDeadline()

			// check the net.Conn
			if b[trojan.HeaderLen] != 0x0d || b[trojan.HeaderLen+1] != 0x0a ||
				!up.Validate(x.ByteSliceToString(b[:trojan.HeaderLen])) {
				// Invalid CRLF terminator or unknown key: rewind and let caddy
				// serve the connection as a normal (decoy) request.
				select {
				case <-l.closed:
					c.Close()
				case l.conns <- rawconn.RewindConn(c, b):
				}
				return
			}
			defer c.Close()
			if l.Verbose {
				lg.Info(fmt.Sprintf("handle trojan net.Conn from %v", c.RemoteAddr()))
			}

			nr, nw, err := trojan.HandleWithDialer(io.Reader(c), io.Writer(c), l.Proxy)
			if err != nil {
				lg.Error(fmt.Sprintf("handle net.Conn error: %v", err))
			}
			up.Consume(x.ByteSliceToString(b[:trojan.HeaderLen]), nr, nw)
		}(conn, l.Logger, l.Upstream)
	}
}
