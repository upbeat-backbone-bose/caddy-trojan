package trojan

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/imgk/memory-go"
)

// tcpBufSize is the per-direction copy buffer for HandleTCP. The pool variant
// of memory.Alloc never returns errors; the malloc_syscall variant (used by
// CI builds per AGENTS.md) does. Both buffers are allocated in the main
// flow before goroutines spawn so an mmap failure surfaces as a regular
// (0, 0, err) return rather than a goroutine panic.
const tcpBufSize = 32 * 1024

// wakeGrace bounds how long HandleTCP keeps the client-side read open after
// the remote side has closed its write direction (TCP half-close) before
// force-waking the peer. The remote's FIN is not a full close: the client may
// still have data in flight (e.g. SSH final packets), and an immediate read
// deadline would truncate it and destabilize long-lived tunnels. The grace
// window lets normal shutdown traffic through (SSH final packets arrive in
// well under a second) while still releasing a truly silent peer quickly, so
// a half-open client cannot deadlock the connection for long.
const wakeGrace = 2 * time.Second

func copyBuffer(w io.Writer, r io.Reader, buf []byte) (n int64, err error) {
	for {
		nr, er := r.Read(buf)
		if nr > 0 {
			nw, ew := w.Write(buf[0:nr])
			if nw < 0 || nr < nw {
				nw = 0
				if ew == nil {
					ew = errors.New("invalid write result")
				}
			}
			n += int64(nw)
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if !errors.Is(er, io.EOF) {
				err = er
			}
			break
		}
	}
	return n, err
}

// allocShortCircuit returns the error HandleTCP/HandleUDP should propagate
// when the test-only allocByteErr is set, or nil when production code should
// proceed to allocate normally. Production leaves allocByteErr nil, so this
// is a no-op; tests override it to exercise the alloc-failure branch without
// exhausting memory. Returns error only (not (int64, int64, error)) so a
// future maintainer cannot accidentally use the int64 sentinels.
func allocShortCircuit() error {
	if err := allocByteErr; err != nil {
		return fmt.Errorf("memory alloc error: %w", err)
	}
	return nil
}

func HandleTCP(r io.Reader, w io.Writer, addr net.Addr, d Dialer) (int64, int64, error) {
	if err := allocShortCircuit(); err != nil {
		return 0, 0, err
	}
	rc, err := d.Dial("tcp", addr.String())
	if err != nil {
		return 0, 0, err
	}
	defer rc.Close()

	ptrA, bufA, err := memory.Alloc[byte](tcpBufSize)
	if err != nil {
		return 0, 0, fmt.Errorf("memory alloc error: %w", err)
	}
	defer memory.Free(ptrA)
	ptrB, bufB, err := memory.Alloc[byte](tcpBufSize)
	if err != nil {
		return 0, 0, fmt.Errorf("memory alloc error: %w", err)
	}
	defer memory.Free(ptrB)

	type Result struct {
		Num int64
		Err error
	}

	errCh := make(chan Result)
	go func(rc net.Conn, r io.Reader, buf []byte, errCh chan Result) {
		nr, err := copyBuffer(io.Writer(rc), r, buf)
		if err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			if cw, ok := rc.(interface {
				CloseWrite() error
			}); ok {
				cw.CloseWrite()
			}
			rc.SetReadDeadline(time.Now())
			errCh <- Result{Num: nr, Err: nil}
			return
		}
		if cw, ok := rc.(interface {
			CloseWrite() error
		}); ok {
			cw.CloseWrite()
		}
		rc.SetReadDeadline(time.Now())
		errCh <- Result{Num: nr, Err: err}
	}(rc, r, bufA, errCh)

	nr, nw, err := func(rc net.Conn, w io.Writer, buf []byte, errCh chan Result) (int64, int64, error) {
		nw, err := copyBuffer(w, io.Reader(rc), buf)
		if err == nil {
			if cw, ok := w.(interface {
				CloseWrite() error
			}); ok {
				cw.CloseWrite()
			}
			// Half-close: rc finished writing, but the client side may still
			// be sending (see wakeGrace above). Give it a grace window to
			// drain instead of force-waking immediately, which would truncate
			// in-flight data and cause spurious disconnects on long-lived
			// tunnels (e.g. SSH over trojan).
			trySetReadDeadline(w, time.Now().Add(wakeGrace))
			r := <-errCh
			return r.Num, nw, r.Err
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			select {
			case r := <-errCh:
				if r.Err == nil {
					for {
						rc.SetReadDeadline(time.Now().Add(time.Minute))
						n, err := copyBuffer(w, io.Reader(rc), buf)
						nw += n
						if n == 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
							break
						}
					}
					return r.Num, nw, r.Err
				}

				if cw, ok := w.(interface {
					CloseWrite() error
				}); ok {
					cw.CloseWrite()
				}
				return r.Num, nw, r.Err
			case <-time.After(time.Minute):
			}
			if cw, ok := w.(interface {
				CloseWrite() error
			}); ok {
				cw.CloseWrite()
			}
			wakeReader(w)
			r := <-errCh
			return r.Num, nw, r.Err
		}
		rc.SetWriteDeadline(time.Now().Add(wakeGrace))
		if cw, ok := rc.(interface {
			CloseWrite() error
		}); ok {
			cw.CloseWrite()
		}
		wakeReader(w)
		r := <-errCh
		return r.Num, nw, err
	}(rc, w, bufB, errCh)

	return nr, nw, err
}
