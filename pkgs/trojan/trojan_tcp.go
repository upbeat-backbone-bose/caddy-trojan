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

// tcpBufSize is the per-direction copy buffer for HandleTCP. Allocated in the
// main flow before goroutines spawn so an mmap failure surfaces as a regular
// (0, 0, err) return rather than a goroutine panic.
const tcpBufSize = 32 * 1024

// wakeGrace bounds how long HandleTCP keeps the client-side read open after the
// remote half-closes its write side. The FIN is not a full close: in-flight
// data (e.g. SSH final packets) must drain before the peer is force-woken.
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

// allocShortCircuit returns the test-only allocByteErr, or nil in production
// so HandleTCP/HandleUDP proceed to allocate normally. Tests override
// allocByteErr to exercise the alloc-failure branch without exhausting memory.
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
		// Clean exits cover EOF and the wakeGrace timeout. Wrappers like
		// gorilla/websocket return a *netError with Timeout()==true rather
		// than the stdlib sentinel, so check the net.Error interface too.
		isClean := err == nil
		if !isClean {
			var nerr net.Error
			if errors.As(err, &nerr) && nerr.Timeout() {
				isClean = true
			}
		}
		if isClean {
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
		// The write path through w never sees a deadline error: rc is a raw
		// *net.TCPConn and only the reader goroutine's deadline is set (via
		// trySetReadDeadline). Timeout detection therefore stays on the
		// stdlib sentinel here.
		nw, err := copyBuffer(w, io.Reader(rc), buf)
		if err == nil {
			if cw, ok := w.(interface {
				CloseWrite() error
			}); ok {
				cw.CloseWrite()
			}
			// rc finished writing but the client may still be sending; give
			// it wakeGrace to drain instead of truncating in-flight data.
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
		// If the writer timed out but the reader exited cleanly, the tunnel is
		// in a normal shutdown shape: report nil.
		if r.Err == nil && isTimeoutError(err) {
			return r.Num, nw, nil
		}
		return r.Num, nw, err
	}(rc, w, bufB, errCh)

	return nr, nw, err
}
