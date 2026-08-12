package trojan

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/imgk/caddy-trojan/pkgs/socks"

	"github.com/imgk/memory-go"
)

// [AddrType(1 byte)][Addr(max 256 byte)][Port(2 byte)][Len(2 byte)][0x0d, 0x0a][Data(max 65535 byte)]
func HandleUDP(r io.Reader, w io.Writer, timeout time.Duration, d Dialer) (int64, int64, error) {
	if err := allocShortCircuit(); err != nil {
		return 0, 0, err
	}
	rc, err := d.ListenPacket("udp", "")
	if err != nil {
		return 0, 0, err
	}
	defer rc.Close()

	ptrPrev, bb, err := memory.Alloc[byte](socks.MaxAddrLen)
	if err != nil {
		return 0, 0, fmt.Errorf("memory alloc error: %w", err)
	}
	defer memory.Free(ptrPrev)

	ptrRead, b, err := memory.Alloc[byte](64*1024 + socks.MaxAddrLen)
	if err != nil {
		return 0, 0, fmt.Errorf("memory alloc error: %w", err)
	}
	defer memory.Free(ptrRead)

	ptrWrite, bWrite, err := memory.Alloc[byte](64*1024 + socks.MaxAddrLen + 4)
	if err != nil {
		return 0, 0, fmt.Errorf("memory alloc error: %w", err)
	}
	defer memory.Free(ptrWrite)
	bWrite[socks.MaxAddrLen+2] = 0x0d
	bWrite[socks.MaxAddrLen+3] = 0x0a

	type Result struct {
		Num int64
		Err error
	}

	errCh := make(chan Result)
	go func(rc net.PacketConn, r io.Reader, errCh chan Result) (nr int64, err error) {
		defer func() {
			// The reader's r.Read / io.ReadFull can return either
			// io.EOF (client closed cleanly) or a deadline error
			// (the writer side triggered rc.SetReadDeadline(now)
			// to release this goroutine, or a wrapper like
			// gorilla/websocket returned a hideTempErr-wrapped
			// *netError with Timeout()==true). All three are
			// "clean exit" shapes that the main goroutine can
			// coalesce into a nil return.
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || isTimeoutError(err) {
				err = nil
			}
			errCh <- Result{Num: nr, Err: err}
		}()

		tt := (*net.UDPAddr)(nil)

		for {
			raddr, er := socks.ReadAddrBuffer(r, b)
			if er != nil {
				err = er
				break
			}

			l := raddr.Len()

			if !bytes.Equal(bb, raddr.Bytes()) {
				addr, er := socks.ResolveUDPAddr(raddr)
				if er != nil {
					err = er
					break
				}
				bb = raddr.AppendTo(bb[:0])
				tt = addr
			}

			if _, er := io.ReadFull(r, b[l:l+4]); er != nil {
				err = er
				break
			}
			if b[l+2] != 0x0d || b[l+3] != 0x0a {
				err = errInvalidCRLF
				break
			}

			l += (int(b[l])<<8 | int(b[l+1]))
			nr += int64(l) + 4

			buf := b[raddr.Len():l]
			if _, er := io.ReadFull(r, buf); er != nil {
				err = er
				break
			}

			if _, ew := rc.WriteTo(buf, tt); ew != nil {
				err = ew
				break
			}
		}
		rc.SetReadDeadline(time.Now())
		return
	}(rc, r, errCh)

	nr, nw, err := func(rc net.PacketConn, w io.Writer, clientR io.Reader, buf []byte, errCh chan Result, timeout time.Duration) (_, nw int64, err error) {
	for {
			rc.SetReadDeadline(time.Now().Add(timeout))
			n, addr, er := rc.ReadFrom(buf[socks.MaxAddrLen+4:])
			if er != nil {
				err = er
				break
			}

			buf[socks.MaxAddrLen] = byte(n >> 8)
			buf[socks.MaxAddrLen+1] = byte(n)

			udpAddr, ok := addr.(*net.UDPAddr)
			if !ok {
				// PacketConn.ReadFrom can return any net.Addr; if a future
				// proxy returns a non-UDP packet source (e.g. a TCP-backed
				// test fake), surface the unsupported address type as a
				// hard error and abort the session. The pre-fix comma-ok-less
				// assertion would panic on the same input; the new branch
				// fails loud and clean instead.
				// Release the reader's blocked Read on r so the
				// main goroutine does not hang on the errCh
				// wait below. The hard error propagates
				// through err to the main goroutine; without
				// the release the reader would block forever
				// (r has no other caller).
				// trySetImmediateReadDeadline dispatches through
				// the wakeableConn interface so wrappers like
				// *net.PipeConn (which implements
				// net.Conn.SetReadDeadline) are released; for
				// opaque readers the call is a silent no-op
				// matching the pre-fix behavior.
				err = fmt.Errorf("handle udp error: unsupported packet address type %T", addr)
				trySetImmediateReadDeadline(clientR)
				break
			}
			l := func(bb []byte, addr *net.UDPAddr) int64 {
				if ipv4 := addr.IP.To4(); ipv4 != nil {
					const offset = socks.MaxAddrLen - (1 + net.IPv4len + 2)
					bb[offset] = socks.AddrTypeIPv4
					copy(bb[offset+1:], ipv4)
					bb[offset+1+net.IPv4len], bb[offset+1+net.IPv4len+1] = byte(addr.Port>>8), byte(addr.Port)
					return 1 + net.IPv4len + 2
				} else {
					const offset = socks.MaxAddrLen - (1 + net.IPv6len + 2)
					bb[offset] = socks.AddrTypeIPv6
					copy(bb[offset+1:], addr.IP.To16())
					bb[offset+1+net.IPv6len], bb[offset+1+net.IPv6len+1] = byte(addr.Port>>8), byte(addr.Port)
					return 1 + net.IPv6len + 2
				}
			}(buf[:socks.MaxAddrLen], udpAddr)

			if _, ew := w.Write(buf[socks.MaxAddrLen-l : socks.MaxAddrLen+4+n]); ew != nil {
				err = ew
				break
			}
		}
	rc.SetWriteDeadline(time.Now())

	wakeReader(w)
	r := <-errCh
	// Prefer the reader goroutine's error over the writer's: the
	// reader is the one that validates the trojan CRLF terminator, so
	// a CRLF rejection (errInvalidCRLF) must not be masked by a
	// concurrent writer-side error (e.g. a UDP write failing for an
	// unrelated reason). When the reader has no error, fall back to
	// the writer's — but if the writer's error is a clean timeout
	// (the reader defer's rc.SetReadDeadline(now) typically triggers
	// exactly that via the main loop's blocked ReadFrom), suppress
	// it and report nil. Without this, every normal UDP session
	// close (client-first EOF, 10-min idle timeout, or WS-over-UDP
	// tunnel teardown) would log a spurious 'i/o timeout' error.
	if r.Err != nil {
		return r.Num, nw, r.Err
	}
	if isTimeoutError(err) {
		return r.Num, nw, nil
	}
	return r.Num, nw, err
	}(rc, w, r, bWrite, errCh, timeout)

	return nr, nw, err
}
