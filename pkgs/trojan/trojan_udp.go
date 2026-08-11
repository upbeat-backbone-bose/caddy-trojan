package trojan

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
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
			if errors.Is(err, io.EOF) || errors.Is(err, os.ErrDeadlineExceeded) {
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

	nr, nw, err := func(rc net.PacketConn, w io.Writer, buf []byte, errCh chan Result, timeout time.Duration) (_, nw int64, err error) {
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
				// hard error rather than panic on the unchecked type
				// assertion below. The next loop iteration's ReadFrom
				// will time out per the existing deadline, so this is
				// self-recovering for transient cases.
				err = fmt.Errorf("handle udp error: unsupported packet address type %T", addr)
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
	// Prefer the reader goroutine's error over the writer's: the reader is
	// the one that validates the trojan CRLF terminator, so a CRLF rejection
	// (errInvalidCRLF) must not be masked by a concurrent writer-side error
	// (e.g. a UDP write failing for an unrelated reason). If the reader has
	// no error, fall back to the writer's.
	if r.Err != nil {
		return r.Num, nw, r.Err
	}
	return r.Num, nw, err
	}(rc, w, bWrite, errCh, timeout)

	return nr, nw, err
}
