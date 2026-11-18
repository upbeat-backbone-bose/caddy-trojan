#!/usr/bin/env python3
"""Minimal trojan-protocol client used by the end-to-end gate.

Wire format (see pkgs/trojan.HandleWithDialer and pkgs/socks/addr.go):

    hex(sha224(password)) [56 bytes] | CRLF | cmd[1] | addr | CRLF | payload
    cmd  := 0x01 connect
    addr := 0x01 | ipv4[4] | port[2 BE]      (socks.AddrTypeIPv4)

Exit codes:
    0  the server answered (authentication succeeded and the tunnel works)
    2  the connection was closed without an answer (authentication rejected)
    3  usage error

Usage:
    trojan_client.py <password> <trojan_host> <trojan_port> <target_host> <target_port> [payload]
"""

import hashlib
import socket
import sys

CMD_CONNECT = 0x01
ADDR_TYPE_IPV4 = 0x01


def token(password: str) -> bytes:
    """Trojan auth token: hex(sha224(password))."""
    return hashlib.sha224(password.encode()).hexdigest().encode()


def build_wire(password: str, target_host: str, target_port: int, payload: bytes) -> bytes:
    addr = bytearray([ADDR_TYPE_IPV4])
    addr += socket.inet_aton(target_host)
    addr += target_port.to_bytes(2, "big")
    return token(password) + b"\r\n" + bytes([CMD_CONNECT]) + bytes(addr) + b"\r\n" + payload


def main() -> int:
    if len(sys.argv) < 6:
        sys.stderr.write(__doc__)
        return 3

    password = sys.argv[1]
    trojan_host, trojan_port = sys.argv[2], int(sys.argv[3])
    target_host, target_port = sys.argv[4], int(sys.argv[5])
    payload = sys.argv[6].encode() if len(sys.argv) > 6 else b"GET / HTTP/1.1\r\nHost: target\r\n\r\n"

    wire = build_wire(password, target_host, target_port, payload)

    sock = socket.create_connection((trojan_host, trojan_port), timeout=15)
    try:
        sock.sendall(wire)
        sock.settimeout(15)
        chunks = []
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
        data = b"".join(chunks)
    except (ConnectionResetError, BrokenPipeError, socket.timeout, OSError):
        # Rejected before any answer: the listener rewinds the connection to the
        # decoy HTTP path and the peer goes away without answering.
        return 2
    finally:
        sock.close()

    sys.stdout.write(data.decode("utf-8", "replace"))
    return 0 if data else 2


if __name__ == "__main__":
    sys.exit(main())
