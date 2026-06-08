"""E2e: real client IP recovery via PROXY protocol v2 (issue #98).

A raw client prepends a PROXY-v2 header declaring a public client IP, then
completes TLS + GET /login against the proxy_protocol-enabled :444 listener
(host port 8444). The rendered identity card must show the PROXY-declared IP,
proving nginx parses PROXY-v2, the realip module rewrites $remote_addr, X-Real-IP
carries it, and the portal renders it. Auto-marked `e2e` by conftest.
"""
from __future__ import annotations

import socket
import ssl
import struct

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8444
DECLARED_IP = "203.0.113.42"
DECLARED_PORT = 54321


def _proxy_v2_tcp4(src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> bytes:
    """A PROXY protocol v2 header for a TCP-over-IPv4 connection.

    Layout (haproxy PROXY-protocol spec, section 2.2): 12-byte signature,
    version+command (0x21 = v2, PROXY), family+transport (0x11 = AF_INET+STREAM),
    2-byte address-block length, then src/dst IPv4 (4+4) and src/dst port (2+2).
    """
    sig = b"\r\n\r\n\x00\r\nQUIT\n"
    addr = (socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + struct.pack("!HH", src_port, dst_port))
    return sig + bytes([0x21, 0x11]) + struct.pack("!H", len(addr)) + addr


def test_proxy_protocol_recovers_real_client_ip(e2e_certs, e2e_stack):
    raw = socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=15)
    try:
        raw.settimeout(15)
        raw.sendall(_proxy_v2_tcp4(DECLARED_IP, DECLARED_PORT, PROXY_HOST, PROXY_PORT))
        ctx = ssl.create_default_context(cafile=str(e2e_certs))
        with ctx.wrap_socket(raw, server_hostname="postern.test") as tls:
            tls.sendall(
                b"GET /login HTTP/1.1\r\n"
                b"Host: postern.test\r\n"
                b"User-Agent: pp-test\r\n"
                b"Connection: close\r\n\r\n"
            )
            chunks = []
            while True:
                b = tls.recv(4096)
                if not b:
                    break
                chunks.append(b)
    finally:
        raw.close()
    body = b"".join(chunks).decode("utf-8", "replace")
    # Pin to the identity-card element (login.html: <div class="ipc-ip">{{ identity.ip }}</div>)
    # so the test proves realip -> identity card, not an incidental substring match.
    assert f'ipc-ip">{DECLARED_IP}' in body, f"identity card did not show {DECLARED_IP}; got:\n{body[:2000]}"
