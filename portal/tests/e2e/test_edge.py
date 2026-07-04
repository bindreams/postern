"""End-to-end tests for nginx edge fronting (EDGE_PROFILE=cloudflare).

Boots a dedicated compose stack (postern-e2e-edge, host port 8453) with nginx
running EDGE_PROFILE=cloudflare and a locally-generated mTLS test CA substituted
for the shipped Cloudflare origin-pull CA.  Asserts the two load-bearing security
behaviors:

1. Fail-closed real-IP recovery
   With no ranges in the postern-edge volume, CF-Connecting-IP is NOT trusted
   (nginx's realip module ignores the header when the source has no matching
   set_real_ip_from entry).  After seeding a ``set_real_ip_from 0.0.0.0/0``
   entry, the same header IS recovered and appears in the login-page identity card.

2. mTLS enforcement
   nginx requires a client cert signed by the mounted CA (``ssl_verify_client on``).
   A connection without any client cert is rejected at the HTTP level with 400 Bad
   Request (nginx returns 400 when the TLS handshake completes but no valid cert is
   present; this is TLS 1.3 behavior where the empty Certificate message is accepted
   at TLS level and nginx enforces the requirement at the HTTP level).  A connection
   with the test client cert is accepted and produces an HTTP 200/302 response.

All tests are auto-marked ``e2e_edge`` by conftest; run with:
    cd portal && uv run pytest -m e2e_edge -v
"""

from __future__ import annotations

import socket
import ssl

from ._edge_helpers import EDGE_BASE_URL

_FAKE_CF_IP = "203.0.113.42"  # RFC 5737 TEST-NET-3: publicly routable, never real traffic
_CF_HEADER = "CF-Connecting-IP"


def _make_ssl_ctx(e2e_certs, client_cert=None, client_key=None):
    """Build an ssl.SSLContext trusting the test CA, optionally with a client cert."""
    ctx = ssl.create_default_context(cafile=str(e2e_certs))
    if client_cert is not None:
        ctx.load_cert_chain(certfile=str(client_cert), keyfile=str(client_key))
    return ctx


# Real-IP recovery tests ===============================================================================================


def test_real_ip_fail_closed_without_ranges(e2e_certs, edge_stack, edge_client_certs):
    """With an empty postern-edge volume, CF-Connecting-IP is not trusted.

    The identity card on /login must show the real source IP (docker bridge
    gateway), NOT the fake CF IP in the header.  This is the fail-closed
    behavior: no set_real_ip_from entry -> header ignored regardless of value.

    A client cert is required to pass the mTLS gate; the test uses the same
    test client cert that the mTLS acceptance test uses.
    """
    import httpx

    client_cert, client_key = edge_client_certs
    ctx = _make_ssl_ctx(e2e_certs, client_cert, client_key)
    with httpx.Client(base_url=EDGE_BASE_URL, verify=ctx, follow_redirects=False) as client:
        r = client.get("/login", headers={_CF_HEADER: _FAKE_CF_IP})

    assert r.status_code == 200, f"expected 200 from /login; got {r.status_code}"
    assert f'ipc-ip">{_FAKE_CF_IP}' not in r.text, (
        f"CF-Connecting-IP {_FAKE_CF_IP!r} appeared in the identity card despite no "
        f"set_real_ip_from entry (fail-closed check failed); "
        f"body excerpt: {r.text[:600]!r}"
    )


def test_real_ip_recovered_with_seeded_ranges(e2e_certs, edge_stack, edge_client_certs, seeded_edge_ranges):
    """With a seeded set_real_ip_from 0.0.0.0/0 entry, CF-Connecting-IP IS recovered.

    The identity card on /login must show the fake CF IP declared in the header,
    proving nginx's realip module reads the header when the source is trusted.
    """
    import httpx

    client_cert, client_key = edge_client_certs
    ctx = _make_ssl_ctx(e2e_certs, client_cert, client_key)
    with httpx.Client(base_url=EDGE_BASE_URL, verify=ctx, follow_redirects=False) as client:
        r = client.get("/login", headers={_CF_HEADER: _FAKE_CF_IP})

    assert r.status_code == 200, f"expected 200 from /login; got {r.status_code}"
    assert f'ipc-ip">{_FAKE_CF_IP}' in r.text, (
        f"CF-Connecting-IP {_FAKE_CF_IP!r} was NOT recovered despite seeded "
        f"set_real_ip_from 0.0.0.0/0; "
        f"body excerpt: {r.text[:600]!r}"
    )


# mTLS enforcement tests ===============================================================================================


def test_mtls_without_client_cert_rejected(e2e_certs, edge_stack):
    """nginx returns 400 when no client certificate is presented.

    With ``ssl_verify_client on``, nginx sends CertificateRequest during the
    TLS 1.3 handshake.  When the client responds with an empty Certificate
    message (no cert loaded), nginx completes the TLS handshake and returns
    HTTP 400 Bad Request -- it is the HTTP layer that enforces the requirement,
    not the TLS layer, in the TLS 1.3 negotiation path.
    """
    ctx = ssl.create_default_context(cafile=str(e2e_certs))
    # Deliberately load NO client cert.
    with socket.create_connection(("127.0.0.1", 8453), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname="postern.test") as tls:
            tls.sendall(b"GET /login HTTP/1.1\r\n"
                        b"Host: postern.test\r\n"
                        b"Connection: close\r\n\r\n")
            chunks: list[bytes] = []
            while True:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)

    response = b"".join(chunks).decode("utf-8", "replace")
    assert response.startswith("HTTP/1.1"), (f"expected an HTTP response; got: {response[:200]!r}")
    status_line = response.splitlines()[0]
    assert " 400 " in status_line, (
        f"expected nginx to return 400 Bad Request when no client cert is "
        f"provided (ssl_verify_client on); got status line: {status_line!r}"
    )


def test_mtls_with_client_cert_accepted(e2e_certs, edge_stack, edge_client_certs):
    """A client cert signed by the mounted test CA passes nginx mTLS validation.

    The TLS handshake succeeds and nginx proxies the request to the portal,
    which returns an HTTP response (200 login page or 302 redirect).
    """
    client_cert, client_key = edge_client_certs

    ctx = _make_ssl_ctx(e2e_certs, client_cert, client_key)
    with socket.create_connection(("127.0.0.1", 8453), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname="postern.test") as tls:
            tls.sendall(b"GET /login HTTP/1.1\r\n"
                        b"Host: postern.test\r\n"
                        b"Connection: close\r\n\r\n")
            chunks: list[bytes] = []
            while True:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)

    response = b"".join(chunks).decode("utf-8", "replace")
    assert response.startswith("HTTP/1.1"
                               ), (f"expected an HTTP/1.1 response with valid client cert; got: {response[:200]!r}")
    status_line = response.splitlines()[0]
    assert " 200 " in status_line or " 302 " in status_line, (
        f"expected 200 or 302 with valid client cert; got status line: {status_line!r}"
    )
