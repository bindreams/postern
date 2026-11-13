"""Tests for the DoH apex-HTTPS ech= front check."""
from __future__ import annotations

import functools
import logging
from types import SimpleNamespace

import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import httpx2
import pytest
from dns.rdtypes.IN.HTTPS import HTTPS
from dns.rdtypes.svcbbase import GenericParam, ParamKey

from postern import ech

DOH_URL = "https://doh.test/dns-query"
# 2-byte length prefix 4, then 4 bytes: the smallest ECHConfigList dnspython >= 2.9 accepts.
VALID_ECH = bytes([0, 4, 0, 0, 0, 0])


def test_doh_backend_available():
    # The DoH transport (h2/httpcore2/httpx2 via the dnspython[doh] extra) must be
    # installed, or check_apex_ech silently degrades to always-"inconclusive".
    import dns._features
    assert dns._features.have("doh"), "dnspython[doh] extra (h2/httpcore2/httpx2) is not installed"


def test_has_ech_param_against_real_dnspython_rdata():
    # Exercise _has_ech_param against REAL dnspython HTTPS rdata (not a mock), so the
    # rr.params key type and the ech-value attribute shape are pinned to the library.
    # dnspython >= 2.9 validates the ECHConfigList, so the value must be well-formed
    # ("AAQAAAAA" = 2-byte length prefix 4, then 4 bytes); "AAAA" is rejected.
    with_ech = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.HTTPS, '1 . ech="AAQAAAAA"')
    without_ech = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.HTTPS, '1 . alpn="h2"')
    assert ech._has_ech_param(with_ech) is True
    assert ech._has_ech_param(without_ech) is False


def _https_rdata(params: dict) -> HTTPS:
    return HTTPS(dns.rdataclass.IN, dns.rdatatype.HTTPS, 1, dns.name.root, params)


def _serve_doh(monkeypatch, body_for):
    """Route check_apex_ech's real dns.query.https through a mock httpx2 transport.

    `body_for(query)` returns the DNS reply wire for the parsed query (or raw bytes
    to serve verbatim). Only the network is replaced: the HTTP exchange, the status
    check and dns.message.from_wire all run for real."""

    def handler(request: httpx2.Request) -> httpx2.Response:
        body = body_for(dns.message.from_wire(request.content))
        # stream=, not content=: only a streamed body is closed, which sets response.elapsed.
        return httpx2.Response(200, stream=httpx2.ByteStream(body), headers={"content-type": "application/dns-message"})

    client = httpx2.Client(transport=httpx2.MockTransport(handler))
    monkeypatch.setattr(ech.dns.query, "https", functools.partial(dns.query.https, session=client))


def _reply_with(rdata: HTTPS):

    def build(query: dns.message.Message) -> bytes:
        reply = dns.message.make_response(query)
        reply.answer.append(dns.rrset.from_rdata("postern.test.", 300, rdata))
        return reply.to_wire()

    return build


def test_present_when_wire_reply_carries_ech(monkeypatch):
    _serve_doh(monkeypatch, _reply_with(_https_rdata({ParamKey.ECH: GenericParam(VALID_ECH)})))
    assert ech.check_apex_ech("postern.test", DOH_URL) == "present"


def test_absent_when_wire_reply_has_no_ech(monkeypatch):
    rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.HTTPS, '1 . alpn="h2"')
    _serve_doh(monkeypatch, _reply_with(rdata))
    assert ech.check_apex_ech("postern.test", DOH_URL) == "absent"


@pytest.mark.parametrize(
    "value", [b"", bytes([0, 4, 0]), bytes([0, 9]) + b"abcdef"],
    ids=["empty", "short-config-list", "length-prefix-mismatch"]
)
def test_absent_when_wire_reply_ech_is_unusable(monkeypatch, value):
    # The record exists but cannot carry a usable ECH config: dnspython >= 2.9 rejects
    # the whole reply while parsing it. That is a confirmed "front not serving ECH"
    # (so `--ech always` refuses), not an unknown.
    _serve_doh(monkeypatch, _reply_with(_https_rdata({ParamKey.ECH: GenericParam(value)})))
    assert ech.check_apex_ech("postern.test", DOH_URL) == "absent"


def test_inconclusive_when_reply_is_not_a_dns_message(monkeypatch):
    # A captive portal / broken resolver answering 200 with a non-DNS body says nothing
    # about the record, so it must not read as a confirmed "absent".
    _serve_doh(monkeypatch, lambda query: b"<html>login required</html>")
    assert ech.check_apex_ech("postern.test", DOH_URL) == "inconclusive"


def test_inconclusive_when_doh_transport_fails(monkeypatch):

    def handler(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("doh down")

    client = httpx2.Client(transport=httpx2.MockTransport(handler))
    monkeypatch.setattr(ech.dns.query, "https", functools.partial(dns.query.https, session=client))
    assert ech.check_apex_ech("postern.test", DOH_URL) == "inconclusive"


def test_inconclusive_when_no_https_record(monkeypatch):
    monkeypatch.setattr(ech, "_query_https_rrs", lambda *a, **k: None)
    assert ech.check_apex_ech("postern.test", "https://doh.test/dns-query") == "inconclusive"


def test_inconclusive_on_query_error(monkeypatch):

    def boom(*a, **k):
        raise TimeoutError("doh down")

    monkeypatch.setattr(ech, "_query_https_rrs", boom)
    assert ech.check_apex_ech("postern.test", "https://doh.test/dns-query") == "inconclusive"


def test_lost_doh_backend_logs_error_and_is_inconclusive(monkeypatch, caplog):
    # A dropped DoH backend (NoDOH) is a systemic regression, not an ordinary blip:
    # inconclusive, but logged at ERROR so it is visible.
    def no_backend(*a, **k):
        raise dns.query.NoDOH("DoH not available")

    monkeypatch.setattr(ech, "_query_https_rrs", no_backend)
    caplog.set_level(logging.ERROR, logger="postern.ech")
    assert ech.check_apex_ech("postern.test", "https://doh.test/dns-query") == "inconclusive"
    assert "DoH backend unavailable" in caplog.text


def test_inconclusive_when_param_parsing_raises(monkeypatch):
    # A parse-shape surprise inside the rr loop must degrade to inconclusive, not
    # propagate (check_apex_ech's contract is "never raises").
    class Boom:

        @property
        def params(self):
            raise RuntimeError("unexpected rdata shape")

    monkeypatch.setattr(ech, "_query_https_rrs", lambda *a, **k: [Boom()])
    assert ech.check_apex_ech("postern.test", "https://doh.test/dns-query") == "inconclusive"


def test_inconclusive_when_rdata_missing_params_attr(monkeypatch):
    # A dnspython shape change (renamed/removed .params) must degrade to inconclusive
    # (not a false confirmed "absent"). Direct attribute access lets the AttributeError
    # reach check_apex_ech's outer try/except.
    class NoParams:
        pass  # no .params attribute

    monkeypatch.setattr(ech, "_query_https_rrs", lambda *a, **k: [NoParams()])
    assert ech.check_apex_ech("postern.test", "https://doh.test/dns-query") == "inconclusive"
