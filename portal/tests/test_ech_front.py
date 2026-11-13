"""Tests for the DoH apex-HTTPS ech= front check."""
from __future__ import annotations

import logging
import struct

import dns.exception
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

HTTPS_TYPE = int(dns.rdatatype.HTTPS)
BAD_IPV6HINT = (int(ParamKey.IPV6HINT), b"\x00" * 3)  # not a multiple of 16: dnspython rejects the reply
ALPN_H2 = (int(ParamKey.ALPN), b"\x02h2")
ECH = (int(ParamKey.ECH), VALID_ECH)


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


# Wire helpers =========================================================================================================
def _https_rdata(params: dict) -> HTTPS:
    return HTTPS(dns.rdataclass.IN, dns.rdatatype.HTTPS, 1, dns.name.root, params)


def _reply_with(rdata: HTTPS):

    def build(query: dns.message.Message) -> bytes:
        reply = dns.message.make_response(query)
        reply.answer.append(dns.rrset.from_rdata("postern.test.", 300, rdata))
        return reply.to_wire()

    return build


def _https_rdata_wire(*params: tuple[int, bytes]) -> bytes:
    """Raw HTTPS rdata (priority 1, target "."), SvcParams written as given: no validation."""
    return struct.pack("!HB", 1, 0) + b"".join(struct.pack("!HH", key, len(value)) + value for key, value in params)


def _raw_reply(*rrs: tuple[int, bytes]):
    """A reply whose answer section holds the given (rrtype, rdata bytes) records verbatim."""

    def build(query: dns.message.Message) -> bytes:
        head = bytearray(dns.message.make_response(query).to_wire())
        head[6:8] = struct.pack("!H", len(rrs))
        body = b"".join(
            b"\xc0\x0c" + struct.pack("!HHIH", rrtype, dns.rdataclass.IN, 300, len(rdata)) + rdata
            for rrtype, rdata in rrs
        )
        return bytes(head) + body

    return build


def _wire_of(build) -> bytes:
    return build(dns.message.make_query("postern.test.", dns.rdatatype.HTTPS))


def _assert_dnspython_rejects(build):
    """Guard: the case under test really is a reply dnspython refuses to parse."""
    with pytest.raises(dns.exception.FormError):
        dns.message.from_wire(_wire_of(build))


def _serve_doh(monkeypatch, body_for, *, status: int = 200):
    """Route check_apex_ech's real HTTP exchange through a mock httpx2 transport.

    `body_for(query)` returns the DNS reply wire for the parsed query (or raw bytes to
    serve verbatim, or raises to fail the transport). Only the network is replaced: the
    request, the status check and the reply parsing all run for real."""
    real_client = httpx2.Client

    def handler(request: httpx2.Request) -> httpx2.Response:
        body = body_for(dns.message.from_wire(request.content))
        return httpx2.Response(status, content=body, headers={"content-type": "application/dns-message"})

    monkeypatch.setattr(httpx2, "Client", lambda **kw: real_client(**kw, transport=httpx2.MockTransport(handler)))


# Classification on real wire bytes ====================================================================================
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
    build = _raw_reply((HTTPS_TYPE, _https_rdata_wire((int(ParamKey.ECH), value))))
    _assert_dnspython_rejects(build)
    _serve_doh(monkeypatch, build)
    assert ech.check_apex_ech("postern.test", DOH_URL) == "absent"


def test_present_when_valid_ech_sits_beside_an_unrelated_bad_param(monkeypatch):
    # dnspython rejects the whole reply over the ipv6hint, but a usable ech= is there.
    build = _raw_reply((HTTPS_TYPE, _https_rdata_wire(ALPN_H2, ECH, BAD_IPV6HINT)))
    _assert_dnspython_rejects(build)
    _serve_doh(monkeypatch, build)
    assert ech.check_apex_ech("postern.test", DOH_URL) == "present"


def test_present_when_valid_ech_is_in_another_record_than_the_bad_one(monkeypatch):
    build = _raw_reply(
        (HTTPS_TYPE, _https_rdata_wire(ALPN_H2, BAD_IPV6HINT)),
        (HTTPS_TYPE, _https_rdata_wire(ECH)),
    )
    _assert_dnspython_rejects(build)
    _serve_doh(monkeypatch, build)
    assert ech.check_apex_ech("postern.test", DOH_URL) == "present"


def test_absent_when_an_unrelated_bad_param_and_no_ech(monkeypatch):
    build = _raw_reply((HTTPS_TYPE, _https_rdata_wire(ALPN_H2, BAD_IPV6HINT)))
    _assert_dnspython_rejects(build)
    _serve_doh(monkeypatch, build)
    assert ech.check_apex_ech("postern.test", DOH_URL) == "absent"


def test_inconclusive_when_the_reply_is_bad_outside_any_https_record(monkeypatch):
    # A 3-byte A record makes dnspython reject the reply; the HTTPS record beside it is
    # fine and has no ech, so nothing explains the failure as "no ech served".
    build = _raw_reply((HTTPS_TYPE, _https_rdata_wire(ALPN_H2)), (int(dns.rdatatype.A), b"\x01\x02\x03"))
    _assert_dnspython_rejects(build)
    _serve_doh(monkeypatch, build)
    assert ech.check_apex_ech("postern.test", DOH_URL) == "inconclusive"


def test_inconclusive_when_only_a_non_https_record_is_bad(monkeypatch):
    build = _raw_reply((int(dns.rdatatype.A), b"\x01\x02\x03"))
    _assert_dnspython_rejects(build)
    _serve_doh(monkeypatch, build)
    assert ech.check_apex_ech("postern.test", DOH_URL) == "inconclusive"


def test_inconclusive_when_svcparam_framing_overruns_the_record(monkeypatch):
    # A param claiming more bytes than the record holds: ech= (if any) cannot be located.
    rdata = struct.pack("!HB", 1, 0) + struct.pack("!HH", int(ParamKey.IPV6HINT), 40) + b"\x00" * 3
    build = _raw_reply((HTTPS_TYPE, rdata))
    _assert_dnspython_rejects(build)
    _serve_doh(monkeypatch, build)
    assert ech.check_apex_ech("postern.test", DOH_URL) == "inconclusive"


def test_inconclusive_when_reply_is_truncated(monkeypatch):
    wire = _wire_of(_raw_reply((HTTPS_TYPE, _https_rdata_wire(ALPN_H2, ECH, BAD_IPV6HINT))))
    _serve_doh(monkeypatch, lambda query: wire[:-5])
    assert ech.check_apex_ech("postern.test", DOH_URL) == "inconclusive"


def test_inconclusive_when_reply_is_shorter_than_a_dns_header(monkeypatch):
    _serve_doh(monkeypatch, lambda query: b"\x00\x01\x80")
    assert ech.check_apex_ech("postern.test", DOH_URL) == "inconclusive"


def test_inconclusive_when_reply_is_not_a_dns_message(monkeypatch):
    # A captive portal / broken resolver answering 200 with a non-DNS body says nothing
    # about the record, so it must not read as a confirmed "absent".
    _serve_doh(monkeypatch, lambda query: b"<html>login required</html>")
    assert ech.check_apex_ech("postern.test", DOH_URL) == "inconclusive"


def test_inconclusive_when_doh_returns_an_error_status(monkeypatch):
    _serve_doh(monkeypatch, lambda query: b"", status=500)
    assert ech.check_apex_ech("postern.test", DOH_URL) == "inconclusive"


def test_inconclusive_when_doh_transport_fails(monkeypatch):

    def down(query):
        raise httpx2.ConnectError("doh down")

    _serve_doh(monkeypatch, down)
    assert ech.check_apex_ech("postern.test", DOH_URL) == "inconclusive"


def test_inconclusive_when_no_https_record(monkeypatch):
    _serve_doh(monkeypatch, lambda query: dns.message.make_response(query).to_wire())
    assert ech.check_apex_ech("postern.test", DOH_URL) == "inconclusive"


# Degradation paths ====================================================================================================
def test_lost_doh_backend_logs_error_and_is_inconclusive(monkeypatch, caplog):
    # A dropped DoH backend (NoDOH) is a systemic regression, not an ordinary blip:
    # inconclusive, but logged at ERROR so it is visible.
    def no_backend(*a, **k):
        raise dns.query.NoDOH("DoH not available")

    monkeypatch.setattr(ech, "_fetch_wire", no_backend)
    caplog.set_level(logging.ERROR, logger="postern.ech")
    assert ech.check_apex_ech("postern.test", DOH_URL) == "inconclusive"
    assert "DoH backend unavailable" in caplog.text


def test_inconclusive_when_param_parsing_raises(monkeypatch):
    # A parse-shape surprise inside the rr loop must degrade to inconclusive, not
    # propagate (check_apex_ech's contract is "never raises").
    class Boom:

        @property
        def params(self):
            raise RuntimeError("unexpected rdata shape")

    monkeypatch.setattr(ech, "_fetch_wire", lambda *a, **k: b"")
    monkeypatch.setattr(ech, "_parse_https_rrs", lambda wire: [Boom()])
    assert ech.check_apex_ech("postern.test", DOH_URL) == "inconclusive"


def test_inconclusive_when_rdata_missing_params_attr(monkeypatch):
    # A dnspython shape change (renamed/removed .params) must degrade to inconclusive
    # (not a false confirmed "absent"). Direct attribute access lets the AttributeError
    # reach check_apex_ech's outer try/except.
    class NoParams:
        pass  # no .params attribute

    monkeypatch.setattr(ech, "_fetch_wire", lambda *a, **k: b"")
    monkeypatch.setattr(ech, "_parse_https_rrs", lambda wire: [NoParams()])
    assert ech.check_apex_ech("postern.test", DOH_URL) == "inconclusive"
