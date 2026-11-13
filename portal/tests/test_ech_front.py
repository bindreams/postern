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
    # dnspython >= 2.9 validates the ECHConfigList, so use a well-formed value (see VALID_ECH).
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


def _raw_reply(*rrs: tuple[int, bytes], owner: bytes = b"\xc0\x0c"):
    """A reply whose answer section holds the given (rrtype, rdata bytes) records verbatim,
    all owned by `owner` (wire form; default: a pointer to the question name)."""

    def build(query: dns.message.Message) -> bytes:
        head = bytearray(dns.message.make_response(query).to_wire())
        head[6:8] = struct.pack("!H", len(rrs))
        body = b"".join(
            owner + struct.pack("!HHIH", rrtype, dns.rdataclass.IN, 300, len(rdata)) + rdata for rrtype, rdata in rrs
        )
        return bytes(head) + body

    return build


def _answering(build, *, qname: str = "postern.test.", id_xor: int = 0):
    """Wrap `build` so the reply is addressed to another question name / query id."""

    def wrapped(query: dns.message.Message) -> bytes:
        other = dns.message.make_query(qname, dns.rdatatype.HTTPS, id=query.id ^ id_xor)
        return build(other)

    return wrapped


def _mangled(build, mangle):
    """Wrap `build` so the reply wire (still addressed to the real query) is passed through `mangle`."""

    def wrapped(query: dns.message.Message) -> bytes:
        return mangle(build(query))

    return wrapped


def _wire_of(build) -> bytes:
    return build(dns.message.make_query("postern.test.", dns.rdatatype.HTTPS))


def _assert_dnspython_rejects(build):
    """Guard: the case under test really is a reply dnspython refuses to parse."""
    with pytest.raises(dns.exception.FormError):
        dns.message.from_wire(_wire_of(build))


def _serve_doh(monkeypatch, body_for, *, status: int = 200):
    """Route check_apex_ech's real HTTP exchange through a mock httpx2 transport (in place of
    dnspython's own).

    `body_for(query)` returns the DNS reply wire for the parsed query (or raw bytes to
    serve verbatim, or raises to fail the transport)."""

    def handler(request: httpx2.Request) -> httpx2.Response:
        body = body_for(dns.message.from_wire(request.content))
        # A stream, like a real transport's: the client closes it after reading, which dnspython's
        # `response.elapsed` needs.
        return httpx2.Response(
            status, stream=httpx2.ByteStream(body), headers={"content-type": "application/dns-message"}
        )

    monkeypatch.setattr(dns.query, "_HTTPTransport", lambda **kw: httpx2.MockTransport(handler))


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


def test_absent_when_valid_ech_sits_beside_an_unrelated_bad_param(monkeypatch):
    # RFC 9460 s2.2: a malformed record makes the client discard the whole HTTPS RRset, so a
    # usable ech= in the same record is not served.
    build = _raw_reply((HTTPS_TYPE, _https_rdata_wire(ALPN_H2, ECH, BAD_IPV6HINT)))
    _assert_dnspython_rejects(build)
    _serve_doh(monkeypatch, build)
    assert ech.check_apex_ech("postern.test", DOH_URL) == "absent"


def test_absent_when_valid_ech_is_in_another_record_than_the_bad_one(monkeypatch):
    # Same RRset, so the rejected record takes the valid one down with it.
    build = _raw_reply(
        (HTTPS_TYPE, _https_rdata_wire(ALPN_H2, BAD_IPV6HINT)),
        (HTTPS_TYPE, _https_rdata_wire(ECH)),
    )
    _assert_dnspython_rejects(build)
    _serve_doh(monkeypatch, build)
    assert ech.check_apex_ech("postern.test", DOH_URL) == "absent"


def test_inconclusive_when_the_rejected_https_record_is_owned_by_an_unrelated_name(monkeypatch):
    # An HTTPS record for another name is not the RRset this query asked for.
    other = b"\x09elsewhere\x04test\x00"
    build = _raw_reply((HTTPS_TYPE, _https_rdata_wire(ALPN_H2, BAD_IPV6HINT)), owner=other)
    _assert_dnspython_rejects(build)
    _serve_doh(monkeypatch, build)
    assert ech.check_apex_ech("postern.test", DOH_URL) == "inconclusive"


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


def test_absent_when_svcparam_framing_overruns_the_record(monkeypatch):
    # A malformed SvcParam list is a rejected record of the answer RRset, whatever it would have held.
    rdata = struct.pack("!HB", 1, 0) + struct.pack("!HH", int(ParamKey.IPV6HINT), 40) + b"\x00" * 3
    build = _raw_reply((HTTPS_TYPE, rdata))
    _assert_dnspython_rejects(build)
    _serve_doh(monkeypatch, build)
    assert ech.check_apex_ech("postern.test", DOH_URL) == "absent"


def test_inconclusive_when_reply_is_truncated(monkeypatch):
    build = _mangled(_raw_reply((HTTPS_TYPE, _https_rdata_wire(ALPN_H2, ECH, BAD_IPV6HINT))), lambda wire: wire[:-5])
    _serve_doh(monkeypatch, build)
    assert ech.check_apex_ech("postern.test", DOH_URL) == "inconclusive"


def test_inconclusive_when_a_truncated_reply_still_shows_a_good_ech_record(monkeypatch):
    # The ech record parses, but the message framing is broken after it: the reply is not
    # trustworthy, so it must not read as a confirmed "present".
    build = _mangled(
        _raw_reply((HTTPS_TYPE, _https_rdata_wire(ALPN_H2, ECH)), (HTTPS_TYPE, _https_rdata_wire(ALPN_H2))),
        lambda wire: wire[:-3]
    )
    _assert_dnspython_rejects(build)
    _serve_doh(monkeypatch, build)
    assert ech.check_apex_ech("postern.test", DOH_URL) == "inconclusive"


def test_inconclusive_when_trailing_junk_follows_an_https_record_without_ech(monkeypatch):
    # dnspython reports TrailingJunk at the end of the last record; it must not be blamed
    # on that record's SvcParams.
    build = _mangled(_raw_reply((HTTPS_TYPE, _https_rdata_wire(ALPN_H2))), lambda wire: wire + b"\x00\x01")
    _assert_dnspython_rejects(build)
    _serve_doh(monkeypatch, build)
    assert ech.check_apex_ech("postern.test", DOH_URL) == "inconclusive"


def test_absent_when_the_last_param_of_the_last_record_is_an_unusable_ech(monkeypatch):
    # The rejection is reported at the very end of the record's rdata: still attributed to it.
    build = _raw_reply((HTTPS_TYPE, _https_rdata_wire(ALPN_H2, (int(ParamKey.ECH), b"\x00\x09abc"))))
    _assert_dnspython_rejects(build)
    _serve_doh(monkeypatch, build)
    assert ech.check_apex_ech("postern.test", DOH_URL) == "absent"


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


# Reply must answer our question =======================================================================================
_ECH_REPLY = _reply_with(_https_rdata({ParamKey.ECH: GenericParam(VALID_ECH)}))
_REJECTED_ECH_REPLY = _raw_reply((HTTPS_TYPE, _https_rdata_wire(ECH, BAD_IPV6HINT)))


@pytest.mark.parametrize(
    "build", [
        _answering(_ECH_REPLY, qname="elsewhere.test."),
        _answering(_ECH_REPLY, id_xor=1),
        _answering(_REJECTED_ECH_REPLY, qname="elsewhere.test."),
        _answering(_REJECTED_ECH_REPLY, id_xor=1),
    ],
    ids=["parsed-other-name", "parsed-other-id", "rejected-other-name", "rejected-other-id"]
)
def test_inconclusive_when_reply_does_not_answer_our_question(monkeypatch, build):
    # An ech= in a reply to some other query says nothing about this domain.
    _serve_doh(monkeypatch, build)
    assert ech.check_apex_ech("postern.test", DOH_URL) == "inconclusive"


# Transport configuration ==============================================================================================
def _spy_on_https(monkeypatch):
    """Capture what check_apex_ech hands dns.query.https; the spy fails the exchange, so no network."""
    seen = {}

    def spy(query, where, **kwargs):
        seen.update(kwargs, where=where)
        raise httpx2.ConnectError("spy")

    monkeypatch.setattr(dns.query, "https", spy)
    return seen


def _record_transport(monkeypatch):
    """Replace dnspython's transport class with a recorder; returns (kwargs it got, instances built)."""
    seen: dict = {}
    built: list = []

    def make(**kwargs):
        seen.update(kwargs)
        built.append(httpx2.MockTransport(lambda request: httpx2.Response(500)))
        return built[-1]

    monkeypatch.setattr(dns.query, "_HTTPTransport", make)
    return seen, built


def test_exchange_uses_dnspythons_transport_and_ignores_the_environment(monkeypatch):
    # Env proxy and SSL_CERT_* must not steer the lookup: trust_env=False on both client and transport.
    seen = _spy_on_https(monkeypatch)
    transport_kwargs, built = _record_transport(monkeypatch)
    assert ech.check_apex_ech("postern.test", DOH_URL, timeout=2.5) == "inconclusive"
    session = seen["session"]
    assert session.trust_env is False
    assert session._transport is built[0]
    assert transport_kwargs["trust_env"] is False
    assert seen["where"] == DOH_URL
    assert seen["timeout"] == 2.5


def test_ssl_cert_file_from_the_environment_is_ignored(monkeypatch, tmp_path):
    # Behavioural: httpx2 fails building the SSL context from a missing SSL_CERT_FILE if it reads it.
    monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "missing.pem"))
    seen = _spy_on_https(monkeypatch)
    assert ech.check_apex_ech("postern.test", DOH_URL) == "inconclusive"
    assert "session" in seen  # the exchange was reached, so the transport was built


@pytest.mark.parametrize(
    "url,bootstrap", [
        ("https://192.0.2.53/dns-query", "192.0.2.53"),
        ("https://[2001:db8::53]:8443/dns-query", "2001:db8::53"),
        (DOH_URL, None),
    ],
    ids=["ipv4-literal", "ipv6-literal", "hostname"]
)
def test_ip_literal_doh_host_is_bootstrapped_without_resolv_conf(monkeypatch, url, bootstrap):
    # Mirrors dns.query.https: an IP-literal host needs no name resolution, so no resolver.
    _spy_on_https(monkeypatch)
    transport_kwargs, _ = _record_transport(monkeypatch)
    ech.check_apex_ech("postern.test", url)
    assert transport_kwargs.get("bootstrap_address") == bootstrap


# Degradation paths ====================================================================================================
def test_lost_doh_backend_logs_error_and_is_inconclusive(monkeypatch, caplog):
    # A dropped DoH backend (NoDOH) is a systemic regression, not an ordinary blip:
    # inconclusive, but logged at ERROR so it is visible.
    monkeypatch.setattr(dns.query, "have_doh", False)
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

    _serve_doh(monkeypatch, _ECH_REPLY)
    monkeypatch.setattr(ech, "_https_rrs", lambda message: [Boom()])
    assert ech.check_apex_ech("postern.test", DOH_URL) == "inconclusive"


def test_inconclusive_when_rdata_missing_params_attr(monkeypatch):
    # A dnspython shape change (renamed/removed .params) must degrade to inconclusive
    # (not a false confirmed "absent"). Direct attribute access lets the AttributeError
    # reach check_apex_ech's outer try/except.
    class NoParams:
        pass  # no .params attribute

    _serve_doh(monkeypatch, _ECH_REPLY)
    monkeypatch.setattr(ech, "_https_rrs", lambda message: [NoParams()])
    assert ech.check_apex_ech("postern.test", DOH_URL) == "inconclusive"


@pytest.mark.parametrize("error", [AttributeError("no _HTTPTransport"), TypeError("unexpected keyword")])
def test_unbuildable_dnspython_transport_logs_error_and_is_inconclusive(monkeypatch, caplog, error):
    # dns.query._HTTPTransport is private: if it vanishes or changes shape, every check would
    # silently degrade. That is a systemic regression, logged at ERROR like a lost backend.
    def broken(**kwargs):
        raise error

    monkeypatch.setattr(dns.query, "_HTTPTransport", broken)
    caplog.set_level(logging.ERROR, logger="postern.ech")
    assert ech.check_apex_ech("postern.test", DOH_URL) == "inconclusive"
    assert "DoH backend unavailable" in caplog.text
    assert repr(error) in caplog.text


def test_failed_exchange_logs_its_cause_at_warning(monkeypatch, caplog):

    def down(query):
        raise httpx2.ConnectError("doh down")

    _serve_doh(monkeypatch, down)
    caplog.set_level(logging.WARNING, logger="postern.ech")
    assert ech.check_apex_ech("postern.test", DOH_URL) == "inconclusive"
    assert "doh down" in caplog.text


def test_reply_without_https_records_logs_why_it_is_inconclusive(monkeypatch, caplog):
    _serve_doh(monkeypatch, lambda query: dns.message.make_response(query).to_wire())
    caplog.set_level(logging.DEBUG, logger="postern.ech")
    assert ech.check_apex_ech("postern.test", DOH_URL) == "inconclusive"
    assert "postern.test: reply has no HTTPS records (rcode=0); inconclusive" in caplog.text


@pytest.mark.parametrize(
    "build,verdict", [
        (_raw_reply((HTTPS_TYPE, _https_rdata_wire(ALPN_H2, BAD_IPV6HINT))), "absent"),
        (_raw_reply((int(dns.rdatatype.A), b"\x01\x02\x03")), "inconclusive"),
        (_answering(_REJECTED_ECH_REPLY, id_xor=1), "inconclusive"),
    ],
    ids=["rejected-https", "bad-elsewhere", "other-query"]
)
def test_unparsed_reply_logs_its_verdict_and_reason(monkeypatch, caplog, build, verdict):
    _serve_doh(monkeypatch, build)
    caplog.set_level(logging.DEBUG, logger="postern.ech")
    assert ech.check_apex_ech("postern.test", DOH_URL) == verdict
    assert f"unparsed reply classified {verdict}: " in caplog.text
