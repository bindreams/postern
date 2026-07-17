"""Tests for the DoH apex-HTTPS ech= front check."""
from __future__ import annotations

import logging
from types import SimpleNamespace

import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdatatype

from postern import ech


def test_doh_backend_available():
    # The DoH transport (h2/httpcore/httpx via the dnspython[doh] extra) must be
    # installed, or check_apex_ech silently degrades to always-"inconclusive".
    import dns._features
    assert dns._features.have("doh"), "dnspython[doh] extra (h2/httpcore/httpx) is not installed"


def test_has_ech_param_against_real_dnspython_rdata():
    # Exercise _has_ech_param against REAL dnspython HTTPS rdata (not a mock), so the
    # rr.params key type and the ech-value attribute shape are pinned to the library.
    with_ech = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.HTTPS, '1 . ech="AAAA"')
    without_ech = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.HTTPS, '1 . alpn="h2"')
    empty_ech = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.HTTPS, '1 . ech=""')
    assert ech._has_ech_param(with_ech) is True
    assert ech._has_ech_param(without_ech) is False
    # An empty ech="" param is "absent" per the spec -- pin the non-empty boundary.
    assert ech._has_ech_param(empty_ech) is False


def test_present_when_ech_param_has_bytes(monkeypatch):
    rr = SimpleNamespace(params={ech._ECH_PARAM_KEY: SimpleNamespace(ech=b"\x00\x01")})
    monkeypatch.setattr(ech, "_query_https_rrs", lambda *a, **k: [rr])
    assert ech.check_apex_ech("postern.test", "https://doh.test/dns-query") == "present"


def test_absent_when_https_record_has_no_ech(monkeypatch):
    rr = SimpleNamespace(params={})
    monkeypatch.setattr(ech, "_query_https_rrs", lambda *a, **k: [rr])
    assert ech.check_apex_ech("postern.test", "https://doh.test/dns-query") == "absent"


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
