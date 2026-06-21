"""Tests for postern.mta.dnssec -- AD-bit checking via external resolvers."""

import logging
from unittest.mock import MagicMock, patch

import dns.exception
import dns.flags
import dns.name
import dns.resolver
import pytest

from postern.mta import dnssec


def _ad_response(ad: bool) -> MagicMock:
    resp = MagicMock()
    resp.flags = dns.flags.AD if ad else 0
    return resp


def _resolver_answer(ad: bool) -> MagicMock:
    """Build a mock dns.resolver.Resolver().resolve() return value with the AD bit configured."""
    answer = MagicMock()
    answer.response = _ad_response(ad)
    return answer


def _soa_resolver(*, ad: bool, nodata: bool) -> MagicMock:
    """Resolver mock mirroring a validating resolver's SOA behaviour.

    nodata=True  -> NODATA: raise NoAnswer on a default (raise_on_no_answer=True)
                    query; return an Answer carrying the AD-flagged response when
                    the caller passes raise_on_no_answer=False.
    nodata=False -> normal ANSWER: always return the Answer.
    """
    resolver = MagicMock()

    def _resolve(name, rdtype, *a, raise_on_no_answer=True, **kw):
        if nodata and raise_on_no_answer:
            raise dns.resolver.NoAnswer(response=_ad_response(ad))
        return _resolver_answer(ad)

    resolver.resolve.side_effect = _resolve
    return resolver


def _nxdomain_resolver(*, ad: bool, empty: bool = False) -> MagicMock:
    resolver = MagicMock()
    name = dns.name.from_text("sub.example.com.")

    def _resolve(qname, rdtype, *a, **kw):
        responses = {} if empty else {name: _ad_response(ad)}
        raise dns.resolver.NXDOMAIN(qnames=[name], responses=responses)

    resolver.resolve.side_effect = _resolve
    return resolver


# _soa_response ========================================================================================================
class TestSoaResponse:

    def test_apex_answer_returns_response_with_ad(self):
        resolver = _soa_resolver(ad=True, nodata=False)
        resp = dnssec._soa_response(resolver, "example.com")
        assert bool(resp.flags & dns.flags.AD) is True

    def test_signed_nodata_subdomain_returns_response_with_ad(self):
        # The bug: a validating resolver raises NoAnswer here, but the AD bit is
        # on the response. _soa_response must read it via raise_on_no_answer=False.
        resolver = _soa_resolver(ad=True, nodata=True)
        resp = dnssec._soa_response(resolver, "sub.example.com")
        assert bool(resp.flags & dns.flags.AD) is True

    def test_unsigned_nodata_returns_response_without_ad(self):
        resolver = _soa_resolver(ad=False, nodata=True)
        resp = dnssec._soa_response(resolver, "sub.example.com")
        assert bool(resp.flags & dns.flags.AD) is False

    def test_signed_nxdomain_returns_response_with_ad(self):
        resolver = _nxdomain_resolver(ad=True)
        resp = dnssec._soa_response(resolver, "sub.example.com")
        assert bool(resp.flags & dns.flags.AD) is True

    def test_unsigned_nxdomain_returns_response_without_ad(self):
        resolver = _nxdomain_resolver(ad=False)
        resp = dnssec._soa_response(resolver, "sub.example.com")
        assert bool(resp.flags & dns.flags.AD) is False

    def test_nxdomain_without_responses_propagates(self):
        resolver = _nxdomain_resolver(ad=True, empty=True)
        with pytest.raises(dns.resolver.NXDOMAIN):
            dnssec._soa_response(resolver, "sub.example.com")

    def test_nxdomain_reads_ad_off_the_queried_name(self):
        # Defensive: if a resolver captured multiple denials (search expansion),
        # read AD off the entry for the queried name, not an arbitrary one. The
        # WRONG (AD-unset) entry is inserted first so `next(iter(...))` would fail.
        queried = dns.name.from_text("sub.example.com")
        other = dns.name.from_text("sub.example.com.search.example.")
        responses = {other: _ad_response(False), queried: _ad_response(True)}
        resolver = MagicMock()
        resolver.resolve.side_effect = dns.resolver.NXDOMAIN(qnames=list(responses), responses=responses)
        resp = dnssec._soa_response(resolver, "sub.example.com")
        assert bool(resp.flags & dns.flags.AD) is True

    def test_transient_servfail_propagates(self):
        resolver = MagicMock()
        resolver.resolve.side_effect = dns.resolver.NoNameservers()
        with pytest.raises(dns.exception.DNSException):
            dnssec._soa_response(resolver, "example.com")


# check ================================================================================================================
class TestCheck:

    def test_passes_when_two_resolvers_set_ad(self):
        with patch.object(dnssec.dns.query, "udp") as mock_udp:
            mock_udp.side_effect = [_ad_response(True), _ad_response(True), _ad_response(False)]
            failures = dnssec.check("postern.example.com")
        assert failures == []

    def test_passes_when_all_three_resolvers_set_ad(self):
        with patch.object(dnssec.dns.query, "udp") as mock_udp:
            mock_udp.side_effect = [_ad_response(True), _ad_response(True), _ad_response(True)]
            failures = dnssec.check("postern.example.com")
        assert failures == []

    def test_fails_when_only_one_resolver_sets_ad(self):
        with patch.object(dnssec.dns.query, "udp") as mock_udp:
            mock_udp.side_effect = [_ad_response(True), _ad_response(False), _ad_response(False)]
            failures = dnssec.check("postern.example.com")
        assert failures
        assert any("AD bit set on 1 of 3" in f for f in failures)

    def test_fails_when_no_resolver_sets_ad(self):
        with patch.object(dnssec.dns.query, "udp") as mock_udp:
            mock_udp.side_effect = [_ad_response(False), _ad_response(False), _ad_response(False)]
            failures = dnssec.check("postern.example.com")
        assert failures

    def test_handles_resolver_timeout_as_failure(self):
        with patch.object(dnssec.dns.query, "udp") as mock_udp:
            mock_udp.side_effect = [
                _ad_response(True),
                dns.exception.Timeout(),
                dns.exception.Timeout(),
            ]
            failures = dnssec.check("postern.example.com")
        assert failures
        assert any("timeout" in f.lower() for f in failures)

    def test_passes_when_two_resolvers_set_ad_and_one_times_out(self):
        with patch.object(dnssec.dns.query, "udp") as mock_udp:
            mock_udp.side_effect = [_ad_response(True), _ad_response(True), dns.exception.Timeout()]
            failures = dnssec.check("postern.example.com")
        assert failures == []

    def test_default_resolvers_are_validating_publics(self):
        # Smoke test that we picked sane defaults; all three are widely-recognised
        # validating resolvers operated by independent organisations.
        assert dnssec.PUBLIC_VALIDATING_RESOLVERS == ("1.1.1.1", "9.9.9.9", "8.8.8.8")


# parse_setting ========================================================================================================
class TestParseSetting:

    @pytest.mark.parametrize("raw", [True, False])
    def test_bool_passes_through(self, raw):
        assert dnssec.parse_setting(raw) is raw

    def test_none_is_auto(self):
        assert dnssec.parse_setting(None) == "auto"

    @pytest.mark.parametrize("raw", ["true", "True", "TRUE", "1", "yes", "YES", "on", "On"])
    def test_truthy_strings(self, raw):
        assert dnssec.parse_setting(raw) is True

    @pytest.mark.parametrize("raw", ["false", "False", "FALSE", "0", "no", "NO", "off", "Off"])
    def test_falsy_strings(self, raw):
        assert dnssec.parse_setting(raw) is False

    @pytest.mark.parametrize("raw", ["auto", "AUTO", "Auto", "", "  ", " auto  "])
    def test_auto_strings(self, raw):
        assert dnssec.parse_setting(raw) == "auto"

    @pytest.mark.parametrize("raw", ["garbage", "maybe", "yes please", "0.0"])
    def test_invalid_string_raises(self, raw):
        with pytest.raises(ValueError, match="invalid MTA_REQUIRE_DNSSEC value"):
            dnssec.parse_setting(raw)

    @pytest.mark.parametrize("raw", [42, 0.0, object(), [], {}])
    def test_invalid_type_raises(self, raw):
        with pytest.raises(ValueError, match="invalid MTA_REQUIRE_DNSSEC type"):
            dnssec.parse_setting(raw)


# resolve_required =====================================================================================================
class TestResolveRequiredPassthrough:

    def test_true_passes_through_without_dns_calls(self):
        with patch.object(dnssec, "check") as mock_check:
            assert dnssec.resolve_required(True, "example.com") is True
        mock_check.assert_not_called()

    def test_false_passes_through_without_dns_calls(self):
        with patch.object(dnssec, "check") as mock_check:
            assert dnssec.resolve_required(False, "example.com") is False
        mock_check.assert_not_called()

    def test_true_passes_through_even_with_resolver(self):
        resolver = MagicMock()
        assert dnssec.resolve_required(True, "example.com", resolver=resolver) is True
        resolver.resolve.assert_not_called()


class TestResolveRequiredAutoLocal:

    def test_returns_true_when_ad_bit_set(self, caplog):
        resolver = MagicMock()
        resolver.resolve.return_value = _resolver_answer(ad=True)
        with caplog.at_level(logging.INFO, logger=dnssec.logger.name):
            result = dnssec.resolve_required("auto", "example.com", resolver=resolver)
        assert result is True
        assert any("is signed" in r.message and "Enforcing" in r.message for r in caplog.records)

    def test_returns_false_when_ad_bit_unset(self, caplog):
        resolver = MagicMock()
        resolver.resolve.return_value = _resolver_answer(ad=False)
        with caplog.at_level(logging.WARNING, logger=dnssec.logger.name):
            result = dnssec.resolve_required("auto", "example.com", resolver=resolver)
        assert result is False
        assert any("is unsigned" in r.message and "Not enforcing" in r.message for r in caplog.records)

    def test_retries_on_transient_dns_exception_then_succeeds(self, monkeypatch):
        resolver = MagicMock()
        resolver.resolve.side_effect = [
            dns.exception.DNSException("warming up"),
            dns.exception.DNSException("still warming"),
            _resolver_answer(ad=True),
        ]
        sleep_calls: list[float] = []
        monkeypatch.setattr(dnssec.time, "sleep", lambda s: sleep_calls.append(s))
        # Virtual clock so the deadline doesn't elapse in real time.
        ticks = iter([0.0, 0.1, 0.2, 0.3, 0.4])
        monkeypatch.setattr(dnssec.time, "monotonic", lambda: next(ticks))

        result = dnssec.resolve_required(
            "auto",
            "example.com",
            resolver=resolver,
            deadline_s=10.0,
            poll_interval_s=0.5,
        )
        assert result is True
        assert sleep_calls, "expected at least one retry"
        # All sleeps used the configured poll_interval_s, not wall-clock-meaningful values.
        assert all(s == 0.5 for s in sleep_calls)
        assert resolver.resolve.call_count == 3

    def test_returns_false_when_deadline_elapses_with_only_exceptions(self, monkeypatch, caplog):
        resolver = MagicMock()
        resolver.resolve.side_effect = dns.exception.DNSException("SERVFAIL forever")
        monkeypatch.setattr(dnssec.time, "sleep", lambda _s: None)
        # Virtual clock that jumps well past the deadline on the second tick.
        ticks = iter([0.0, 9999.0, 9999.0, 9999.0])
        monkeypatch.setattr(dnssec.time, "monotonic", lambda: next(ticks))

        with caplog.at_level(logging.WARNING, logger=dnssec.logger.name):
            result = dnssec.resolve_required(
                "auto",
                "example.com",
                resolver=resolver,
                deadline_s=30.0,
            )
        assert result is False
        assert any("SOA lookup" in r.message and "failed" in r.message for r in caplog.records)


class TestResolveRequiredAutoExternal:

    def test_returns_true_when_consensus_passes(self, caplog):
        with patch.object(dnssec, "check", return_value=[]) as mock_check, \
             caplog.at_level(logging.INFO, logger=dnssec.logger.name):
            result = dnssec.resolve_required("auto", "example.com")
        mock_check.assert_called_once_with("example.com")
        assert result is True
        assert any("consensus" in r.message and "Enforcing" in r.message for r in caplog.records)

    def test_returns_false_when_consensus_fails_completely(self, caplog):
        failures = ["DNSSEC example.com: insufficient consensus (AD bit set on 0 of 3)."]
        with patch.object(dnssec, "check", return_value=failures), \
             caplog.at_level(logging.WARNING, logger=dnssec.logger.name):
            result = dnssec.resolve_required("auto", "example.com")
        assert result is False
        assert any("insufficient consensus" in r.message for r in caplog.records)

    def test_returns_false_when_consensus_is_one_of_three(self, caplog):
        # Mixed consensus: check() already returns failures in this case; resolve_required
        # treats any non-empty failure list as "not signed".
        failures = ["DNSSEC example.com: insufficient consensus (AD bit set on 1 of 3)."]
        with patch.object(dnssec, "check", return_value=failures), \
             caplog.at_level(logging.WARNING, logger=dnssec.logger.name):
            result = dnssec.resolve_required("auto", "example.com")
        assert result is False
