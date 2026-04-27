"""Tests for postern.mta.dnssec -- AD-bit checking via external resolvers."""

import logging
from unittest.mock import MagicMock, patch

import dns.exception
import dns.flags
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
