"""Tests for postern.mta.dnssec -- AD-bit checking via external resolvers."""

from unittest.mock import MagicMock, patch

import dns.exception
import dns.flags

from postern.mta import dnssec


def _ad_response(ad: bool) -> MagicMock:
    resp = MagicMock()
    resp.flags = dns.flags.AD if ad else 0
    return resp


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
