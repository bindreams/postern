"""Tests for postern.mta.dns -- DNS record rendering + verification."""

from unittest.mock import MagicMock, patch

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rdatatype
import dns.resolver
import pytest

from postern.mta import dns as mta_dns

# Fixtures =============================================================================================================
DOMAIN = "postern.example.com"
ADMIN = "admin@elsewhere.example"
PUBKEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAabcdef"


def _fake_resolver(answers: dict[tuple[str, str], object]) -> MagicMock:
    """Build a Resolver mock whose .resolve(name, rdtype) returns canned answers.

    `answers` is keyed by (name, rdtype). Value is either:
      - a list of MagicMock-shaped records (each carrying .exchange, .strings, .address, .target)
      - an exception class to raise

    Returns a bare ``MagicMock`` (not ``spec=Resolver``) so the test can freely
    set ``resolver.resolve.side_effect`` to drive different scenarios.
    """
    resolver = MagicMock()

    def _resolve(name, rdtype, *_, **__):
        key = (str(name).rstrip("."), rdtype)
        result = answers.get(key)
        if result is None:
            raise dns.resolver.NXDOMAIN()
        if isinstance(result, type) and issubclass(result, BaseException):
            raise result()
        records = list(result)  # ty: type-narrowed away from `object`
        ans = MagicMock()
        ans.__iter__.return_value = iter(records)
        return ans

    resolver.resolve.side_effect = _resolve
    return resolver


def _txt_rec(value: str) -> MagicMock:
    rec = MagicMock()
    rec.strings = [value.encode("utf-8")]
    return rec


def _mx_rec(target: str) -> MagicMock:
    rec = MagicMock()
    rec.exchange = dns.name.from_text(target)
    return rec


def _a_rec(ip: str) -> MagicMock:
    rec = MagicMock()
    rec.address = ip
    return rec


def _ptr_rec(target: str) -> MagicMock:
    rec = MagicMock()
    rec.target = dns.name.from_text(target)
    return rec


# expected_records =====================================================================================================
class TestExpectedRecords:

    def test_includes_all_record_types(self):
        records = mta_dns.expected_records(DOMAIN, {"postern-2026-04": PUBKEY}, admin_email=ADMIN)

        for label in ("MX", "A", "PTR", "SPF", "DMARC", "MTA-STS", "TLS-RPT", "DKIM"):
            assert label in records, f"missing {label}"

    def test_mx_points_at_mail_subdomain(self):
        records = mta_dns.expected_records(DOMAIN, {}, admin_email=ADMIN)
        assert f"10 mail.{DOMAIN}." in records["MX"][0]

    def test_dmarc_uses_admin_email_with_strict_alignment(self):
        records = mta_dns.expected_records(DOMAIN, {}, admin_email=ADMIN)
        dmarc = records["DMARC"][0]
        assert "p=reject" in dmarc
        assert "adkim=s" in dmarc
        assert "aspf=s" in dmarc
        assert f"rua=mailto:{ADMIN}" in dmarc
        assert f"ruf=mailto:{ADMIN}" in dmarc

    def test_dmarc_falls_back_to_postmaster_when_admin_email_blank(self):
        records = mta_dns.expected_records(DOMAIN, {}, admin_email="")
        assert f"postmaster@{DOMAIN}" in records["DMARC"][0]

    def test_dkim_emits_one_line_per_selector(self):
        records = mta_dns.expected_records(
            DOMAIN,
            {
                "postern-2026-04": "OLDKEY",
                "postern-2026-10": "NEWKEY",
            },
            admin_email=ADMIN,
        )
        assert len(records["DKIM"]) == 2
        joined = "\n".join(records["DKIM"])
        assert "postern-2026-04._domainkey" in joined
        assert "postern-2026-10._domainkey" in joined
        assert "p=OLDKEY" in joined
        assert "p=NEWKEY" in joined

    def test_dkim_placeholder_when_no_keys_yet(self):
        records = mta_dns.expected_records(DOMAIN, {}, admin_email=ADMIN)
        assert any("postern mta show-dns" in line for line in records["DKIM"])

    def test_a_records_use_provided_ips(self):
        records = mta_dns.expected_records(
            DOMAIN, {}, admin_email=ADMIN, server_ip="203.0.113.10", nginx_ip="203.0.113.20"
        )
        joined = "\n".join(records["A"])
        assert "203.0.113.10" in joined
        assert "203.0.113.20" in joined

    def test_ptr_uses_reverse_of_server_ip(self):
        records = mta_dns.expected_records(DOMAIN, {}, admin_email=ADMIN, server_ip="203.0.113.10")
        ptr = records["PTR"][0]
        assert "in-addr.arpa" in ptr
        assert f"mail.{DOMAIN}." in ptr


# verify ===============================================================================================================
def _good_answers(*, ip="203.0.113.10", pubkey=PUBKEY):
    """A complete, passing answer set."""
    rev = "10.113.0.203.in-addr.arpa"
    sts_id = "20260427"
    return {
        (DOMAIN, "MX"): [_mx_rec(f"mail.{DOMAIN}.")],
        (f"mail.{DOMAIN}", "A"): [_a_rec(ip)],
        (f"mta-sts.{DOMAIN}", "A"): [_a_rec(ip)],
        (rev, "PTR"): [_ptr_rec(f"mail.{DOMAIN}.")],
        (DOMAIN, "TXT"): [_txt_rec("v=spf1 mx -all")],
        (f"_dmarc.{DOMAIN}", "TXT"): [_txt_rec(f"v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto:{ADMIN}")],
        (f"_mta-sts.{DOMAIN}", "TXT"): [_txt_rec(f"v=STSv1; id={sts_id}")],
        (f"_smtp._tls.{DOMAIN}", "TXT"): [_txt_rec(f"v=TLSRPTv1; rua=mailto:{ADMIN}")],
        (f"postern-2026-04._domainkey.{DOMAIN}", "TXT"): [_txt_rec(f"v=DKIM1; k=rsa; p={pubkey}")],
    }


class TestVerify:

    def test_pass_when_all_records_correct(self):
        resolver = _fake_resolver(_good_answers())
        with patch.object(mta_dns, "urllib") as mock_urllib:
            mock_urllib.request.urlopen.return_value.__enter__.return_value.read.return_value = (
                f"version: STSv1\nmode: enforce\nmx: mail.{DOMAIN}\nmax_age: 604800".encode()
            )
            mock_urllib.error = type("E", (), {"URLError": Exception, "HTTPError": Exception})
            failures = mta_dns.verify(
                DOMAIN,
                {"postern-2026-04": PUBKEY},
                admin_email=ADMIN,
                server_ip="203.0.113.10",
                resolver=resolver,
            )
        assert failures == [], f"unexpected failures: {failures}"

    def test_missing_mx_reports_failure(self):
        ans = _good_answers()
        del ans[(DOMAIN, "MX")]
        resolver = _fake_resolver(ans)
        failures = mta_dns.verify(DOMAIN, {}, admin_email=ADMIN, resolver=resolver)
        assert any("MX" in f and DOMAIN in f for f in failures)

    def test_wrong_mx_target_reports_failure(self):
        ans = _good_answers()
        ans[(DOMAIN, "MX")] = [_mx_rec(f"mx.elsewhere.example.")]
        resolver = _fake_resolver(ans)
        failures = mta_dns.verify(DOMAIN, {}, admin_email=ADMIN, resolver=resolver)
        assert any("MX" in f for f in failures)

    def test_dmarc_softfail_policy_reports_failure(self):
        ans = _good_answers()
        ans[(f"_dmarc.{DOMAIN}", "TXT")] = [_txt_rec("v=DMARC1; p=none; adkim=s; aspf=s")]
        resolver = _fake_resolver(ans)
        failures = mta_dns.verify(DOMAIN, {}, admin_email=ADMIN, resolver=resolver)
        assert any("DMARC" in f and "p=" in f for f in failures)

    def test_dmarc_relaxed_alignment_reports_failure(self):
        ans = _good_answers()
        ans[(f"_dmarc.{DOMAIN}", "TXT")] = [_txt_rec("v=DMARC1; p=reject; adkim=r; aspf=r")]
        resolver = _fake_resolver(ans)
        failures = mta_dns.verify(DOMAIN, {}, admin_email=ADMIN, resolver=resolver)
        assert any("adkim" in f for f in failures)
        assert any("aspf" in f for f in failures)

    def test_spf_softfail_reports_failure(self):
        ans = _good_answers()
        ans[(DOMAIN, "TXT")] = [_txt_rec("v=spf1 mx ~all")]
        resolver = _fake_resolver(ans)
        failures = mta_dns.verify(DOMAIN, {}, admin_email=ADMIN, resolver=resolver)
        assert any("SPF" in f for f in failures)

    def test_dkim_pubkey_mismatch_reports_failure(self):
        ans = _good_answers()
        resolver = _fake_resolver(ans)
        with patch.object(mta_dns, "urllib"):
            failures = mta_dns.verify(
                DOMAIN,
                {"postern-2026-04": "DIFFERENT-KEY"},
                admin_email=ADMIN,
                resolver=resolver,
            )
        assert any("DKIM" in f and "match" in f for f in failures)

    def test_missing_dkim_record_reports_failure(self):
        ans = _good_answers()
        del ans[(f"postern-2026-04._domainkey.{DOMAIN}", "TXT")]
        resolver = _fake_resolver(ans)
        with patch.object(mta_dns, "urllib"):
            failures = mta_dns.verify(
                DOMAIN,
                {"postern-2026-04": PUBKEY},
                admin_email=ADMIN,
                resolver=resolver,
            )
        assert any("DKIM" in f and "no TXT record" in f for f in failures)

    def test_require_dnssec_passes_when_ad_bit_set(self):
        ans = _good_answers()
        resolver = _fake_resolver(ans)
        soa_resp = MagicMock()
        soa_resp.flags = dns.flags.AD
        ans_soa = MagicMock()
        ans_soa.response = soa_resp
        resolver.resolve.side_effect = lambda name, rdtype, *a, **kw: (
            ans_soa if rdtype == "SOA" else _fake_resolver(ans).resolve(name, rdtype)
        )

    def test_require_dnssec_fails_when_ad_bit_missing(self):
        ans = _good_answers()
        resolver = _fake_resolver(ans)
        soa_resp = MagicMock()
        soa_resp.flags = 0
        ans_soa = MagicMock()
        ans_soa.response = soa_resp

        original = resolver.resolve.side_effect

        def _resolve(name, rdtype, *a, **kw):
            if rdtype == "SOA":
                return ans_soa
            return original(name, rdtype)

        resolver.resolve.side_effect = _resolve

        with patch.object(mta_dns, "urllib") as mock_urllib:
            mock_urllib.request.urlopen.return_value.__enter__.return_value.read.return_value = (
                f"version: STSv1\nmode: enforce\nmx: mail.{DOMAIN}".encode()
            )
            mock_urllib.error = type("E", (), {"URLError": Exception, "HTTPError": Exception})
            failures = mta_dns.verify(
                DOMAIN,
                {"postern-2026-04": PUBKEY},
                admin_email=ADMIN,
                server_ip="203.0.113.10",
                require_dnssec=True,
                resolver=resolver,
            )

        assert any("DNSSEC" in f for f in failures)


# DKIM-field parser ----------------------------------------------------------------------------------------------------
class TestParseDkimFields:

    def test_parses_typical_record(self):
        pairs = mta_dns._parse_dkim_fields("v=DKIM1; k=rsa; p=ABC123")
        assert ("v", "DKIM1") in pairs
        assert ("k", "rsa") in pairs
        assert ("p", "ABC123") in pairs

    def test_handles_extra_whitespace(self):
        pairs = mta_dns._parse_dkim_fields("  v=DKIM1 ;  p=ABC ; ")
        assert ("v", "DKIM1") in pairs
        assert ("p", "ABC") in pairs
