"""Unit tests for the `postern doctor` check engine and rendering."""
from __future__ import annotations

import json
import socket
import ssl
from unittest.mock import MagicMock, patch

import dns.exception
import dns.flags
import dns.resolver
import pytest

from postern import doctor


# Fixtures =============================================================================================================
def _settings(**overrides) -> doctor.DoctorSettings:
    base = dict(
        domain="hole.example",
        public_ipv4="203.0.113.42",
        public_ipv6="2001:db8::42",
        admin_email="ops@example.com",
        tlsa_cert_hex=None,
        dkim_pubkey_by_selector={},
    )
    base.update(overrides)
    return doctor.DoctorSettings(**base)


def _ok(label: str, *, section: doctor.Section = doctor.EXTERNAL) -> doctor.CheckResult:
    return doctor.CheckResult(section=section, label=label, status="ok", detail="-> ok")


def _fail(label: str, *, section: doctor.Section = doctor.EXTERNAL, fix: str = "do the thing") -> doctor.CheckResult:
    return doctor.CheckResult(section=section, label=label, status="fail", detail="something is wrong", fix=fix)


# CheckResult / DoctorReport ===========================================================================================
class TestReport:

    def test_exit_code_zero_when_all_ok(self):
        report = doctor.DoctorReport(results=[_ok("a"), _ok("b")])
        assert report.exit_code == 0
        assert report.failures == []

    def test_exit_code_nonzero_when_any_fail(self):
        report = doctor.DoctorReport(results=[_ok("a"), _fail("b")])
        assert report.exit_code == 1
        assert len(report.failures) == 1


# DS check (delegates to mta.dnssec.check) =============================================================================
class TestDsCheck:

    def test_ok_when_dnssec_check_returns_empty(self):
        with patch.object(doctor.mta_dnssec, "check", return_value=[]):
            result = doctor.check_ds("hole.example")
        assert result.status == "ok"
        assert result.section == doctor.EXTERNAL
        assert "AD bit set" in result.detail

    def test_fail_when_dnssec_check_returns_failures(self):
        with patch.object(doctor.mta_dnssec, "check", return_value=["AD bit set on 0 of 3"]):
            result = doctor.check_ds("hole.example")
        assert result.status == "fail"
        assert "AD bit set on 0 of 3" in result.detail
        assert "DS records" in result.fix
        assert "registrar" in result.fix


# PTR check ============================================================================================================
class TestPtrCheck:

    def _resolver_with_ptr(self, target: str) -> dns.resolver.Resolver:
        r = MagicMock(spec=dns.resolver.Resolver)
        ans = MagicMock()
        ans.__iter__ = lambda self: iter([MagicMock(target=MagicMock(__str__=lambda s: target))])
        r.resolve.return_value = ans
        return r

    def test_ok_when_ptr_matches(self):
        r = self._resolver_with_ptr("mail.hole.example.")
        result = doctor.check_ptr("203.0.113.42", expected="mail.hole.example.", resolver=r)
        assert result.status == "ok"

    def test_ok_when_ptr_target_missing_trailing_dot(self):
        r = self._resolver_with_ptr("mail.hole.example")
        result = doctor.check_ptr("203.0.113.42", expected="mail.hole.example.", resolver=r)
        assert result.status == "ok"

    def test_fail_when_ptr_mismatches(self):
        r = self._resolver_with_ptr("wrong.example.")
        result = doctor.check_ptr("203.0.113.42", expected="mail.hole.example.", resolver=r)
        assert result.status == "fail"
        assert "PTR" in result.fix
        assert "VPS provider" in result.fix

    def test_fail_when_no_ptr(self):
        r = MagicMock(spec=dns.resolver.Resolver)
        r.resolve.side_effect = dns.resolver.NXDOMAIN()
        result = doctor.check_ptr("203.0.113.42", expected="mail.hole.example.", resolver=r)
        assert result.status == "fail"
        assert "no PTR record" in result.detail

    def test_fail_on_invalid_ip(self):
        result = doctor.check_ptr("not-an-ip", expected="mail.hole.example.")
        assert result.status == "fail"
        assert ".env" in result.fix

    def test_ptr_fix_mentions_v6_for_ipv6(self):
        r = MagicMock(spec=dns.resolver.Resolver)
        r.resolve.side_effect = dns.resolver.NXDOMAIN()
        result = doctor.check_ptr("2001:db8::42", expected="mail.hole.example.", resolver=r)
        assert "IPv6" in result.fix


# Postern-managed expectations =========================================================================================
class TestBuildPosternExpectations:

    def test_includes_apex_wildcard_mail_a(self):
        exps = doctor.build_postern_expectations(
            "hole.example",
            public_ipv4="203.0.113.42",
            public_ipv6=None,
            admin_email="ops@example.com",
            tlsa_cert_hex=None,
        )
        a_names = {e.name for e in exps if e.type == "A"}
        assert a_names == {"hole.example", "*.hole.example", "mail.hole.example"}

    def test_no_aaaa_when_no_v6(self):
        exps = doctor.build_postern_expectations(
            "hole.example",
            public_ipv4="203.0.113.42",
            public_ipv6=None,
            admin_email="ops@example.com",
            tlsa_cert_hex=None,
        )
        assert not any(e.type == "AAAA" for e in exps)

    def test_aaaa_when_v6(self):
        exps = doctor.build_postern_expectations(
            "hole.example",
            public_ipv4="203.0.113.42",
            public_ipv6="2001:db8::42",
            admin_email="ops@example.com",
            tlsa_cert_hex=None,
        )
        aaaa_names = {e.name for e in exps if e.type == "AAAA"}
        assert aaaa_names == {"hole.example", "*.hole.example", "mail.hole.example"}

    def test_caa_apex_only(self):
        exps = doctor.build_postern_expectations(
            "hole.example",
            public_ipv4="1.1.1.1",
            public_ipv6=None,
            admin_email="ops@example.com",
            tlsa_cert_hex=None,
        )
        caa = [e for e in exps if e.type == "CAA"]
        assert len(caa) == 1
        assert caa[0].name == "hole.example"
        assert 'letsencrypt.org' in caa[0].expected_content

    def test_mx_target_has_trailing_dot(self):
        """`postern-dns mx-set` normalizes to trailing dot; the doctor must
        expect the on-wire form, not the bare hostname."""
        exps = doctor.build_postern_expectations(
            "hole.example",
            public_ipv4="1.1.1.1",
            public_ipv6=None,
            admin_email="ops@example.com",
            tlsa_cert_hex=None,
        )
        mx = next(e for e in exps if e.type == "MX")
        assert mx.expected_content == "10 mail.hole.example."

    def test_txt_content_is_unquoted(self):
        """libdns/cloudflare unwraps on read; the doctor compares against the
        unquoted form (#122)."""
        exps = doctor.build_postern_expectations(
            "hole.example",
            public_ipv4="1.1.1.1",
            public_ipv6=None,
            admin_email="ops@example.com",
            tlsa_cert_hex=None,
        )
        spf = next(e for e in exps if e.type == "TXT" and e.name == "hole.example")
        assert spf.expected_content == "v=spf1 mx -all"
        assert not spf.expected_content.startswith('"')

    def test_tlsa_when_cert_hex_provided(self):
        exps = doctor.build_postern_expectations(
            "hole.example",
            public_ipv4="1.1.1.1",
            public_ipv6=None,
            admin_email="ops@example.com",
            tlsa_cert_hex="ab" * 32,
        )
        tlsa = next(e for e in exps if e.type == "TLSA")
        assert tlsa.name == "_25._tcp.mail.hole.example"
        assert tlsa.expected_content == "3 1 1 " + "ab" * 32

    def test_no_tlsa_when_cert_hex_absent(self):
        exps = doctor.build_postern_expectations(
            "hole.example",
            public_ipv4="1.1.1.1",
            public_ipv6=None,
            admin_email="ops@example.com",
            tlsa_cert_hex=None,
        )
        assert not any(e.type == "TLSA" for e in exps)

    def test_dkim_included_when_pubkey_supplied(self):
        exps = doctor.build_postern_expectations(
            "hole.example",
            public_ipv4="1.1.1.1",
            public_ipv6=None,
            admin_email="ops@example.com",
            tlsa_cert_hex=None,
            dkim_pubkey_by_selector={"sel-2026-05": "BASE64KEY"},
        )
        dkim = next(e for e in exps if e.name == "sel-2026-05._domainkey.hole.example")
        assert "v=DKIM1; k=rsa; p=BASE64KEY" == dkim.expected_content


# Postern record query =================================================================================================
class TestCheckPosternRecord:

    def _resolver_with_a(self, ip: str) -> dns.resolver.Resolver:
        r = MagicMock(spec=dns.resolver.Resolver)
        ans = MagicMock()
        ans.rrset = MagicMock()
        rec = MagicMock()
        rec.to_text.return_value = ip
        ans.__iter__ = lambda self: iter([rec])
        r.resolve.return_value = ans
        return r

    def test_a_match(self):
        r = self._resolver_with_a("203.0.113.42")
        exp = doctor.PosternManagedExpectation(
            label="A", name="hole.example", type="A", expected_content="203.0.113.42", fix=""
        )
        assert doctor.check_postern_record(exp, resolver=r).status == "ok"

    def test_a_mismatch(self):
        r = self._resolver_with_a("198.51.100.1")
        exp = doctor.PosternManagedExpectation(
            label="A", name="hole.example", type="A", expected_content="203.0.113.42", fix="check provisioner"
        )
        res = doctor.check_postern_record(exp, resolver=r)
        assert res.status == "fail"
        assert "got" in res.detail and "203.0.113.42" in res.detail
        assert res.fix == "check provisioner"

    def test_wildcard_probes_synthetic_subname(self):
        """`*.<domain>` must be probed as `doctor-probe.<domain>` because
        resolvers don't expand wildcards on queries for the literal `*.` name."""
        r = MagicMock(spec=dns.resolver.Resolver)
        captured: list[str] = []

        def _resolve(name, rdtype, raise_on_no_answer=False):
            captured.append(str(name))
            ans = MagicMock()
            ans.rrset = MagicMock()
            rec = MagicMock()
            rec.to_text.return_value = "203.0.113.42"
            ans.__iter__ = lambda self: iter([rec])
            return ans

        r.resolve.side_effect = _resolve
        exp = doctor.PosternManagedExpectation(
            label="A    *.hole.example",
            name="*.hole.example",
            type="A",
            expected_content="203.0.113.42",
            fix="",
        )
        doctor.check_postern_record(exp, resolver=r)
        assert captured == ["doctor-probe.hole.example"]

    def test_txt_concatenates_multi_string(self):
        """RFC 7208 §3.4: multi-string TXTs concatenate byte-for-byte; we mirror that."""
        r = MagicMock(spec=dns.resolver.Resolver)
        ans = MagicMock()
        ans.rrset = MagicMock()
        rec = MagicMock()
        rec.strings = [b"v=spf1 ", b"mx -all"]
        ans.__iter__ = lambda self: iter([rec])
        r.resolve.return_value = ans

        exp = doctor.PosternManagedExpectation(
            label="SPF  hole.example",
            name="hole.example",
            type="TXT",
            expected_content="v=spf1 mx -all",
            fix="",
        )
        assert doctor.check_postern_record(exp, resolver=r).status == "ok"

    def test_mx_normalizes_trailing_dot_in_answer(self):
        r = MagicMock(spec=dns.resolver.Resolver)
        ans = MagicMock()
        ans.rrset = MagicMock()
        rec = MagicMock()
        rec.preference = 10
        # dnspython returns exchange WITH trailing dot; lower-case it.
        rec.exchange = MagicMock()
        rec.exchange.__str__ = lambda self: "Mail.Hole.Example."
        ans.__iter__ = lambda self: iter([rec])
        r.resolve.return_value = ans

        exp = doctor.PosternManagedExpectation(
            label="MX   hole.example",
            name="hole.example",
            type="MX",
            expected_content="10 mail.hole.example.",
            fix="",
        )
        assert doctor.check_postern_record(exp, resolver=r).status == "ok"

    def test_nxdomain_is_fail_with_fix(self):
        r = MagicMock(spec=dns.resolver.Resolver)
        r.resolve.side_effect = dns.resolver.NXDOMAIN()
        exp = doctor.PosternManagedExpectation(
            label="A    hole.example",
            name="hole.example",
            type="A",
            expected_content="203.0.113.42",
            fix="bring up provisioner",
        )
        res = doctor.check_postern_record(exp, resolver=r)
        assert res.status == "fail"
        assert res.fix == "bring up provisioner"


# Connectivity =========================================================================================================
class TestConnectivity:

    def test_tcp_ok_returns_ok(self):
        with patch.object(socket, "create_connection") as mock_conn:
            mock_conn.return_value.__enter__ = lambda self: self
            mock_conn.return_value.__exit__ = lambda self, *a: None
            result = doctor.check_tcp("hole.example", 443)
        assert result.status == "ok"
        assert ":443/tcp" in result.label

    def test_tcp_refused_returns_fail(self):
        with patch.object(socket, "create_connection", side_effect=ConnectionRefusedError("refused")):
            result = doctor.check_tcp("hole.example", 443)
        assert result.status == "fail"
        assert "firewall" in result.fix

    def test_tls_verification_failure_is_fail(self):
        # SSLCertVerificationError is a subclass of SSLError.
        err = ssl.SSLCertVerificationError("self-signed cert")
        err.reason = "SELF_SIGNED_CERT_IN_CHAIN"
        with patch.object(socket, "create_connection") as mock_conn:
            mock_conn.return_value.__enter__ = lambda self: self
            mock_conn.return_value.__exit__ = lambda self, *a: None
            with patch.object(ssl, "create_default_context") as mock_ctx:
                ctx = MagicMock()
                ctx.wrap_socket.side_effect = err
                mock_ctx.return_value = ctx
                result = doctor.check_tls("hole.example", 443)
        assert result.status == "fail"
        assert "cert verification failed" in result.detail
        assert "postern cert verify" in result.fix


# Runner ===============================================================================================================
class TestRunDoctor:

    def _stub(self, ok: bool = True) -> doctor.CheckResult:
        return _ok("stub") if ok else _fail("stub")

    def test_runs_all_sections_by_default(self):
        seen: list[str] = []

        def ds(d):
            seen.append("ds")
            return _ok(f"DS {d}")

        def ptr(ip, exp):
            seen.append(f"ptr-{ip}")
            return _ok(f"PTR {ip}")

        def rec(e):
            seen.append(f"rec-{e.name}-{e.type}")
            return _ok(e.label)

        def tcp(h, p):
            seen.append(f"tcp-{h}-{p}")
            return _ok(f":{p}/tcp {h}")

        def tls(h, p):
            seen.append(f"tls-{h}-{p}")
            return _ok(f"TLS {h}:{p}")

        report = doctor.run_doctor(
            _settings(),
            ds_probe=ds,
            ptr_probe=ptr,
            record_probe=rec,
            tcp_probe=tcp,
            tls_probe=tls,
        )
        assert "ds" in seen
        assert "ptr-203.0.113.42" in seen
        assert "ptr-2001:db8::42" in seen  # because public_ipv6 is set
        assert any(s.startswith("rec-") for s in seen)
        assert "tcp-hole.example-443" in seen
        assert "tcp-mail.hole.example-25" in seen
        assert "tls-hole.example-443" in seen
        assert report.exit_code == 0

    def test_external_only_skips_other_sections(self):
        seen: list[str] = []
        report = doctor.run_doctor(
            _settings(),
            sections=(doctor.EXTERNAL, ),
            ds_probe=lambda d: (seen.append("ds"), _ok(f"DS {d}"))[1],
            ptr_probe=lambda ip, exp: (seen.append(f"ptr-{ip}"), _ok(f"PTR {ip}"))[1],
            record_probe=lambda e: pytest.fail("record_probe must not run"),
            tcp_probe=lambda h, p: pytest.fail("tcp_probe must not run"),
            tls_probe=lambda h, p: pytest.fail("tls_probe must not run"),
        )
        assert all(r.section == doctor.EXTERNAL for r in report.results)
        assert "ds" in seen

    def test_no_v6_skips_ipv6_ptr(self):
        seen: list[str] = []
        doctor.run_doctor(
            _settings(public_ipv6=None),
            sections=(doctor.EXTERNAL, ),
            ds_probe=lambda d: _ok("ds"),
            ptr_probe=lambda ip, exp: (seen.append(ip), _ok(ip))[1],
        )
        assert seen == ["203.0.113.42"]

    def test_failure_propagates_to_exit_code(self):
        report = doctor.run_doctor(
            _settings(),
            sections=(doctor.EXTERNAL, ),
            ds_probe=lambda d: _fail(f"DS {d}"),
            ptr_probe=lambda ip, exp: _ok(f"PTR {ip}"),
        )
        assert report.exit_code == 1


# Rendering ============================================================================================================
class TestRender:

    def test_all_pass_text_says_all_passed(self):
        report = doctor.DoctorReport(results=[
            _ok("DS hole.example"),
            _ok("PTR 1.2.3.4"),
        ])
        out = doctor.render_text(report)
        assert "All 2 checks passed." in out
        assert "[OK]" in out

    def test_failures_section_count_in_summary(self):
        report = doctor.DoctorReport(results=[
            _ok("DS hole.example"),
            _fail("PTR 1.2.3.4", fix="set rDNS"),
        ])
        out = doctor.render_text(report)
        assert "1 of 2 checks failed" in out
        assert "[FAIL]" in out
        assert "Fix: set rDNS" in out

    def test_render_layout_columns_aligned(self):
        """Verify the label column reaches at least _LABEL_W cells before
        detail starts (so tabular output stays readable)."""
        report = doctor.DoctorReport(results=[
            _ok("short", section=doctor.EXTERNAL),
        ])
        line = next(l for l in doctor.render_text(report).splitlines() if "[OK]" in l)
        # Indent + marker is 2 + 6 + 1 = 9 chars; then label padded to _LABEL_W.
        assert len(line.split("-> ok")[0]) >= 9 + doctor._LABEL_W - 1

    def test_json_is_parseable_and_includes_exit_code(self):
        report = doctor.DoctorReport(results=[_fail("foo")])
        decoded = json.loads(doctor.render_json(report))
        assert decoded["exit_code"] == 1
        assert decoded["results"][0]["status"] == "fail"
        assert decoded["results"][0]["section"] == "external"

    def test_grouped_by_section_with_headings(self):
        report = doctor.DoctorReport(
            results=[
                _ok("A", section=doctor.EXTERNAL),
                _ok("B", section=doctor.POSTERN_MANAGED),
                _ok("C", section=doctor.CONNECTIVITY),
            ]
        )
        out = doctor.render_text(report)
        # The three headings appear in this order.
        i_ext = out.index("External (operator must publish")
        i_pm = out.index("Postern-managed (current state")
        i_conn = out.index("Connectivity:")
        assert i_ext < i_pm < i_conn

    def test_empty_section_heading_omitted(self):
        report = doctor.DoctorReport(results=[_ok("only", section=doctor.CONNECTIVITY)])
        out = doctor.render_text(report)
        assert "External (" not in out
        assert "Postern-managed (" not in out
        assert "Connectivity:" in out
