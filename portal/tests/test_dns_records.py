"""Unit tests for the cert-manager-driven A/AAAA + CAA reconciler (PR #115)."""
from __future__ import annotations

import datetime as dt
import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from postern.cert import dns_records as dns_state
from postern_provisioner import dns_records as dns_driver


# Fakes ================================================================================================================
@dataclass
class FakeRunner:
    """Records each set/delete invocation for assertion. Raises on demand."""
    set_calls: list[tuple] = field(default_factory=list)
    delete_calls: list[tuple] = field(default_factory=list)
    raise_on_set: str | None = None  # if set, raises CalledProcessError when this record name appears

    def set_record(self, rec: dns_driver.DesiredRecord) -> None:
        if self.raise_on_set is not None and rec.name == self.raise_on_set:
            raise subprocess.CalledProcessError(1, ["postern-dns", "set"], stderr=b"forced")
        self.set_calls.append((rec.type, rec.name, rec.args, rec.proxied))

    def delete_record(self, rec: dns_driver.DesiredRecord) -> None:
        self.delete_calls.append((rec.type, rec.name, rec.args))


def _settings(
    domain="example.com",
    v4="1.2.3.4",
    v6="",
    *,
    dns_provider="cloudflare",
    cert_enabled=True,
    mta_enabled=True,
    edge_enabled=False,
) -> dns_driver.DnsRecordsSettings:
    return dns_driver.DnsRecordsSettings(
        domain=domain,
        dns_provider=dns_provider,
        public_ipv4=v4,
        public_ipv6=v6,
        cert_enabled=cert_enabled,
        mta_enabled=mta_enabled,
        edge_enabled=edge_enabled,
    )


# desired_records ======================================================================================================
def test_desired_records_ipv4_only():
    recs = dns_driver.desired_records(_settings(v4="1.2.3.4"))
    types = [(r.type, r.name) for r in recs]
    assert ("A", "example.com") in types
    assert ("A", "*.example.com") in types
    assert ("A", "mail.example.com") in types
    assert ("CAA", "example.com") in types
    # No AAAA when v6 is empty.
    assert not any(r.type == "AAAA" for r in recs)


def test_desired_records_dualstack():
    recs = dns_driver.desired_records(_settings(v4="1.2.3.4", v6="2001:db8::1"))
    aaaa = [r for r in recs if r.type == "AAAA"]
    # Three AAAA: apex + wildcard + mail.
    assert len(aaaa) == 3
    assert {r.name for r in aaaa} == {"example.com", "*.example.com", "mail.example.com"}


def test_desired_records_caa_payload():
    recs = dns_driver.desired_records(_settings())
    caa = next(r for r in recs if r.type == "CAA")
    assert caa.args == ("0", "issue", "letsencrypt.org")


def test_desired_records_apex_proxied_under_cloudflare_edge():
    recs = dns_driver.desired_records(_settings(edge_enabled=True))
    apex_a = next(r for r in recs if r.type == "A" and r.name == "example.com")
    assert apex_a.proxied is True
    # Wildcard and mail stay gray even under edge.
    assert next(r for r in recs if r.name == "*.example.com").proxied is False
    assert next(r for r in recs if r.name == "mail.example.com").proxied is False


def test_desired_records_apex_gray_when_edge_off():
    recs = dns_driver.desired_records(_settings(edge_enabled=False))
    apex_a = next(r for r in recs if r.type == "A" and r.name == "example.com")
    assert apex_a.proxied is False


def test_desired_records_apex_not_proxied_without_cloudflare_provider():
    # Defensive: edge on but a non-CF provider -> proxied stays False so we never
    # desire a state the runner (CF-only --proxied) cannot converge.
    recs = dns_driver.desired_records(_settings(edge_enabled=True, dns_provider="route53"))
    apex_a = next(r for r in recs if r.type == "A" and r.name == "example.com")
    assert apex_a.proxied is False


def test_desired_records_wildcard_and_caa_only_under_cert():
    recs = dns_driver.desired_records(_settings(cert_enabled=False, mta_enabled=False, edge_enabled=True))
    names = {(r.type, r.name) for r in recs}
    assert ("A", "*.example.com") not in names
    assert not any(r.type == "CAA" for r in recs)
    # Apex still present (edge needs it).
    assert ("A", "example.com") in names


def test_desired_records_mail_only_under_mta():
    with_mta = {(r.type, r.name) for r in dns_driver.desired_records(_settings(mta_enabled=True))}
    without = {(r.type, r.name) for r in dns_driver.desired_records(_settings(mta_enabled=False))}
    assert ("A", "mail.example.com") in with_mta
    assert ("A", "mail.example.com") not in without


def test_desired_records_mta_sts_only_when_edge_and_mta():
    both = dns_driver.desired_records(_settings(edge_enabled=True, mta_enabled=True))
    sts = next(r for r in both if r.name == "mta-sts.example.com")
    assert sts.type == "A" and sts.proxied is True
    # Not published when either is off (gray wildcard covers it without edge).
    assert not any(r.name == "mta-sts.example.com" for r in dns_driver.desired_records(_settings(edge_enabled=False)))
    assert not any(
        r.name == "mta-sts.example.com"
        for r in dns_driver.desired_records(_settings(edge_enabled=True, mta_enabled=False))
    )


def test_desired_records_mta_only_omits_apex():
    # DKIM/MTA on, no cert, no edge: only mail records; apex needs cert or edge.
    recs = dns_driver.desired_records(_settings(cert_enabled=False, mta_enabled=True, edge_enabled=False))
    names = {r.name for r in recs}
    assert names == {"mail.example.com"}


# reconcile_apex_dns ===================================================================================================
def test_reconcile_publishes_everything_on_first_tick():
    runner = FakeRunner()
    state = dns_state.DnsRecordsState()  # nothing published yet
    new = dns_driver.reconcile_apex_dns(state, settings=_settings(v4="1.2.3.4"), runner=runner)

    # 3 A records + 1 CAA. No AAAA (v6 unset).
    assert len(runner.set_calls) == 4
    assert len(runner.delete_calls) == 0
    assert new.last_published_ipv4 == "1.2.3.4"
    assert new.last_published_ipv6 == ""
    assert new.last_reconciled_iso is not None
    assert new.consecutive_failures == 0


def test_reconcile_skips_when_state_matches():
    runner = FakeRunner()
    state = dns_state.DnsRecordsState(
        last_published_ipv4="1.2.3.4",
        last_published_caa='0 issue "letsencrypt.org"',
        last_reconciled_iso="2026-05-11T00:00:00+00:00",
    )
    new = dns_driver.reconcile_apex_dns(state, settings=_settings(v4="1.2.3.4"), runner=runner)
    # Idempotent: every record already shows as published, so no API calls.
    assert runner.set_calls == []
    assert runner.delete_calls == []
    # Timestamp advances anyway -- a successful tick is a successful tick.
    assert new.last_reconciled_iso is not None


def test_reconcile_aaaa_delete_on_unset():
    """PUBLIC_IPV6 was set; now unset -> reconciler deletes AAAA records and clears state."""
    runner = FakeRunner()
    state = dns_state.DnsRecordsState(
        last_published_ipv4="1.2.3.4",
        last_published_ipv6="2001:db8::1",
        last_published_caa='0 issue "letsencrypt.org"',
        last_reconciled_iso="2026-05-11T00:00:00+00:00",
    )
    new = dns_driver.reconcile_apex_dns(state, settings=_settings(v4="1.2.3.4", v6=""), runner=runner)

    # Three AAAA deletes (apex, wildcard, mail), nothing else.
    assert len(runner.delete_calls) == 3
    assert all(call[0] == "AAAA" for call in runner.delete_calls)
    assert all(call[2] == ("2001:db8::1", ) for call in runner.delete_calls)
    assert new.last_published_ipv6 == ""


def test_reconcile_ipv4_drift_deletes_old_then_publishes_new():
    """PUBLIC_IPV4 changed from 1.2.3.4 to 5.6.7.8 -> delete old A then publish new."""
    runner = FakeRunner()
    state = dns_state.DnsRecordsState(
        last_published_ipv4="1.2.3.4",
        last_published_caa='0 issue "letsencrypt.org"',
        last_reconciled_iso="2026-05-11T00:00:00+00:00",
    )
    new = dns_driver.reconcile_apex_dns(state, settings=_settings(v4="5.6.7.8"), runner=runner)

    # Three old A deletes.
    assert len(runner.delete_calls) == 3
    assert all(call[0] == "A" and call[2] == ("1.2.3.4", ) for call in runner.delete_calls)
    # Three new A publishes (CAA was already published so it's skipped).
    sets_by_type = {}
    for typ, _, args, *_ in runner.set_calls:
        sets_by_type.setdefault(typ, []).append(args)
    assert sets_by_type.get("A") == [("5.6.7.8", )] * 3
    assert new.last_published_ipv4 == "5.6.7.8"


def test_reconcile_failure_increments_counter():
    """An exception from the runner bumps consecutive_failures but state is otherwise unchanged."""
    runner = FakeRunner(raise_on_set="example.com")
    state = dns_state.DnsRecordsState(consecutive_failures=2)
    new = dns_driver.reconcile_apex_dns(state, settings=_settings(v4="1.2.3.4"), runner=runner)
    assert new.consecutive_failures == 3
    # last_reconciled_iso unchanged (no successful tick).
    assert new.last_reconciled_iso == state.last_reconciled_iso


def test_reconcile_publishes_proxied_apex_under_edge():
    runner = FakeRunner()
    state = dns_state.DnsRecordsState()
    new = dns_driver.reconcile_apex_dns(state, settings=_settings(edge_enabled=True), runner=runner)
    apex = next(c for c in runner.set_calls if c[1] == "example.com" and c[0] == "A")
    assert apex[3] is True  # proxied
    assert new.last_published_apex_proxied is True


def test_reconcile_apex_proxied_flip_off_republishes_gray():
    # Edge was on (apex proxied); now off -> apex must be re-set gray so the
    # runner PATCHes proxied=false. A content-only compare would wrongly skip it.
    runner = FakeRunner()
    state = dns_state.DnsRecordsState(
        last_published_ipv4="1.2.3.4",
        last_published_caa='0 issue "letsencrypt.org"',
        last_published_apex_proxied=True,
        last_reconciled_iso="2026-07-01T00:00:00+00:00",
    )
    new = dns_driver.reconcile_apex_dns(state, settings=_settings(edge_enabled=False), runner=runner)
    apex_sets = [c for c in runner.set_calls if c[1] == "example.com" and c[0] == "A"]
    assert apex_sets and apex_sets[0][3] is False
    assert new.last_published_apex_proxied is False


def test_reconcile_no_apex_flip_is_a_noop():
    runner = FakeRunner()
    state = dns_state.DnsRecordsState(
        last_published_ipv4="1.2.3.4",
        last_published_caa='0 issue "letsencrypt.org"',
        last_published_apex_proxied=True,
        last_reconciled_iso="2026-07-01T00:00:00+00:00",
    )
    dns_driver.reconcile_apex_dns(state, settings=_settings(edge_enabled=True), runner=runner)
    assert not any(c[1] == "example.com" for c in runner.set_calls)


def test_reconcile_retracts_mta_sts_when_edge_disabled():
    runner = FakeRunner()
    state = dns_state.DnsRecordsState(
        last_published_ipv4="1.2.3.4",
        last_published_caa='0 issue "letsencrypt.org"',
        last_published_apex_proxied=True,
        last_published_mta_sts_present=True,
        last_reconciled_iso="2026-07-01T00:00:00+00:00",
    )
    new = dns_driver.reconcile_apex_dns(state, settings=_settings(edge_enabled=False), runner=runner)
    assert ("A", "mta-sts.example.com") in {(c[0], c[1]) for c in runner.delete_calls}
    assert new.last_published_mta_sts_present is False


def test_reconcile_publishes_mta_sts_when_edge_enabled():
    runner = FakeRunner()
    state = dns_state.DnsRecordsState(
        last_published_ipv4="1.2.3.4",
        last_published_caa='0 issue "letsencrypt.org"',
        last_reconciled_iso="2026-07-01T00:00:00+00:00",
    )
    new = dns_driver.reconcile_apex_dns(state, settings=_settings(edge_enabled=True), runner=runner)
    sts = next(c for c in runner.set_calls if c[1] == "mta-sts.example.com")
    assert sts[3] is True
    assert new.last_published_mta_sts_present is True


# State persistence ====================================================================================================
def test_state_roundtrip(tmp_path):
    state = dns_state.DnsRecordsState(
        last_published_ipv4="1.2.3.4",
        last_published_ipv6="2001:db8::1",
        last_published_caa='0 issue "letsencrypt.org"',
        last_reconciled_iso="2026-05-11T00:00:00+00:00",
        consecutive_failures=2,
    )
    dns_state.write_state(state, certdir=tmp_path)
    got = dns_state.read_state(certdir=tmp_path)
    assert got == state


def test_state_missing_file_returns_default(tmp_path):
    state = dns_state.read_state(certdir=tmp_path)
    assert state == dns_state.DnsRecordsState()


def test_state_unknown_fields_ignored(tmp_path):
    """Forward-compat: a state.json from a newer schema is tolerated."""
    path = dns_state.state_path(certdir=tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({
            "schema_version": 999,
            "last_published_ipv4": "1.2.3.4",
            "future_field_we_dont_know": "ignored",
        })
    )
    state = dns_state.read_state(certdir=tmp_path)
    assert state.last_published_ipv4 == "1.2.3.4"


def test_state_file_is_world_readable_post_write(tmp_path):
    """Portal CLI runs as a different UID; state.json must be world-readable
    so `postern dns show` doesn't fail with EACCES (matches the privkey.pem
    0644 trust-boundary precedent in CLAUDE.md)."""
    state = dns_state.DnsRecordsState(last_published_ipv4="1.2.3.4")
    dns_state.write_state(state, certdir=tmp_path)
    mode = dns_state.state_path(certdir=tmp_path).stat().st_mode & 0o777
    assert mode & 0o004, f"state.json mode 0{mode:o} is not world-readable"


def test_state_v2_roundtrip_persists_proxied_and_mta_sts(tmp_path):
    state = dns_state.DnsRecordsState(
        last_published_ipv4="1.2.3.4",
        last_published_apex_proxied=True,
        last_published_mta_sts_present=True,
        last_reconciled_iso="2026-07-02T00:00:00+00:00",
    )
    dns_state.write_state(state, certdir=tmp_path)
    got = dns_state.read_state(certdir=tmp_path)
    assert got == state
    assert got.schema_version == 2


def test_state_v1_upgrades_to_gray_defaults(tmp_path):
    # A pre-edge (schema_version 1) file has no proxied/mta-sts keys; they must
    # default to the gray, no-mta-sts values so the first v2 tick sees no drift.
    path = dns_state.state_path(certdir=tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{"schema_version": 1, "last_published_ipv4": "1.2.3.4"}')
    got = dns_state.read_state(certdir=tmp_path)
    assert got.last_published_apex_proxied is False
    assert got.last_published_mta_sts_present is False


# Validation helpers ===================================================================================================
def test_validate_ipv4_accepts_valid():
    assert dns_driver.validate_ipv4("1.2.3.4") == "1.2.3.4"


def test_validate_ipv4_rejects_ipv6():
    with pytest.raises(ValueError, match="IPv4"):
        dns_driver.validate_ipv4("2001:db8::1")


def test_validate_ipv4_rejects_garbage():
    with pytest.raises(ValueError, match="IPv4"):
        dns_driver.validate_ipv4("not-an-ip")


def test_validate_ipv6_accepts_valid():
    assert dns_driver.validate_ipv6("2001:db8::1") == "2001:db8::1"


def test_validate_ipv6_empty_is_ok():
    """PUBLIC_IPV6 is optional -- empty string is a valid (no-op) value."""
    assert dns_driver.validate_ipv6("") == ""


def test_validate_ipv6_rejects_ipv4():
    with pytest.raises(ValueError, match="IPv6"):
        dns_driver.validate_ipv6("1.2.3.4")


# Settings integration =================================================================================================
def test_settings_cert_renewal_requires_public_ipv4(tmp_path, monkeypatch):
    """When CERT_RENEWAL=true, Settings refuses to instantiate without PUBLIC_IPV4."""
    from postern.settings import Settings
    monkeypatch.setenv("SECRET_KEY", "x" * 32)
    monkeypatch.setenv("CERT_RENEWAL", "true")
    monkeypatch.setenv("DNS_PROVIDER", "cloudflare")
    monkeypatch.setenv("CERT_ACME_EMAIL", "ops@deployer.test")
    monkeypatch.setenv("PUBLIC_IPV4", "")
    with pytest.raises(ValueError, match="PUBLIC_IPV4"):
        Settings()


def test_settings_cert_renewal_validates_ipv4_format(tmp_path, monkeypatch):
    from postern.settings import Settings
    monkeypatch.setenv("SECRET_KEY", "x" * 32)
    monkeypatch.setenv("CERT_RENEWAL", "true")
    monkeypatch.setenv("DNS_PROVIDER", "cloudflare")
    monkeypatch.setenv("CERT_ACME_EMAIL", "ops@deployer.test")
    monkeypatch.setenv("PUBLIC_IPV4", "not-an-ip")
    with pytest.raises(ValueError, match="IPv4"):
        Settings()


def test_settings_cert_renewal_dualstack_ok(tmp_path, monkeypatch):
    from postern.settings import Settings
    monkeypatch.setenv("SECRET_KEY", "x" * 32)
    monkeypatch.setenv("CERT_RENEWAL", "true")
    monkeypatch.setenv("DNS_PROVIDER", "cloudflare")
    monkeypatch.setenv("CERT_ACME_EMAIL", "ops@deployer.test")
    monkeypatch.setenv("PUBLIC_IPV4", "1.2.3.4")
    monkeypatch.setenv("PUBLIC_IPV6", "2001:db8::1")
    s = Settings()
    assert s.public_ipv4 == "1.2.3.4"
    assert s.public_ipv6 == "2001:db8::1"


def test_settings_no_cert_renewal_ignores_public_ipv4(monkeypatch):
    """When CERT_RENEWAL=false, PUBLIC_IPV4 may be empty -- it's only required for cert mode."""
    from postern.settings import Settings
    monkeypatch.setenv("SECRET_KEY", "x" * 32)
    monkeypatch.setenv("CERT_RENEWAL", "false")
    monkeypatch.setenv("PUBLIC_IPV4", "")
    s = Settings()
    assert s.cert_renewal is False
    assert s.public_ipv4 == ""


# PosternDnsRunner --proxied ===========================================================================================
def _capture_argv(monkeypatch) -> dict:
    captured: dict = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd

        class _Result:
            returncode = 0

        return _Result()

    monkeypatch.setattr(dns_driver.subprocess, "run", fake_run)
    return captured


def test_set_record_emits_proxied_true_for_cloudflare_a(monkeypatch):
    captured = _capture_argv(monkeypatch)
    runner = dns_driver.PosternDnsRunner(dns_provider="cloudflare")
    runner.set_record(dns_driver.DesiredRecord(name="example.com", type="A", args=("1.2.3.4", ), proxied=True))
    assert captured["cmd"][-1] == "--proxied=true"


def test_set_record_emits_proxied_false_for_cloudflare_gray_a(monkeypatch):
    captured = _capture_argv(monkeypatch)
    runner = dns_driver.PosternDnsRunner(dns_provider="cloudflare")
    runner.set_record(dns_driver.DesiredRecord(name="*.example.com", type="A", args=("1.2.3.4", ), proxied=False))
    assert captured["cmd"][-1] == "--proxied=false"


def test_set_record_no_proxied_flag_for_non_cloudflare(monkeypatch):
    captured = _capture_argv(monkeypatch)
    runner = dns_driver.PosternDnsRunner(dns_provider="route53")
    runner.set_record(dns_driver.DesiredRecord(name="example.com", type="A", args=("1.2.3.4", ), proxied=True))
    assert not any(str(a).startswith("--proxied") for a in captured["cmd"])


def test_set_record_no_proxied_flag_for_caa_even_under_cloudflare(monkeypatch):
    captured = _capture_argv(monkeypatch)
    runner = dns_driver.PosternDnsRunner(dns_provider="cloudflare")
    runner.set_record(dns_driver.DesiredRecord(name="example.com", type="CAA", args=("0", "issue", "letsencrypt.org")))
    assert not any(str(a).startswith("--proxied") for a in captured["cmd"])


def test_delete_record_never_emits_proxied(monkeypatch):
    # Delete matches on (zone,type,name,content); proxied is not part of the key.
    captured = _capture_argv(monkeypatch)
    runner = dns_driver.PosternDnsRunner(dns_provider="cloudflare")
    runner.delete_record(dns_driver.DesiredRecord(name="example.com", type="A", args=("1.2.3.4", ), proxied=True))
    assert not any(str(a).startswith("--proxied") for a in captured["cmd"])


# FakeRunner ownership guard ===========================================================================================
def test_fakerunner_not_shipped_in_dns_driver():
    # Tests own their FakeRunner; production must not grow one.
    assert not hasattr(dns_driver, "FakeRunner")
