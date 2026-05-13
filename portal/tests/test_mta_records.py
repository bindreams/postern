"""Unit tests for the MTA-records reconciler (PR #118)."""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from postern.mta import dns as mta_dns
from postern_provisioner import mta_records as mta_driver


# Fakes ================================================================================================================
@dataclass
class FakeRunner:
    set_calls: list[tuple] = field(default_factory=list)
    delete_calls: list[tuple] = field(default_factory=list)

    def set_record(self, rec: mta_dns.MtaRecord) -> None:
        self.set_calls.append((rec.type, rec.name, rec.args))

    def delete_record(self, rec: mta_dns.MtaRecord) -> None:
        self.delete_calls.append((rec.type, rec.name, rec.args))


def _settings(admin: str = "ops@example.com") -> mta_driver.MtaRecordsSettings:
    return mta_driver.MtaRecordsSettings(
        domain="example.com",
        dns_provider="cloudflare",
        admin_email=admin,
    )


# Policy template cross-consistency ====================================================================================
def test_mta_sts_policy_template_matches_nginx():
    """The Python constant in mta/dns.py must byte-match the nginx template
    (nginx serves the policy; the reconciler hashes it; both must agree)."""
    nginx_template = (Path(__file__).resolve().parent.parent.parent
                      / "nginx" / "etc" / "conf.d" / "mta-sts" / "policy.txt.tmpl")
    on_disk = nginx_template.read_text(encoding="utf-8")
    assert on_disk == mta_dns.MTA_STS_POLICY_TEMPLATE, (
        f"nginx policy.txt.tmpl drift from mta_dns.MTA_STS_POLICY_TEMPLATE.\n"
        f"nginx:\n{on_disk!r}\n\nmta_dns:\n{mta_dns.MTA_STS_POLICY_TEMPLATE!r}"
    )


def test_render_mta_sts_policy_substitutes_domain():
    out = mta_dns.render_mta_sts_policy("example.com")
    assert "mx: mail.example.com" in out
    assert "${DOMAIN}" not in out


def test_mta_sts_id_is_stable_and_short():
    a = mta_dns.mta_sts_id("example.com")
    b = mta_dns.mta_sts_id("example.com")
    assert a == b
    assert len(a) == 16
    # Different domains -> different ids.
    assert mta_dns.mta_sts_id("example.com") != mta_dns.mta_sts_id("other.example")


# Structured records API ===============================================================================================
def test_expected_records_structured_v4_only():
    recs = mta_dns.expected_records_structured("example.com", admin_email="ops@example.com")
    types = {(r.type, r.name) for r in recs}
    assert ("MX", "example.com") in types
    assert ("TXT", "example.com") in types  # SPF
    assert ("TXT", "_dmarc.example.com") in types
    assert ("TXT", "_mta-sts.example.com") in types
    assert ("TXT", "_smtp._tls.example.com") in types
    # No TLSA when tlsa_cert_hex is unspecified.
    assert not any(r.type == "TLSA" for r in recs)


def test_expected_records_structured_with_tlsa():
    hex_data = "ab" * 32
    recs = mta_dns.expected_records_structured(
        "example.com", admin_email="ops@example.com", tlsa_cert_hex=hex_data
    )
    tlsa = next(r for r in recs if r.type == "TLSA")
    assert tlsa.name == "_25._tcp.mail.example.com"
    # Mode 3 1 1 (DANE-EE, SPKI, SHA-256).
    assert tlsa.args == ("3", "1", "1", hex_data)


def test_expected_records_structured_tlsa_hex_lowercased():
    """Cert SPKI hex from cryptography is lowercase; if caller passes uppercase,
    the wrapper normalizes (postern-dns's tlsa parser is case-insensitive but
    we want byte-identity for state comparison)."""
    upper = "AB" * 32
    recs = mta_dns.expected_records_structured(
        "example.com", admin_email="ops@example.com", tlsa_cert_hex=upper
    )
    tlsa = next(r for r in recs if r.type == "TLSA")
    assert tlsa.args[3] == upper.lower()


def test_expected_records_structured_mx_target():
    recs = mta_dns.expected_records_structured("example.com", admin_email="ops@example.com")
    mx = next(r for r in recs if r.type == "MX")
    assert mx.args == ("10", "mail.example.com")


def test_dmarc_contains_url_encoded_admin_email():
    """Admin emails with chars needing percent-encoding in mailto: URIs
    must be encoded (RFC 7489 §6.2 / RFC 3986). `@` stays literal."""
    recs = mta_dns.expected_records_structured(
        "example.com", admin_email="ops+postmaster@example.com"
    )
    dmarc = next(r for r in recs if r.name == "_dmarc.example.com")
    # `+` percent-encodes to `%2B` in mailto: URIs.
    assert "mailto:ops%2Bpostmaster@example.com" in dmarc.args[0]


def test_mta_sts_id_appears_in_txt_record():
    recs = mta_dns.expected_records_structured("example.com", admin_email="ops@example.com")
    sts_rec = next(r for r in recs if r.name == "_mta-sts.example.com")
    expected_id = mta_dns.mta_sts_id("example.com")
    assert f"id={expected_id}" in sts_rec.args[0]


# Reconciler ===========================================================================================================
def test_reconcile_publishes_everything_on_first_tick():
    runner = FakeRunner()
    state = mta_driver.MtaRecordsState()
    new = mta_driver.reconcile_mta_records(
        state, settings=_settings(), cert_pem_path=Path("/nonexistent"), runner=runner
    )
    # 5 records when no cert is on disk (no TLSA).
    assert len(runner.set_calls) == 5
    assert len(runner.delete_calls) == 0
    assert new.last_reconciled_iso is not None
    assert new.consecutive_failures == 0
    # State now reflects what was published.
    assert new.last_published_mx.startswith("10 mail.example.com")
    assert "v=spf1" in new.last_published_spf
    assert "v=DMARC1" in new.last_published_dmarc
    assert "v=STSv1" in new.last_published_mta_sts
    assert "v=TLSRPTv1" in new.last_published_tls_rpt
    assert new.last_published_tlsa == ""


def test_reconcile_skips_when_state_matches(tmp_path):
    """If every record's signature matches state, no API calls."""
    runner = FakeRunner()
    # Pre-populate state with all the expected values.
    expected = mta_dns.expected_records_structured("example.com", admin_email="ops@example.com")
    state = mta_driver.MtaRecordsState(
        last_reconciled_iso="2026-05-11T00:00:00+00:00",
    )
    for rec in expected:
        mta_driver._set_last_published(state, rec.name, rec.type, " ".join(rec.args))
    new = mta_driver.reconcile_mta_records(
        state, settings=_settings(), cert_pem_path=Path("/nonexistent"), runner=runner
    )
    assert runner.set_calls == []
    assert runner.delete_calls == []


def test_reconcile_dmarc_drift_deletes_old_publishes_new():
    """Admin email changed -> DMARC TXT republished (delete old, set new)."""
    runner = FakeRunner()
    state = mta_driver.MtaRecordsState(
        last_published_mx='10 mail.example.com',
        last_published_spf='"v=spf1 mx -all"',
        last_published_dmarc='"v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto:OLD@example.com; ruf=mailto:OLD@example.com"',
        last_published_mta_sts=f'"v=STSv1; id={mta_dns.mta_sts_id("example.com")}"',
        last_published_tls_rpt='"v=TLSRPTv1; rua=mailto:OLD@example.com"',
        last_reconciled_iso="2026-05-11T00:00:00+00:00",
    )
    new = mta_driver.reconcile_mta_records(
        state, settings=_settings(admin="NEW@example.com"),
        cert_pem_path=Path("/nonexistent"), runner=runner,
    )
    # DMARC + TLS-RPT both reference the admin email, so both should drift.
    deleted_names = {call[1] for call in runner.delete_calls}
    set_names = {call[1] for call in runner.set_calls}
    assert "_dmarc.example.com" in deleted_names
    assert "_dmarc.example.com" in set_names
    assert "_smtp._tls.example.com" in deleted_names
    assert "_smtp._tls.example.com" in set_names
    # MX/SPF/MTA-STS not in scope of admin-email drift -- they shouldn't move.
    assert "example.com" not in deleted_names
    # The new state's DMARC must show the new admin.
    assert "mailto:NEW@example.com" in new.last_published_dmarc


def test_reconcile_skips_tlsa_when_cert_missing():
    runner = FakeRunner()
    state = mta_driver.MtaRecordsState()
    new = mta_driver.reconcile_mta_records(
        state, settings=_settings(), cert_pem_path=Path("/nonexistent/fullchain.pem"), runner=runner
    )
    # No TLSA in the publish set.
    tlsa_set = [call for call in runner.set_calls if call[0] == "TLSA"]
    assert tlsa_set == []
    assert new.last_published_tlsa == ""


def test_reconcile_publishes_tlsa_when_cert_present(tmp_path, monkeypatch):
    """When a cert is on disk, TLSA appears in the publish set with the
    SPKI sha256 hex of the leaf. (Uses a minimal self-signed cert fixture.)"""
    cert_path = tmp_path / "fullchain.pem"

    # Generate a tiny self-signed cert just for SPKI extraction.
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example")])
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=90)).sign(key, hashes.SHA256())
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    runner = FakeRunner()
    state = mta_driver.MtaRecordsState()
    new = mta_driver.reconcile_mta_records(
        state, settings=_settings(), cert_pem_path=cert_path, runner=runner
    )
    tlsa_sets = [call for call in runner.set_calls if call[0] == "TLSA"]
    assert len(tlsa_sets) == 1
    assert tlsa_sets[0][1] == "_25._tcp.mail.example.com"
    # Args = ("3", "1", "1", <hex>); hex is sha256(SPKI) -- 64 hex chars.
    assert tlsa_sets[0][2][:3] == ("3", "1", "1")
    assert len(tlsa_sets[0][2][3]) == 64
    # State reflects what was published.
    assert new.last_published_tlsa.startswith("3 1 1 ")


def test_reconcile_failure_increments_counter():
    """An exception from the runner bumps consecutive_failures, doesn't update last_reconciled."""

    class RaisingRunner(FakeRunner):

        def set_record(self, rec):
            raise subprocess.CalledProcessError(1, ["postern-dns"], stderr=b"forced")

    state = mta_driver.MtaRecordsState(consecutive_failures=2)
    runner = RaisingRunner()
    new = mta_driver.reconcile_mta_records(
        state, settings=_settings(), cert_pem_path=Path("/nonexistent"), runner=runner
    )
    assert new.consecutive_failures == 3
    assert new.last_reconciled_iso == state.last_reconciled_iso


# State persistence ====================================================================================================
def test_state_roundtrip(tmp_path):
    state = mta_driver.MtaRecordsState(
        last_published_mx="10 mail.example.com",
        last_published_spf='"v=spf1 mx -all"',
        last_published_tlsa="3 1 1 " + "ab" * 32,
        last_reconciled_iso="2026-05-11T00:00:00+00:00",
        consecutive_failures=1,
    )
    mta_driver.write_state(state, keydir=tmp_path)
    got = mta_driver.read_state(keydir=tmp_path)
    assert got == state


def test_state_missing_returns_default(tmp_path):
    assert mta_driver.read_state(keydir=tmp_path) == mta_driver.MtaRecordsState()


def test_state_unknown_fields_ignored(tmp_path):
    path = mta_driver.state_path(keydir=tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "schema_version": 999,
        "last_published_mx": "10 mail.example.com",
        "future_field": "ignored",
    }))
    state = mta_driver.read_state(keydir=tmp_path)
    assert state.last_published_mx == "10 mail.example.com"


def test_state_file_world_readable(tmp_path):
    """Same trust-boundary precedent as dns_records / privkey.pem."""
    state = mta_driver.MtaRecordsState(last_published_mx="10 mail.example.com")
    mta_driver.write_state(state, keydir=tmp_path)
    mode = mta_driver.state_path(keydir=tmp_path).stat().st_mode & 0o777
    assert mode & 0o004
