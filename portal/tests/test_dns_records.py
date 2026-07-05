"""Unit tests for the cert-manager-driven A/AAAA + CAA reconciler (PR #115)."""
from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass, field

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


def _snapshot(**kw) -> list[dns_state.DnsRecord]:
    """A last-published snapshot equal to the desired set for `_settings(**kw)`.
    Building snapshots via desired_records (rather than hand-listing) keeps them
    in lockstep with the reconciler and avoids off-by-one omissions."""
    return list(dns_driver.desired_records(_settings(**kw)))


def _state(records: list | None = None, **kw) -> dns_state.DnsRecordsState:
    """A v3 state carrying a last-published snapshot."""
    return dns_state.DnsRecordsState(last_published=records if records is not None else [], **kw)


def _write_v2_state(tmp_path, **scalars) -> dns_state.DnsRecordsState:
    """Write a pre-v3 (schema 2) scalar state file and return the read-back state
    (with its legacy_scalars stashed) as the reconciler would see it on upgrade."""
    path = dns_state.state_path(certdir=tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"schema_version": 2, **scalars}
    path.write_text(json.dumps(payload))
    return dns_state.read_state(certdir=tmp_path)


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
def _rec(records, name, type):
    """The snapshot record at (name, type), or None."""
    return next((r for r in records if r.name == name and r.type == type), None)


def test_reconcile_publishes_everything_on_first_tick():
    runner = FakeRunner()
    state = dns_state.DnsRecordsState()  # nothing published yet
    new = dns_driver.reconcile_apex_dns(state, settings=_settings(v4="1.2.3.4"), runner=runner)

    # 3 A records + 1 CAA. No AAAA (v6 unset).
    assert len(runner.set_calls) == 4
    assert len(runner.delete_calls) == 0
    assert _rec(new.last_published, "example.com", "A").args == ("1.2.3.4", )
    assert not any(r.type == "AAAA" for r in new.last_published)
    assert new.last_reconciled_iso is not None
    assert new.consecutive_failures == 0


def test_reconcile_skips_when_state_matches():
    runner = FakeRunner()
    # Snapshot already equals the desired set -> the diff is a pure no-op.
    state = _state(_snapshot(v4="1.2.3.4"), last_reconciled_iso="2026-05-11T00:00:00+00:00")
    new = dns_driver.reconcile_apex_dns(state, settings=_settings(v4="1.2.3.4"), runner=runner)
    # Idempotent: every record already shows as published, so no API calls.
    assert runner.set_calls == []
    assert runner.delete_calls == []
    # Timestamp advances anyway -- a successful tick is a successful tick.
    assert new.last_reconciled_iso is not None


def test_reconcile_aaaa_delete_on_unset():
    """PUBLIC_IPV6 was set; now unset -> the AAAA records leave the desired set and
    are deleted (apex, wildcard, mail), nothing else."""
    runner = FakeRunner()
    state = _state(_snapshot(v4="1.2.3.4", v6="2001:db8::1"), last_reconciled_iso="2026-05-11T00:00:00+00:00")
    new = dns_driver.reconcile_apex_dns(state, settings=_settings(v4="1.2.3.4", v6=""), runner=runner)

    assert len(runner.delete_calls) == 3
    assert all(call[0] == "AAAA" for call in runner.delete_calls)
    assert all(call[2] == ("2001:db8::1", ) for call in runner.delete_calls)
    assert not any(r.type == "AAAA" for r in new.last_published)


def test_reconcile_ipv4_drift_deletes_old_then_publishes_new():
    """PUBLIC_IPV4 changed from 1.2.3.4 to 5.6.7.8 -> delete old A then publish new."""
    runner = FakeRunner()
    state = _state(_snapshot(v4="1.2.3.4"), last_reconciled_iso="2026-05-11T00:00:00+00:00")
    new = dns_driver.reconcile_apex_dns(state, settings=_settings(v4="5.6.7.8"), runner=runner)

    # Three old A deletes (apex, wildcard, mail).
    assert len(runner.delete_calls) == 3
    assert all(call[0] == "A" and call[2] == ("1.2.3.4", ) for call in runner.delete_calls)
    # Three new A publishes (CAA was already published so it's skipped).
    sets_by_type = {}
    for typ, _, args, *_ in runner.set_calls:
        sets_by_type.setdefault(typ, []).append(args)
    assert sets_by_type.get("A") == [("5.6.7.8", )] * 3
    assert _rec(new.last_published, "example.com", "A").args == ("5.6.7.8", )


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
    assert _rec(new.last_published, "example.com", "A").proxied is True


def test_reconcile_apex_proxied_flip_off_republishes_gray():
    # Edge was on (apex proxied); now off -> apex must be re-set gray so the
    # runner PATCHes proxied=false. A content-only compare would wrongly skip it.
    runner = FakeRunner()
    state = _state(_snapshot(edge_enabled=True), last_reconciled_iso="2026-07-01T00:00:00+00:00")
    new = dns_driver.reconcile_apex_dns(state, settings=_settings(edge_enabled=False), runner=runner)
    apex_sets = [c for c in runner.set_calls if c[1] == "example.com" and c[0] == "A"]
    assert apex_sets and apex_sets[0][3] is False
    assert _rec(new.last_published, "example.com", "A").proxied is False


def test_reconcile_apex_proxied_flip_does_not_delete_apex():
    # A proxied-only flip (same IP) must be a re-SET, never a delete+set -- the
    # CF-direct PATCH flips the orange cloud in place.
    runner = FakeRunner()
    state = _state(_snapshot(edge_enabled=True), last_reconciled_iso="2026-07-01T00:00:00+00:00")
    dns_driver.reconcile_apex_dns(state, settings=_settings(edge_enabled=False), runner=runner)
    assert not any(c[1] == "example.com" and c[0] == "A" for c in runner.delete_calls)


def test_reconcile_no_apex_flip_is_a_noop():
    runner = FakeRunner()
    state = _state(_snapshot(edge_enabled=True), last_reconciled_iso="2026-07-01T00:00:00+00:00")
    dns_driver.reconcile_apex_dns(state, settings=_settings(edge_enabled=True), runner=runner)
    assert not any(c[1] == "example.com" for c in runner.set_calls)


def test_reconcile_retracts_mta_sts_when_edge_disabled():
    runner = FakeRunner()
    state = _state(_snapshot(edge_enabled=True), last_reconciled_iso="2026-07-01T00:00:00+00:00")
    new = dns_driver.reconcile_apex_dns(state, settings=_settings(edge_enabled=False), runner=runner)
    assert ("A", "mta-sts.example.com") in {(c[0], c[1]) for c in runner.delete_calls}
    assert _rec(new.last_published, "mta-sts.example.com", "A") is None


def test_reconcile_publishes_mta_sts_when_edge_enabled():
    runner = FakeRunner()
    # Edge was off (no mta-sts, apex gray); now on.
    state = _state(_snapshot(edge_enabled=False), last_reconciled_iso="2026-07-01T00:00:00+00:00")
    new = dns_driver.reconcile_apex_dns(state, settings=_settings(edge_enabled=True), runner=runner)
    sts = next(c for c in runner.set_calls if c[1] == "mta-sts.example.com")
    assert sts[3] is True
    assert _rec(new.last_published, "mta-sts.example.com", "A").proxied is True


# Set-diff: precise pruning (new in the set-based model) ===============================================================
def test_reconcile_prunes_wildcard_and_caa_when_cert_disabled():
    """Cert turned off -> wildcard A + CAA leave the desired set and are deleted
    (the scalar model could not express this)."""
    runner = FakeRunner()
    state = _state(_snapshot(cert_enabled=True), last_reconciled_iso="2026-07-01T00:00:00+00:00")
    new = dns_driver.reconcile_apex_dns(state, settings=_settings(cert_enabled=False), runner=runner)
    deleted = {(c[0], c[1]) for c in runner.delete_calls}
    assert ("A", "*.example.com") in deleted
    assert ("CAA", "example.com") in deleted
    # mail (mta still on) survives; it is neither deleted nor re-set.
    assert not any(c[1] == "mail.example.com" for c in runner.delete_calls)
    assert _rec(new.last_published, "*.example.com", "A") is None
    assert _rec(new.last_published, "example.com", "CAA") is None


def test_reconcile_prunes_mail_when_mta_disabled():
    """MTA turned off -> mail A leaves the desired set and is deleted."""
    runner = FakeRunner()
    state = _state(_snapshot(mta_enabled=True), last_reconciled_iso="2026-07-01T00:00:00+00:00")
    dns_driver.reconcile_apex_dns(state, settings=_settings(mta_enabled=False), runner=runner)
    assert ("A", "mail.example.com") in {(c[0], c[1]) for c in runner.delete_calls}


# Migration: pre-v3 (scalar) state file upgrade ========================================================================
def test_reconcile_legacy_no_drift_touches_only_unevidenced_records(tmp_path):
    """A pre-v3 file whose scalars match the current settings: evidence-backed
    records (apex/wildcard/CAA via the CAA scalar) are untouched, while mail. --
    desired but unevidenced (the scalars can't prove it was published) -- gets one
    idempotent re-set. Nothing is deleted."""
    runner = FakeRunner()
    state = _write_v2_state(
        tmp_path,
        last_published_ipv4="1.2.3.4",
        last_published_caa='0 issue "letsencrypt.org"',
        last_reconciled_iso="2026-06-01T00:00:00+00:00",
    )
    new = dns_driver.reconcile_apex_dns(state, settings=_settings(v4="1.2.3.4"), runner=runner)
    assert runner.set_calls == [("A", "mail.example.com", ("1.2.3.4", ), False)]
    assert runner.delete_calls == []
    # The reconstructed snapshot is persisted so subsequent ticks are v3-native.
    assert {(r.name, r.type)
            for r in new.last_published} == {("example.com", "A"), ("*.example.com", "A"), ("mail.example.com", "A"),
                                             ("example.com", "CAA")}


def test_reconcile_legacy_ipv6_unset_deletes_stale_aaaa(tmp_path):
    """Upgrade coincident with PUBLIC_IPV6 unset still deletes the stale AAAA
    records the pre-v3 model published."""
    runner = FakeRunner()
    state = _write_v2_state(
        tmp_path,
        last_published_ipv4="1.2.3.4",
        last_published_ipv6="2001:db8::1",
        last_published_caa='0 issue "letsencrypt.org"',
    )
    dns_driver.reconcile_apex_dns(state, settings=_settings(v4="1.2.3.4", v6=""), runner=runner)
    assert len(runner.delete_calls) == 3
    assert all(c[0] == "AAAA" and c[2] == ("2001:db8::1", ) for c in runner.delete_calls)
    # Only the unevidenced mail A is (idempotently) re-set; no AAAA comes back.
    assert runner.set_calls == [("A", "mail.example.com", ("1.2.3.4", ), False)]


def test_reconcile_legacy_ipv4_change_deletes_old_then_sets_new(tmp_path):
    """Upgrade coincident with an IP change: delete old A (no duplicate left) then set new."""
    runner = FakeRunner()
    state = _write_v2_state(tmp_path, last_published_ipv4="1.2.3.4", last_published_caa='0 issue "letsencrypt.org"')
    dns_driver.reconcile_apex_dns(state, settings=_settings(v4="5.6.7.8"), runner=runner)
    assert all(c[0] == "A" and c[2] == ("1.2.3.4", ) for c in runner.delete_calls)
    assert {c[2] for c in runner.set_calls if c[0] == "A"} == {("5.6.7.8", )}


def test_reconcile_legacy_edge_only_does_not_delete_unmanaged_names(tmp_path):
    """Edge-only pre-v3 state (apex only): the migration must NOT fabricate/delete
    wildcard or mail records at PUBLIC_IPV4 (they were never reconciler-managed)."""
    runner = FakeRunner()
    state = _write_v2_state(tmp_path, last_published_ipv4="1.2.3.4", last_published_apex_proxied=True)
    edge_only = dict(cert_enabled=False, mta_enabled=False, edge_enabled=True)
    dns_driver.reconcile_apex_dns(state, settings=_settings(**edge_only), runner=runner)
    # No drift -> apex unchanged; and crucially nothing touched at *. / mail. / CAA.
    touched = {c[1] for c in runner.delete_calls} | {c[1] for c in runner.set_calls}
    assert touched == set()


def test_reconcile_legacy_cert_disable_with_v6_unset_prunes_apex_wildcard(tmp_path):
    """Subsystem disabled coincident with the upgrade: pre-v3 cert+mta dualstack,
    then cert off (mta stays on, keeping the reconciler running) AND PUBLIC_IPV6
    unset. The CAA scalar proves cert owned apex+wildcard, so their stale records
    are pruned rather than orphaned pointing at the decommissioned v6 address."""
    runner = FakeRunner()
    state = _write_v2_state(
        tmp_path,
        last_published_ipv4="1.2.3.4",
        last_published_ipv6="2001:db8::1",
        last_published_caa='0 issue "letsencrypt.org"',
    )
    dns_driver.reconcile_apex_dns(state, settings=_settings(v4="1.2.3.4", v6="", cert_enabled=False), runner=runner)
    deleted = {(c[0], c[1]) for c in runner.delete_calls}
    # No stale AAAA (old v6) orphaned at the apex/wildcard the cert used to own.
    assert ("AAAA", "example.com") in deleted
    assert ("AAAA", "*.example.com") in deleted
    assert ("AAAA", "mail.example.com") in deleted
    # apex/wildcard A + CAA are no longer desired (cert off) -> pruned too.
    assert ("A", "example.com") in deleted
    assert ("A", "*.example.com") in deleted
    assert ("CAA", "example.com") in deleted
    # mail A stays (mta on, IP unchanged) -- not deleted, only idempotently re-set.
    assert ("A", "mail.example.com") not in deleted
    assert runner.set_calls == [("A", "mail.example.com", ("1.2.3.4", ), False)]


def test_reconcile_legacy_mta_sts_retract(tmp_path):
    """Pre-v3 mta-sts-present flag, upgrade coincident with edge disable: the stale
    orange mta-sts record is reconstructed and pruned."""
    runner = FakeRunner()
    state = _write_v2_state(
        tmp_path,
        last_published_ipv4="1.2.3.4",
        last_published_caa='0 issue "letsencrypt.org"',
        last_published_apex_proxied=True,
        last_published_mta_sts_present=True,
    )
    dns_driver.reconcile_apex_dns(state, settings=_settings(edge_enabled=False), runner=runner)
    assert ("A", "mta-sts.example.com") in {(c[0], c[1]) for c in runner.delete_calls}


def test_reconcile_legacy_apex_proxied_evidence_prunes_apex(tmp_path):
    """apex_proxied alone (no CAA) proves edge+CF owned the apex; with every
    apex-desiring subsystem now off, the stale apex A must be pruned."""
    runner = FakeRunner()
    state = _write_v2_state(tmp_path, last_published_ipv4="1.2.3.4", last_published_apex_proxied=True)
    settings = _settings(v4="1.2.3.4", cert_enabled=False, edge_enabled=False, mta_enabled=True)
    dns_driver.reconcile_apex_dns(state, settings=settings, runner=runner)
    assert ("A", "example.com") in {(c[0], c[1]) for c in runner.delete_calls}


def test_reconcile_legacy_mta_sts_evidence_prunes_apex_and_mta_sts(tmp_path):
    """mta_sts_present alone (apex_proxied absent) proves edge+MTA owned the apex
    AND mta-sts; with edge/cert now off, both stale A records must be pruned."""
    runner = FakeRunner()
    state = _write_v2_state(tmp_path, last_published_ipv4="1.2.3.4", last_published_mta_sts_present=True)
    settings = _settings(v4="1.2.3.4", cert_enabled=False, edge_enabled=False, mta_enabled=True)
    dns_driver.reconcile_apex_dns(state, settings=settings, runner=runner)
    deleted = {(c[0], c[1]) for c in runner.delete_calls}
    assert ("A", "example.com") in deleted
    assert ("A", "mta-sts.example.com") in deleted


def test_reconcile_legacy_mta_enabled_at_upgrade_sets_mail(tmp_path):
    """Subsystem ENABLED coincident with the upgrade, IP unchanged: a pre-v3
    cert-only file gives no evidence mail. was ever published, so the migration
    tick must SET it -- a fabricated snapshot entry equal to the desired record
    would suppress the set forever."""
    runner = FakeRunner()
    state = _write_v2_state(tmp_path, last_published_ipv4="1.2.3.4", last_published_caa='0 issue "letsencrypt.org"')
    new = dns_driver.reconcile_apex_dns(state, settings=_settings(v4="1.2.3.4", mta_enabled=True), runner=runner)
    assert ("A", "mail.example.com") in {(c[0], c[1]) for c in runner.set_calls}
    assert _rec(new.last_published, "mail.example.com", "A").args == ("1.2.3.4", )


def test_reconcile_legacy_mta_enabled_at_upgrade_sets_mta_sts(tmp_path):
    """Pre-v3 cert+edge file (CF, apex proxied), MTA newly enabled at upgrade:
    mta-sts. must be SET on the migration tick."""
    runner = FakeRunner()
    state = _write_v2_state(
        tmp_path,
        last_published_ipv4="1.2.3.4",
        last_published_caa='0 issue "letsencrypt.org"',
        last_published_apex_proxied=True,
    )
    settings = _settings(v4="1.2.3.4", edge_enabled=True, mta_enabled=True)
    dns_driver.reconcile_apex_dns(state, settings=settings, runner=runner)
    assert ("A", "mta-sts.example.com") in {(c[0], c[1]) for c in runner.set_calls}


def test_reconcile_legacy_cert_enabled_at_upgrade_sets_wildcard(tmp_path):
    """Pre-v3 edge-only file, cert newly enabled at upgrade: the wildcard must be
    SET on the migration tick."""
    runner = FakeRunner()
    state = _write_v2_state(tmp_path, last_published_ipv4="1.2.3.4", last_published_apex_proxied=True)
    settings = _settings(v4="1.2.3.4", cert_enabled=True, mta_enabled=False, edge_enabled=True)
    dns_driver.reconcile_apex_dns(state, settings=settings, runner=runner)
    assert ("A", "*.example.com") in {(c[0], c[1]) for c in runner.set_calls}


def test_reconcile_legacy_warns_about_unattributable_names(tmp_path, caplog):
    """Evidence-less pre-v3 file (e.g. MTA-only: bare IP scalars) + subsystem now
    disabled: the migration can't attribute the old records, so it must NOT delete
    them -- instead it warns once, naming the exact suspect FQDNs."""
    runner = FakeRunner()
    state = _write_v2_state(tmp_path, last_published_ipv4="1.2.3.4")
    settings = _settings(v4="1.2.3.4", cert_enabled=True, mta_enabled=False, edge_enabled=False)
    with caplog.at_level(logging.WARNING, logger="postern_provisioner.dns_records"):
        dns_driver.reconcile_apex_dns(state, settings=settings, runner=runner)
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "mail.example.com" in warnings[0]
    assert "mta-sts.example.com" in warnings[0]
    # The unattributable names are warned about, never deleted.
    assert not any(c[1] in ("mail.example.com", "mta-sts.example.com") for c in runner.delete_calls)


def test_reconcile_legacy_no_warning_when_all_names_accounted_for(tmp_path, caplog):
    """No ambiguity -> no warning: every managed name is desired or evidence-attributed."""
    runner = FakeRunner()
    state = _write_v2_state(
        tmp_path,
        last_published_ipv4="1.2.3.4",
        last_published_caa='0 issue "letsencrypt.org"',
        last_published_apex_proxied=True,
        last_published_mta_sts_present=True,
    )
    settings = _settings(v4="1.2.3.4", cert_enabled=True, mta_enabled=True, edge_enabled=True)
    with caplog.at_level(logging.WARNING, logger="postern_provisioner.dns_records"):
        dns_driver.reconcile_apex_dns(state, settings=settings, runner=runner)
    assert not [r for r in caplog.records if r.levelno == logging.WARNING]


def test_reconcile_legacy_no_warning_when_nothing_was_published(tmp_path, caplog):
    """A pre-v3 file with empty IP scalars (failed first tick) published nothing,
    so there can be no leftovers to warn about."""
    runner = FakeRunner()
    state = _write_v2_state(tmp_path, last_published_ipv4="")
    with caplog.at_level(logging.WARNING, logger="postern_provisioner.dns_records"):
        dns_driver.reconcile_apex_dns(state, settings=_settings(v4="1.2.3.4"), runner=runner)
    assert not [r for r in caplog.records if r.levelno == logging.WARNING]


def test_reconcile_legacy_failed_first_tick_has_no_empty_ip(tmp_path):
    """A pre-v3 file from a FAILED first tick (empty IP) must not reconstruct an
    empty-content record (which would be an invalid delete) -- it publishes fresh."""
    runner = FakeRunner()
    state = _write_v2_state(tmp_path, last_published_ipv4="", consecutive_failures=1)
    dns_driver.reconcile_apex_dns(state, settings=_settings(v4="1.2.3.4"), runner=runner)
    assert runner.delete_calls == []
    assert all(c[2] and c[2][0] for c in runner.set_calls)  # no empty-string args


def test_reconcile_legacy_failure_persists_reconstruction(tmp_path):
    """If the first legacy tick fails at the provider, the reconstructed snapshot
    (not an empty one) is kept so the migration intent survives to the next tick."""
    runner = FakeRunner(raise_on_set="example.com")
    state = _write_v2_state(tmp_path, last_published_ipv4="1.2.3.4", last_published_caa='0 issue "letsencrypt.org"')
    new = dns_driver.reconcile_apex_dns(state, settings=_settings(v4="5.6.7.8"), runner=runner)
    assert new.consecutive_failures == 1
    # Snapshot kept = reconstructed old-IP set, so next tick still diffs correctly.
    assert _rec(new.last_published, "example.com", "A").args == ("1.2.3.4", )


# State persistence ====================================================================================================
def test_state_roundtrip(tmp_path):
    state = _state(
        _snapshot(v4="1.2.3.4", v6="2001:db8::1"),
        last_reconciled_iso="2026-05-11T00:00:00+00:00",
        consecutive_failures=2,
    )
    dns_state.write_state(state, certdir=tmp_path)
    got = dns_state.read_state(certdir=tmp_path)
    assert got == state
    assert got.schema_version == 3


def test_state_missing_file_returns_default(tmp_path):
    state = dns_state.read_state(certdir=tmp_path)
    assert state == dns_state.DnsRecordsState()


def test_state_roundtrip_preserves_proxied_dimension(tmp_path):
    """A proxied apex + orange mta-sts survive the snapshot round-trip (JSON has no
    tuples/bools footgun): args coerce back to tuples so the diff still matches."""
    state = _state(_snapshot(edge_enabled=True))
    dns_state.write_state(state, certdir=tmp_path)
    got = dns_state.read_state(certdir=tmp_path)
    assert got == state
    apex = _rec(got.last_published, "example.com", "A")
    assert apex.proxied is True and apex.args == ("1.2.3.4", )
    assert _rec(got.last_published, "mta-sts.example.com", "A").proxied is True


def test_state_unknown_fields_ignored(tmp_path):
    """Forward-compat: a state.json from a newer schema (extra top-level and
    per-record keys) is tolerated; the snapshot still parses."""
    path = dns_state.state_path(certdir=tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({
            "schema_version": 999,
            "last_published": [{
                "name": "example.com", "type": "A", "args": ["1.2.3.4"], "proxied": False,
                "future_record_field": "ignored"
            }],
            "future_field_we_dont_know": "ignored",
        })
    )
    state = dns_state.read_state(certdir=tmp_path)
    assert _rec(state.last_published, "example.com", "A").args == ("1.2.3.4", )


def test_state_malformed_record_entry_degrades_to_empty(tmp_path, caplog):
    """JSON-valid but schema-malformed content (snapshot entry missing "name")
    must degrade to the empty-state warning path, not crash -- the provisioner
    healthcheck calls read_state uncaught, and a raise would wedge first-boot
    gating of nginx/mta under compose.cert.yaml."""
    path = dns_state.state_path(certdir=tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"schema_version": 3, "last_published": [{"type": "A"}]}))
    with caplog.at_level(logging.WARNING, logger="postern.cert.dns_records"):
        state = dns_state.read_state(certdir=tmp_path)
    assert state == dns_state.DnsRecordsState()
    assert any("treating as empty" in r.getMessage() for r in caplog.records)


def test_state_non_object_top_level_degrades_to_empty(tmp_path, caplog):
    path = dns_state.state_path(certdir=tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(["not", "an", "object"]))
    with caplog.at_level(logging.WARNING, logger="postern.cert.dns_records"):
        state = dns_state.read_state(certdir=tmp_path)
    assert state == dns_state.DnsRecordsState()
    assert any("treating as empty" in r.getMessage() for r in caplog.records)


def test_state_file_is_world_readable_post_write(tmp_path):
    """Portal CLI runs as a different UID; state.json must be world-readable
    so `postern dns show` doesn't fail with EACCES (matches the privkey.pem
    0644 trust-boundary precedent in CLAUDE.md)."""
    dns_state.write_state(_state(_snapshot(v4="1.2.3.4")), certdir=tmp_path)
    mode = dns_state.state_path(certdir=tmp_path).stat().st_mode & 0o777
    assert mode & 0o004, f"state.json mode 0{mode:o} is not world-readable"


def test_state_does_not_persist_legacy_scalars(tmp_path):
    """The transient legacy_scalars carrier must never reach disk."""
    state = _state(_snapshot(v4="1.2.3.4"))
    state.legacy_scalars = {"last_published_ipv4": "9.9.9.9"}
    dns_state.write_state(state, certdir=tmp_path)
    raw = json.loads(dns_state.state_path(certdir=tmp_path).read_text())
    assert "legacy_scalars" not in raw
    assert dns_state.read_state(certdir=tmp_path).legacy_scalars is None


def test_state_pre_v3_file_stashes_legacy_scalars(tmp_path):
    """A pre-v3 (scalar) file has no snapshot; read_state stashes the scalars in
    the transient legacy_scalars for the driver, with an empty last_published."""
    state = _write_v2_state(
        tmp_path,
        last_published_ipv4="1.2.3.4",
        last_published_ipv6="2001:db8::1",
        last_published_apex_proxied=True,
        last_published_mta_sts_present=True,
        last_reconciled_iso="2026-07-02T00:00:00+00:00",
    )
    assert state.last_published == []
    assert state.legacy_scalars is not None
    assert state.legacy_scalars["last_published_ipv4"] == "1.2.3.4"
    assert state.legacy_scalars["last_published_apex_proxied"] is True
    # Non-snapshot fields still read through.
    assert state.last_reconciled_iso == "2026-07-02T00:00:00+00:00"


def test_published_summary_from_snapshot_and_legacy(tmp_path):
    """`postern dns show` derives (ipv4, ipv6, caa) from the v3 snapshot, and from
    the stashed scalars right after a pre-v3 upgrade."""
    v3 = _state(_snapshot(v4="1.2.3.4", v6="2001:db8::1"))
    assert dns_state.published_summary(v3, "example.com") == ("1.2.3.4", "2001:db8::1", '0 issue "letsencrypt.org"')
    legacy = _write_v2_state(tmp_path, last_published_ipv4="9.9.9.9", last_published_caa='0 issue "letsencrypt.org"')
    assert dns_state.published_summary(legacy, "example.com") == ("9.9.9.9", "", '0 issue "letsencrypt.org"')


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
