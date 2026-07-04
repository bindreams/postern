"""Unit tests for the provisioner enable-gate + tick dispatcher (edge support).

Covers `compute_enablement` (the ONE source of truth for which subsystems run),
the `mta_deployed_from_profiles` helper (COMPOSE_PROFILES -> "MTA deployed"), and
`run_enabled_ticks` (fires each subsystem tick iff its flag is set). The
edge-only invariant -- an edge-only deployment publishes ONLY the orange apex --
is pinned both here and against `dns_records.desired_records`.
"""
from __future__ import annotations

from postern_provisioner import dns_records as dns_driver
from postern_provisioner import enablement as en

_TICKS = ("dkim", "cert", "dns", "mta_records", "edge")


def _spy_ticks(calls: list) -> dict:
    return {name: (lambda n=name: calls.append(n)) for name in _TICKS}


# compute_enablement ===================================================================================================
def test_all_off():
    e = en.compute_enablement(dns_provider="none", cert_renewal=False, edge_profile="none", mta_deployed=False)
    assert not any([e.dkim_enabled, e.cert_enabled, e.mta_enabled, e.dns_enabled, e.edge_enabled])


def test_mta_deployed_with_provider():
    e = en.compute_enablement(dns_provider="cloudflare", cert_renewal=False, edge_profile="none", mta_deployed=True)
    assert e.dkim_enabled and e.mta_enabled and e.dns_enabled
    assert not e.cert_enabled and not e.edge_enabled


def test_with_mta_but_provider_none_falls_to_exit_behaviour():
    # with-mta profile active but DNS_PROVIDER=none (manual rotation): have_provider
    # is False, so every publish gate is off -> main()'s exit-guard exits 0, exactly
    # as it does today ("DNS_PROVIDER=none -> nothing to do").
    e = en.compute_enablement(dns_provider="none", cert_renewal=False, edge_profile="none", mta_deployed=True)
    assert not e.dkim_enabled and not e.mta_enabled and not e.dns_enabled
    assert not e.cert_enabled and not e.edge_enabled


def test_cert_only_no_mta():
    e = en.compute_enablement(dns_provider="cloudflare", cert_renewal=True, edge_profile="none", mta_deployed=False)
    assert e.cert_enabled and e.dns_enabled
    assert not e.mta_enabled and not e.dkim_enabled and not e.edge_enabled


def test_edge_only_publishes_only_apex_flags():
    # THE invariant, at the flag level: cloudflare edge, no cert, no MTA.
    e = en.compute_enablement(
        dns_provider="cloudflare", cert_renewal=False, edge_profile="cloudflare", mta_deployed=False
    )
    assert e.edge_enabled and e.dns_enabled
    assert not e.cert_enabled and not e.mta_enabled and not e.dkim_enabled


def test_edge_plus_mta():
    e = en.compute_enablement(
        dns_provider="cloudflare", cert_renewal=False, edge_profile="cloudflare", mta_deployed=True
    )
    assert e.edge_enabled and e.mta_enabled and e.dkim_enabled and e.dns_enabled
    assert not e.cert_enabled


def test_generic_edge_is_not_a_provisioner_edge():
    # Generic edge is nginx-only; the provisioner's CF ranges/proxied logic stays off.
    e = en.compute_enablement(dns_provider="none", cert_renewal=False, edge_profile="generic", mta_deployed=False)
    assert not e.edge_enabled
    assert not e.dns_enabled  # no usable provider -> nothing to publish


def test_dns_requires_a_provider():
    # cert_renewal without a provider is a misconfig; the DNS publisher stays off
    # (postern-dns exits non-zero with DNS_PROVIDER=none).
    e = en.compute_enablement(dns_provider="none", cert_renewal=True, edge_profile="none", mta_deployed=False)
    assert not e.dns_enabled


def test_case_and_whitespace_insensitive():
    e = en.compute_enablement(
        dns_provider=" Cloudflare ", cert_renewal=False, edge_profile=" CLOUDFLARE ", mta_deployed=True
    )
    assert e.dkim_enabled and e.edge_enabled and e.dns_enabled and e.mta_enabled


# mta_deployed_from_profiles ===========================================================================================
def test_mta_deployed_from_profiles_membership():
    assert en.mta_deployed_from_profiles("with-mta") is True
    assert en.mta_deployed_from_profiles("with-mta,with-edge") is True
    assert en.mta_deployed_from_profiles("with-cert-renewal,with-mta,with-edge") is True


def test_mta_deployed_from_profiles_absent():
    assert en.mta_deployed_from_profiles("") is False
    assert en.mta_deployed_from_profiles("with-edge") is False
    assert en.mta_deployed_from_profiles("with-cert-renewal,with-edge") is False


def test_mta_deployed_from_profiles_whitespace_and_case():
    assert en.mta_deployed_from_profiles(" with-mta , with-edge ") is True
    assert en.mta_deployed_from_profiles("With-MTA") is True
    assert en.mta_deployed_from_profiles("with-mta\twith-edge") is True  # tab/space separated too


def test_mta_deployed_from_profiles_exact_token_not_substring():
    # A profile whose name merely contains "with-mta" must NOT count.
    assert en.mta_deployed_from_profiles("with-mta-experimental") is False
    assert en.mta_deployed_from_profiles("not-with-mta") is False


# run_enabled_ticks ====================================================================================================
def test_run_enabled_ticks_fires_only_enabled_in_fixed_order():
    calls: list = []
    e = en.Enablement(dkim_enabled=True, cert_enabled=False, mta_enabled=True, dns_enabled=True, edge_enabled=True)
    en.run_enabled_ticks(e, _spy_ticks(calls))
    assert calls == ["dkim", "dns", "mta_records", "edge"]  # cert skipped, deterministic order


def test_run_enabled_ticks_edge_runs_iff_edge_enabled():
    for edge in (True, False):
        calls: list = []
        e = en.Enablement(
            dkim_enabled=False, cert_enabled=False, mta_enabled=False, dns_enabled=False, edge_enabled=edge
        )
        en.run_enabled_ticks(e, _spy_ticks(calls))
        assert ("edge" in calls) == edge


# Edge-only invariant against the real DNS reconciler ==================================================================
def test_edge_only_desired_records_are_only_the_orange_apex():
    """End-to-end at the flag->records seam: an edge-only enablement, fed into
    DnsRecordsSettings, yields ONLY the proxied apex A/AAAA -- no mail, no
    mta-sts, no wildcard, no CAA."""
    e = en.compute_enablement(
        dns_provider="cloudflare", cert_renewal=False, edge_profile="cloudflare", mta_deployed=False
    )
    settings = dns_driver.DnsRecordsSettings(
        domain="postern.test",
        dns_provider="cloudflare",
        public_ipv4="203.0.113.10",
        public_ipv6="2001:db8::10",
        cert_enabled=e.cert_enabled,
        mta_enabled=e.mta_enabled,
        edge_enabled=e.edge_enabled,
    )
    recs = dns_driver.desired_records(settings)
    assert {(r.name, r.type) for r in recs} == {("postern.test", "A"), ("postern.test", "AAAA")}
    assert all(r.proxied for r in recs)  # orange-clouded
