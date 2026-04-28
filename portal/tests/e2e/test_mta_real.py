"""Real-infrastructure MTA tests.

Marker (``e2e_mta_real``) is added by ``conftest.pytest_collection_modifyitems``.
These tests fail loudly when env is missing (per the project's "fail loudly"
rule); opt out with ``pytest -m 'not e2e_mta_real'``.

What runs without env:
- ``test_dnssec_status_detects_signed_domain`` (defaults to iana.org)

What needs maintainer-supplied env (validated by ``mta_test_env`` fixture):
- ``MTA_TEST_DOMAIN`` -- a domain the maintainer controls. Required to have a
  set of static baseline DNS records pre-published; see docs/mta.md.
- ``MTA_TEST_DNS_PROVIDER`` + provider-native creds (e.g. ``CLOUDFLARE_API_TOKEN``).

Tests do not boot a compose stack: they invoke ``postern-dns`` via ``docker run
--rm`` against the ``local/postern-provisioner`` image (built by CI before
running pytest), and call ``postern.mta.dns`` / ``postern.mta.dnssec`` from the
host. Resolver isolation: every ``dns.resolver.Resolver`` instance uses
``configure=False`` with explicit upstreams (1.1.1.1 + 8.8.8.8) and ``cache=None``.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import time
from collections.abc import Iterator

import dns.exception
import dns.resolver
import pytest

# postern is installed via `uv sync` in CI; locally it must be available too.
from postern.mta import dns as mta_dns
from postern.mta import dnssec as mta_dnssec

logger = logging.getLogger(__name__)

SELECTOR = "postern-e2e-test"
PUBLIC_RESOLVERS = ("1.1.1.1", "8.8.8.8")


# Helpers ==============================================================================================================
def _fresh_resolver() -> dns.resolver.Resolver:
    """A no-cache resolver with explicit public upstreams."""
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = list(PUBLIC_RESOLVERS)
    r.cache = None
    r.lifetime = 10.0
    r.timeout = 5.0
    return r


def _generate_test_pubkey_b64() -> str:
    """Generate an ephemeral RSA-2048 keypair, return the base64 SPKI body.

    We don't sign anything with this -- we only need a syntactically valid
    DKIM TXT body for the libdns round-trip. dnspython's verifier never
    sees this key.
    """
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    spki = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    import base64
    return base64.b64encode(spki).decode("ascii")


def _provider_env_dict(env: dict[str, str]) -> list[str]:
    """Render `-e KEY=VAL` args for `docker run` based on the resolved env."""
    pass_through = (
        "MTA_DNS_PROVIDER",
        "CLOUDFLARE_API_TOKEN",
        "AWS_REGION",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "GANDI_API_TOKEN",
        "DO_AUTH_TOKEN",
        "OVH_ENDPOINT",
        "OVH_APPLICATION_KEY",
        "OVH_APPLICATION_SECRET",
        "OVH_CONSUMER_KEY",
        "HETZNER_API_TOKEN",
        "LINODE_TOKEN",
        "NAMECHEAP_API_KEY",
        "NAMECHEAP_API_USER",
        "NAMECHEAP_CLIENT_IP",
    )
    args: list[str] = []
    for k in pass_through:
        v = env.get(k) if k in env else os.environ.get(k, "").strip()
        if v:
            args.extend(("-e", f"{k}={v}"))
    # MTA_DNS_PROVIDER comes from the test fixture as MTA_TEST_DNS_PROVIDER;
    # postern-dns reads MTA_DNS_PROVIDER. Bridge the name here.
    args.extend(("-e", f"MTA_DNS_PROVIDER={env['MTA_TEST_DNS_PROVIDER']}"))
    return args


def _postern_dns(env: dict[str, str], *args: str) -> subprocess.CompletedProcess:
    """Run the postern-dns binary in a one-off ``local/postern-provisioner`` container.

    --network bridge (not --network none): the libdns API call needs HTTPS to
    reach the provider's API endpoint. We don't mount the docker socket or pass
    other capabilities -- network access is the only deviation from the safe
    default (CLAUDE.md global rule about explicit-safety).

    --entrypoint postern-dns: the image's ENTRYPOINT is the rotation-state
    Python driver, which requires DOMAIN/MTA_DNS_PROVIDER and starts the full
    state machine. We just want the libdns wrapper, so we bypass the
    entrypoint and exec the binary directly.
    """
    cmd = [
        "docker",
        "run",
        "--rm",
        "--network",
        "bridge",
        "--entrypoint",
        "postern-dns",
        *_provider_env_dict(env),
        "local/postern-provisioner",
        *args,
    ]
    return subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=120)


def _resolve_txt_eventually(
    fqdn: str,
    *,
    expected_substring: str | None,
    timeout: float,
) -> list[str] | None:
    """Resolve TXT for fqdn until expected_substring is present (or absent if None).

    Returns the final list of TXT strings, or None if the lookup ended in
    NoAnswer / NXDOMAIN. Used both for "wait for record to appear" (set
    expected_substring) and "wait for record to disappear" (expected_substring=None
    means we want NoAnswer/NXDOMAIN).
    """
    deadline = time.monotonic() + timeout
    last_state: list[str] | None = []
    while time.monotonic() < deadline:
        r = _fresh_resolver()
        try:
            ans = r.resolve(fqdn, "TXT")
            txts: list[str] = []
            for record in ans:
                txts.append(b"".join(record.strings).decode("utf-8", errors="replace"))
            last_state = txts
            if expected_substring is None:
                # We're waiting for the record to disappear; presence here means keep waiting.
                pass
            elif any(expected_substring in t for t in txts):
                return txts
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            last_state = None
            if expected_substring is None:
                return None
        except dns.exception.DNSException as e:
            logger.warning("TXT %s lookup error during poll: %s", fqdn, e)
        time.sleep(2.0)
    return last_state


# Fixtures =============================================================================================================
@pytest.fixture(scope="module")
def published_dkim_record(mta_test_env: dict[str, str]) -> Iterator[tuple[str, str, str]]:
    """Publish ``<SELECTOR>._domainkey.<MTA_TEST_DOMAIN>`` with an ephemeral
    pubkey via libdns; yield ``(selector, fqdn, pubkey_b64)``; retire on exit.

    Setup also calls ``txt-delete`` first to clear any leftover from a prior
    crashed run (the selector is fixed -- ``postern-e2e-test`` -- so the next
    run is responsible for cleanup of its predecessor).
    """
    domain = mta_test_env["MTA_TEST_DOMAIN"]
    fqdn = f"{SELECTOR}._domainkey.{domain}"
    pubkey = _generate_test_pubkey_b64()
    record_value = f"v=DKIM1; k=rsa; p={pubkey}"
    propagation = float(mta_test_env["MTA_TEST_DNS_PROPAGATION_SECONDS"])

    # Best-effort cleanup of any stale record from a previous run. We don't
    # know the previous value, but `txt-delete` over libdns only matches the
    # exact (name, value) pair, so this delete is conservative -- it only
    # touches a record we ourselves published with this selector + value.
    # Untracked stale records on the maintainer's zone require manual cleanup.
    try:
        _postern_dns(mta_test_env, "txt-delete", fqdn, record_value)
    except subprocess.CalledProcessError as e:
        logger.info("preflight txt-delete returned non-zero (record may not have existed): %s", e.stderr)

    _postern_dns(mta_test_env, "txt-set", fqdn, record_value)

    # Wait for the record to be visible via public resolvers; surface the wait
    # time so flakes have actionable diagnostics.
    seen = _resolve_txt_eventually(fqdn, expected_substring=pubkey, timeout=propagation + 60)
    if not seen or not any(pubkey in t for t in seen):
        try:
            _postern_dns(mta_test_env, "txt-delete", fqdn, record_value)
        except subprocess.CalledProcessError:
            pass
        pytest.fail(
            f"DKIM TXT for {fqdn} did not propagate to public resolvers within "
            f"{propagation + 60:.0f}s after txt-set; last observed: {seen!r}.\n"
            f"Bump MTA_TEST_DNS_PROPAGATION_SECONDS for slower providers.",
            pytrace=False,
        )

    try:
        yield (SELECTOR, fqdn, pubkey)
    finally:
        try:
            _postern_dns(mta_test_env, "txt-delete", fqdn, record_value)
        except subprocess.CalledProcessError as e:
            logger.error(
                "txt-delete cleanup of %s FAILED -- manual cleanup may be required on the test domain: %s",
                fqdn,
                e.stderr,
            )


# Tests ================================================================================================================
def test_libdns_provider_round_trip(
    mta_test_env: dict[str, str],
    published_dkim_record: tuple[str, str, str],
):
    """The provisioner's postern-dns binary actually publishes and retires
    TXT records via the configured real provider. ``published_dkim_record``
    has just done txt-set + waited for propagation; this test asserts the
    record is visible, then re-deletes it explicitly and asserts it disappears
    (the fixture's teardown is best-effort and tolerates already-gone)."""
    selector, fqdn, pubkey = published_dkim_record
    # Sanity-check: the fixture confirmed propagation, but re-resolve once
    # so this test fails on its own line if something odd happens.
    txts = _resolve_txt_eventually(fqdn, expected_substring=pubkey, timeout=30.0)
    assert txts is not None and any(pubkey in t for t in txts), (f"published DKIM TXT not visible at {fqdn}: {txts!r}")

    # Re-delete eagerly and confirm. The fixture teardown will run after
    # tests in this module; calling delete here first lets the "absence"
    # assertion run with the propagation budget we already have.
    record_value = f"v=DKIM1; k=rsa; p={pubkey}"
    _postern_dns(mta_test_env, "txt-delete", fqdn, record_value)
    propagation = float(mta_test_env["MTA_TEST_DNS_PROPAGATION_SECONDS"])
    txts_after = _resolve_txt_eventually(fqdn, expected_substring=None, timeout=propagation + 60)
    assert txts_after is None or not any(pubkey in t for t in txts_after
                                         ), (f"DKIM TXT still resolves at {fqdn} after txt-delete: {txts_after!r}")

    # Re-publish so the rest of the module's tests still see the record.
    _postern_dns(mta_test_env, "txt-set", fqdn, record_value)
    re_seen = _resolve_txt_eventually(fqdn, expected_substring=pubkey, timeout=propagation + 60)
    assert re_seen is not None and any(pubkey in t
                                       for t in re_seen), (f"re-published DKIM TXT did not propagate: {re_seen!r}")


def test_mta_dns_verify_passes_with_published_records(
    mta_test_env: dict[str, str],
    published_dkim_record: tuple[str, str, str],
):
    """Full operator-facing pipeline: with all baseline records pre-published
    + the ephemeral DKIM TXT, ``postern.mta.dns.verify()`` returns no failures.

    Verifies MX, A (mail.<domain>, mta-sts.<domain>), SPF, DMARC, MTA-STS
    HTTPS policy fetch, TLS-RPT, and DKIM. PTR failures are filtered out --
    reverse DNS on shared/VPS infrastructure (e.g. seedbox provider rDNS) is
    not part of the DNS-zone setup the maintainer controls, so the test asserts
    only on records the maintainer publishes via their DNS provider.
    """
    domain = mta_test_env["MTA_TEST_DOMAIN"]
    admin_email = mta_test_env["MTA_TEST_ADMIN_EMAIL"]
    require_dnssec = mta_test_env["MTA_TEST_REQUIRE_DNSSEC"] == "true"
    selector, _fqdn, pubkey = published_dkim_record

    failures = mta_dns.verify(
        domain,
        dkim_pubkey_by_selector={selector: pubkey},
        admin_email=admin_email,
        require_dnssec=require_dnssec,
        resolver=_fresh_resolver(),
    )
    failures = [f for f in failures if not f.startswith("PTR ")]
    assert failures == [], (
        "mta_dns.verify reported failures against fully-configured test domain:\n  " + "\n  ".join(failures)
    )


def test_mta_dns_verify_reports_missing_dkim_but_others_pass(
    mta_test_env: dict[str, str],
    published_dkim_record: tuple[str, str, str],
):
    """Combined positive + negative: the published selector resolves cleanly,
    AND a bogus selector reports the canonical 'no TXT record' failure with
    no other entries. Pins the operator-facing failure-message contract while
    proving the resolver path is functional (rules out 'all DNS broken' as
    the passing condition).
    """
    domain = mta_test_env["MTA_TEST_DOMAIN"]
    admin_email = mta_test_env["MTA_TEST_ADMIN_EMAIL"]
    selector, _fqdn, pubkey = published_dkim_record

    bogus = "nonexistent-selector-9999"
    failures = mta_dns.verify(
        domain,
        dkim_pubkey_by_selector={selector: pubkey, bogus: "fake-pubkey-not-in-dns"},
        admin_email=admin_email,
        require_dnssec=False,
        resolver=_fresh_resolver(),
    )
    # PTR failures are infrastructure-level on shared VPS IPs and not part of
    # the zone-setup contract this test pins. See R2 docstring.
    failures = [f for f in failures if not f.startswith("PTR ")]
    expected_pat = re.compile(rf"^DKIM {re.escape(bogus)}\._domainkey\.{re.escape(domain)}: no TXT record$")
    matching = [f for f in failures if expected_pat.match(f)]
    other = [f for f in failures if not expected_pat.match(f)]
    assert matching, (
        f"expected exactly one failure matching {expected_pat.pattern!r}, none found.\n"
        f"failures: {failures!r}"
    )
    assert not other, (
        f"baseline records or published DKIM also failed (resolver path may be broken):\n  " + "\n  ".join(other)
    )


def test_dnssec_status_detects_signed_domain():
    """``postern.mta.dnssec.check()`` against a known-DNSSEC-signed domain
    returns no failures. Defaults to ``iana.org`` (signed since 2010); the
    maintainer can override via ``MTA_TEST_DNSSEC_DOMAIN`` for a different
    target. No env required, only internet access -- this test is the one
    that runs even on PRs from forks.

    Fails loudly on missing internet (no ``pytest.skip``).
    """
    domain = os.environ.get("MTA_TEST_DNSSEC_DOMAIN", "").strip() or "iana.org"
    try:
        failures = mta_dnssec.check(domain)
    except Exception as e:  # pragma: no cover - intentional broad catch for actionable error
        pytest.fail(
            f"mta_dnssec.check({domain!r}) raised {type(e).__name__}: {e}.\n"
            f"This test requires internet access to public validating resolvers (1.1.1.1, 9.9.9.9, 8.8.8.8).",
            pytrace=False,
        )
    assert failures == [], (f"DNSSEC AD-bit check failed against {domain!r}:\n  " + "\n  ".join(failures))
