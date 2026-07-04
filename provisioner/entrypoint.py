#!/usr/bin/env python3
"""Provisioner entrypoint -- generates initial DKIM keys and runs rotation state machine.

The provisioner is a sibling of the mta container; the two coordinate via
trigger files on the shared `postern-mta-data` volume:

  .rotate-dkim         portal CLI -> provisioner    (advance state machine)
  .reload-opendkim     provisioner -> mta           (HUP opendkim after key change)

Responsibilities:

1. On startup, ensure a DKIM keypair exists. If state.json is absent, generate
   the first selector (`s1`) and write a STABLE state. This runs
   regardless of DNS_PROVIDER -- the mta needs a key to sign with even on
   manual-rotation deployments.

2. If DNS_PROVIDER=none: log and exit 0. Compose's restart=no keeps the
   container stopped.

3. Otherwise, run the rotation state machine: every 60 minutes, or on
   .rotate-dkim trigger, evaluate whether to advance state. Backoff on failure.
"""

from __future__ import annotations

import datetime as dt
import logging
import os
import signal
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import NoReturn

import dns.exception
import dns.resolver

# postern_mta is COPYed into /usr/lib/python3.13/site-packages/ at image build time.
from postern_mta import dkim as mta_dkim  # noqa: E402
from postern_mta import rotation  # noqa: E402

# Cert renewal driver -- imported via the postern.* namespace (also COPYed in by Dockerfile).
from postern.cert import state as cert_state  # noqa: E402
from postern.cert import dns_records as dns_records_state  # noqa: E402
from postern_provisioner import cert as cert_driver  # noqa: E402
from postern_provisioner import dns_records as dns_driver  # noqa: E402
from postern_provisioner import edge_ranges  # noqa: E402
from postern_provisioner import mta_records as mta_records_driver  # noqa: E402
from postern_provisioner.enablement import (  # noqa: E402
    Enablement,
    compute_enablement,
    mta_deployed_from_profiles,
    run_enabled_ticks,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s provisioner %(levelname)s: %(message)s")
logger = logging.getLogger("entrypoint")

KEYDIR = Path("/var/lib/opendkim")
TICK_SECONDS = 60 * 60  # 1 hour
TRIGGER_POLL_SECONDS = 5
MAX_PROPAGATION_WAIT_SECONDS = 24 * 60 * 60
GRACE_PERIOD_SECONDS = 7 * 24 * 60 * 60
DEFAULT_PROPAGATION_TIMEOUT = 10 * 60


# Env parsing ==========================================================================================================
def _bool_env(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() not in ("false", "0", "no", "off", "")


def _require(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        die(f"required env var {name} is not set")
    return value


def die(msg: str) -> NoReturn:
    logger.error(msg)
    sys.exit(1)


# Key generation =======================================================================================================
def generate_keypair(domain: str, selector: str) -> None:
    """Generate a 2048-bit RSA DKIM keypair via opendkim-genkey.

    Writes <selector>.private (mode 0600) and <selector>.txt (mode 0644) into
    the shared volume. Both owned by the `opendkim` user (uid 110), which the
    mta container also runs as.
    """
    KEYDIR.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["opendkim-genkey", "-D", str(KEYDIR), "-d", domain, "-s", selector, "-b", "2048"],
        check=True,
    )
    private = KEYDIR / f"{selector}.private"
    public = KEYDIR / f"{selector}.txt"
    os.chmod(private, 0o600)
    os.chmod(public, 0o644)
    logger.info("generated DKIM keypair %s for %s", selector, domain)


def ensure_initial_key(domain: str, selector_prefix: str) -> rotation.RotationState:
    """If state.json doesn't exist, generate the first DKIM key and STABLE state."""
    state = rotation.read_state(keydir=KEYDIR)
    if state.state != "NO_KEYS":
        return state

    selector = rotation.next_selector(selector_prefix, state.active_selectors)
    generate_keypair(domain, selector)
    now = dt.datetime.now(dt.timezone.utc)
    rotation_days = int(os.environ.get("MTA_DKIM_ROTATION_DAYS", "180"))
    new_state = rotation.RotationState(
        state="STABLE",
        active_selectors=[selector],
        last_rotation_iso=now.isoformat(),
        next_rotation_iso=(now + dt.timedelta(days=rotation_days)).isoformat(),
    )
    rotation.write_state(new_state, keydir=KEYDIR)
    rotation.trigger_opendkim_reload(keydir=KEYDIR)
    pubkey = mta_dkim.read_local_pubkey(selector, keydir=KEYDIR)
    logger.info("DKIM TXT record to publish at %s._domainkey.%s:", selector, domain)
    logger.info('  "v=DKIM1; k=rsa; p=%s"', pubkey)
    return new_state


# DNS publishing (libdns wrapper) ======================================================================================
def dns_txt_set(fqdn: str, value: str) -> None:
    subprocess.run(["postern-dns", "txt-set", fqdn, value], check=True)


def dns_txt_delete(fqdn: str, value: str) -> None:
    subprocess.run(["postern-dns", "txt-delete", fqdn, value], check=True)


def wait_for_dns_propagation(fqdn: str, expected_value_substring: str, *, timeout_s: int) -> bool:
    """Poll public resolvers until the new record is visible. Returns True on success."""
    deadline = time.monotonic() + timeout_s
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["1.1.1.1", "9.9.9.9", "8.8.8.8"]
    resolver.lifetime = 5.0
    while time.monotonic() < deadline:
        try:
            ans = resolver.resolve(fqdn, "TXT")
            for r in ans:
                txt = b"".join(r.strings).decode("utf-8", errors="replace")
                if expected_value_substring in txt:
                    return True
        except dns.exception.DNSException:
            pass
        time.sleep(30)
    return False


# State machine ========================================================================================================
def time_to_rotate(state: rotation.RotationState) -> bool:
    if state.next_rotation_iso is None:
        return False
    next_rot = dt.datetime.fromisoformat(state.next_rotation_iso)
    return dt.datetime.now(dt.timezone.utc) >= next_rot


def advance_state(state: rotation.RotationState, domain: str, selector_prefix: str) -> rotation.RotationState:
    """Run one transition of the state machine. Idempotent enough to retry on failure."""
    if state.state == "STABLE":
        if not time_to_rotate(state) and not _has_explicit_trigger():
            return state
        new_selector = rotation.next_selector(selector_prefix, state.active_selectors)
        generate_keypair(domain, new_selector)
        pubkey = mta_dkim.read_local_pubkey(new_selector, keydir=KEYDIR)
        fqdn = f"{new_selector}._domainkey.{domain}"
        value = f"v=DKIM1; k=rsa; p={pubkey}"
        dns_txt_set(fqdn, value)
        return rotation.RotationState(
            state="PROPAGATING",
            active_selectors=state.active_selectors + [new_selector],
            retiring_selector=state.active_selectors[-1] if state.active_selectors else None,
            last_rotation_iso=state.last_rotation_iso,
            next_rotation_iso=state.next_rotation_iso,
            current_step_started_iso=dt.datetime.now(dt.timezone.utc).isoformat(),
        )

    if state.state == "PROPAGATING":
        if not state.active_selectors:
            return state
        new_selector = state.active_selectors[-1]
        pubkey = mta_dkim.read_local_pubkey(new_selector, keydir=KEYDIR)
        fqdn = f"{new_selector}._domainkey.{domain}"
        if not wait_for_dns_propagation(fqdn, pubkey[:32], timeout_s=DEFAULT_PROPAGATION_TIMEOUT):
            logger.info("propagation pending; will retry next tick")
            return state
        return rotation.RotationState(
            state="OVERLAP",
            active_selectors=state.active_selectors,
            retiring_selector=state.retiring_selector,
            last_rotation_iso=state.last_rotation_iso,
            next_rotation_iso=state.next_rotation_iso,
            current_step_started_iso=dt.datetime.now(dt.timezone.utc).isoformat(),
        )

    if state.state == "OVERLAP":
        if state.current_step_started_iso is None:
            return state
        started = dt.datetime.fromisoformat(state.current_step_started_iso)
        elapsed = (dt.datetime.now(dt.timezone.utc) - started).total_seconds()
        if elapsed < GRACE_PERIOD_SECONDS:
            return state
        return rotation.RotationState(
            state="RETIRING",
            active_selectors=state.active_selectors,
            retiring_selector=state.retiring_selector,
            last_rotation_iso=state.last_rotation_iso,
            next_rotation_iso=state.next_rotation_iso,
            current_step_started_iso=dt.datetime.now(dt.timezone.utc).isoformat(),
        )

    if state.state == "RETIRING":
        if state.retiring_selector is None:
            new_active = state.active_selectors
        else:
            old = state.retiring_selector
            try:
                old_pubkey = mta_dkim.read_local_pubkey(old, keydir=KEYDIR)
                dns_txt_delete(f"{old}._domainkey.{domain}", f"v=DKIM1; k=rsa; p={old_pubkey}")
            except mta_dkim.DkimKeyNotFoundError:
                pass
            for ext in (".private", ".txt"):
                p = KEYDIR / f"{old}{ext}"
                if p.exists():
                    p.unlink()
            new_active = [s for s in state.active_selectors if s != old]
        rotation_days = int(os.environ.get("MTA_DKIM_ROTATION_DAYS", "180"))
        now = dt.datetime.now(dt.timezone.utc)
        return rotation.RotationState(
            state="STABLE",
            active_selectors=new_active,
            retiring_selector=None,
            last_rotation_iso=now.isoformat(),
            next_rotation_iso=(now + dt.timedelta(days=rotation_days)).isoformat(),
            current_step_started_iso=None,
        )

    return state


def _has_explicit_trigger() -> bool:
    return rotation.trigger_path(KEYDIR).exists()


def _consume_trigger() -> None:
    path = rotation.trigger_path(KEYDIR)
    try:
        path.unlink()
    except OSError:
        pass


# Main loop ============================================================================================================
def run_rotation_loop(domain: str, selector_prefix: str) -> NoReturn:
    consecutive_failures = 0
    while True:
        try:
            state = rotation.read_state(keydir=KEYDIR)
            had_trigger = _has_explicit_trigger()
            new_state = advance_state(state, domain, selector_prefix)
            if had_trigger:
                _consume_trigger()
            if new_state != state:
                rotation.write_state(new_state, keydir=KEYDIR)
                rotation.trigger_opendkim_reload(keydir=KEYDIR)
                logger.info("rotation: %s -> %s", state.state, new_state.state)
            consecutive_failures = 0
        except subprocess.CalledProcessError as e:
            consecutive_failures += 1
            backoff = min(60 * (2**consecutive_failures), TICK_SECONDS)
            logger.error("rotation step failed (%d consecutive): %s; backing off %ds", consecutive_failures, e, backoff)
            if consecutive_failures >= 6:
                die(f"rotation failed {consecutive_failures} times in a row; giving up")
            time.sleep(backoff)
            continue
        except Exception:
            logger.exception("unexpected error in rotation loop")
            consecutive_failures += 1
            if consecutive_failures >= 6:
                die("unexpected errors persistent; giving up")
            time.sleep(60)
            continue

        # Sleep with trigger-file polling.
        slept = 0
        while slept < TICK_SECONDS:
            if _has_explicit_trigger():
                break
            time.sleep(TRIGGER_POLL_SECONDS)
            slept += TRIGGER_POLL_SECONDS


def _has_cert_trigger() -> bool:
    return cert_state.trigger_path().exists()


def _consume_cert_trigger() -> None:
    try:
        cert_state.trigger_path().unlink()
    except OSError:
        pass


def _build_cert_settings(domain: str) -> cert_driver.CertSettings:
    return cert_driver.CertSettings(
        domain=domain,
        dns_provider=os.environ.get("DNS_PROVIDER", "none").strip().lower(),
        cert_acme_email=os.environ.get("CERT_ACME_EMAIL", ""),
        cert_acme_directory=os.environ.get("CERT_ACME_DIRECTORY", "https://acme-v02.api.letsencrypt.org/directory"),
        cert_renewal_days_before_expiry=int(os.environ.get("CERT_RENEWAL_DAYS_BEFORE_EXPIRY", "30")),
        cert_force_reissue=_bool_env("CERT_FORCE_REISSUE", False),
    )


def _build_dns_settings(domain: str, enablement: Enablement) -> dns_driver.DnsRecordsSettings:
    """Build DnsRecordsSettings for the apex/wildcard/mail/mta-sts A/AAAA + CAA
    reconciler. Refuses to start without PUBLIC_IPV4 -- every record group this
    publisher writes derives from it.

    Enablement flags come straight from `compute_enablement` (the single source
    of truth). In particular `mta_enabled` means "the built-in MTA is deployed"
    (with-mta profile + a provider), NOT merely "DNS_PROVIDER is set" -- so an
    edge-only deployment publishes ONLY the proxied apex, never mail/mta-sts."""
    public_ipv4 = os.environ.get("PUBLIC_IPV4", "").strip()
    public_ipv6 = os.environ.get("PUBLIC_IPV6", "").strip()
    if not public_ipv4:
        raise RuntimeError(
            "DNS publishing is enabled (cert renewal, a Cloudflare edge profile, or the "
            "built-in MTA) but PUBLIC_IPV4 is unset. The publisher writes A records for "
            "${DOMAIN}, *.${DOMAIN}, mail.${DOMAIN}, and mta-sts.${DOMAIN} from PUBLIC_IPV4."
        )
    # Validate the IP format eagerly so a typo doesn't only surface as a
    # provider-side error mid-reconcile.
    dns_driver.validate_ipv4(public_ipv4)
    if public_ipv6:
        dns_driver.validate_ipv6(public_ipv6)
    return dns_driver.DnsRecordsSettings(
        domain=domain,
        dns_provider=os.environ.get("DNS_PROVIDER", "none").strip().lower(),
        public_ipv4=public_ipv4,
        public_ipv6=public_ipv6,
        cert_enabled=enablement.cert_enabled,
        mta_enabled=enablement.mta_enabled,
        edge_enabled=enablement.edge_enabled,
    )


def _try_advance_dkim(domain: str, selector_prefix: str, counters: dict[str, int]) -> None:
    try:
        state = rotation.read_state(keydir=KEYDIR)
        had_trigger = _has_explicit_trigger()
        new_state = advance_state(state, domain, selector_prefix)
        if had_trigger:
            _consume_trigger()
        if new_state != state:
            rotation.write_state(new_state, keydir=KEYDIR)
            rotation.trigger_opendkim_reload(keydir=KEYDIR)
            logger.info("rotation: %s -> %s", state.state, new_state.state)
        counters["dkim"] = 0
    except Exception:
        counters["dkim"] = counters.get("dkim", 0) + 1
        logger.exception("dkim rotation step failed (%d consecutive)", counters["dkim"])


def _try_advance_cert(domain: str, counters: dict[str, int]) -> None:
    try:
        settings = _build_cert_settings(domain)
        state = cert_state.read_state()
        had_trigger = _has_cert_trigger()
        lego = cert_driver.LegoRunner()
        new_state = cert_driver.advance_cert_state(
            state,
            settings=settings,
            lego=lego,
            trigger_present=had_trigger,
        )
        if had_trigger:
            _consume_cert_trigger()
        if new_state != state:
            cert_state.write_state(new_state)
            logger.info("cert: %s -> %s", state.state, new_state.state)
        counters["cert"] = 0
    except Exception:
        counters["cert"] = counters.get("cert", 0) + 1
        logger.exception("cert step failed (%d consecutive)", counters["cert"])


def _has_dns_trigger() -> bool:
    return dns_records_state.trigger_path().exists()


def _consume_dns_trigger() -> None:
    try:
        dns_records_state.trigger_path().unlink()
    except OSError:
        pass


def _try_advance_dns(domain: str, counters: dict[str, int], enablement: Enablement) -> None:
    """Reconcile apex/wildcard/mail/mta-sts A/AAAA + CAA records. Runs whenever
    cert renewal, a Cloudflare edge profile, or the built-in MTA needs address
    records (caller's gate: enablement.dns_enabled). Matches the dkim/cert tick
    pattern; the pure-function reconciler makes a no-drift tick a cheap no-op."""
    try:
        settings = _build_dns_settings(domain, enablement)
        state = dns_records_state.read_state()
        had_trigger = _has_dns_trigger()
        runner = dns_driver.PosternDnsRunner(dns_provider=settings.dns_provider)
        new_state = dns_driver.reconcile_apex_dns(state, settings=settings, runner=runner)
        if had_trigger:
            _consume_dns_trigger()
        if new_state != state:
            dns_records_state.write_state(new_state)
            # Only log on meaningful transitions; consecutive_failures bumps are noisy.
            if new_state.last_reconciled_iso != state.last_reconciled_iso:
                logger.info(
                    "dns: reconciled A/AAAA + CAA (v4=%s v6=%s apex_proxied=%s mta_sts=%s)",
                    new_state.last_published_ipv4 or "(unset)",
                    new_state.last_published_ipv6 or "(unset)",
                    new_state.last_published_apex_proxied,
                    new_state.last_published_mta_sts_present,
                )
        counters["dns"] = 0
    except Exception:
        counters["dns"] = counters.get("dns", 0) + 1
        logger.exception("dns reconcile step failed (%d consecutive)", counters["dns"])


# MTA records reconciler (#118) ========================================================================================
def _has_mta_records_trigger() -> bool:
    return mta_records_driver.trigger_path(keydir=KEYDIR).exists()


def _consume_mta_records_trigger() -> None:
    try:
        mta_records_driver.trigger_path(keydir=KEYDIR).unlink()
    except OSError:
        pass


def _build_mta_records_settings(domain: str) -> mta_records_driver.MtaRecordsSettings:
    return mta_records_driver.MtaRecordsSettings(
        domain=domain,
        dns_provider=os.environ.get("DNS_PROVIDER", "none").strip().lower(),
        admin_email=os.environ.get("MTA_ADMIN_EMAIL", "").strip(),
    )


def _try_advance_mta_records(domain: str, counters: dict[str, int]) -> None:
    """Reconcile MX/SPF/DMARC/MTA-STS/TLS-RPT/TLSA records. Runs whenever
    DKIM is enabled (the same gate as the rotation loop) -- the reconciler's
    pure-function design means a tick with no drift is a cheap no-op."""
    try:
        settings = _build_mta_records_settings(domain)
        state = mta_records_driver.read_state(keydir=KEYDIR)
        had_trigger = _has_mta_records_trigger()
        runner = mta_records_driver.PosternDnsRunner()
        cert_pem_path = cert_state.DEFAULT_CERTDIR / "live" / domain / "fullchain.pem"
        new_state = mta_records_driver.reconcile_mta_records(
            state, settings=settings, cert_pem_path=cert_pem_path, runner=runner
        )
        if had_trigger:
            _consume_mta_records_trigger()
        if new_state != state:
            mta_records_driver.write_state(new_state, keydir=KEYDIR)
            if new_state.last_reconciled_iso != state.last_reconciled_iso:
                logger.info("mta-dns: reconciled MTA records (MX/SPF/DMARC/MTA-STS/TLS-RPT/TLSA)")
        counters["mta_records"] = 0
    except Exception:
        counters["mta_records"] = counters.get("mta_records", 0) + 1
        logger.exception("mta-dns reconcile step failed (%d consecutive)", counters["mta_records"])


# Edge IP-range publisher (Cloudflare real-IP allowlist) ===============================================================
def _try_advance_edge(counters: dict[str, int]) -> None:
    """Refresh the nginx real-IP allowlist from Cloudflare's published ranges.

    Runs only under EDGE_PROFILE=cloudflare (the caller gates on
    enablement.edge_enabled -- owned by the enable-gate+loop task). Expected
    failures (network, decode, CF success=false) arrive as result.error, already
    carrying the exception type name; we bump counters['edge'] and warn, leaving
    the last-known-good file in place. An UNEXPECTED exception type propagates out
    of reconcile_edge_ranges and crashes the tick loudly -- intentionally NOT
    caught here (contrast the dkim/cert/dns/mta wrappers' broad except)."""
    result = edge_ranges.reconcile_edge_ranges(
        fetcher=edge_ranges.CloudflareIpsFetcher(),
        out_path=edge_ranges.edge_ranges_path(),
    )
    if result.error:
        counters["edge"] = counters.get("edge", 0) + 1
        logger.warning("edge: range reconcile failed (%d consecutive): %s", counters["edge"], result.error)
        return
    counters["edge"] = 0
    if result.changed:
        logger.info("edge: refreshed Cloudflare ranges (%d ipv4, %d ipv6)", result.ipv4_count, result.ipv6_count)


def _sleep_with_triggers() -> None:
    """Sleep up to TICK_SECONDS, returning early if any trigger file appears."""
    slept = 0
    while slept < TICK_SECONDS:
        if (_has_explicit_trigger() or _has_cert_trigger() or _has_dns_trigger() or _has_mta_records_trigger()):
            break
        time.sleep(TRIGGER_POLL_SECONDS)
        slept += TRIGGER_POLL_SECONDS


def run_combined_loop(domain: str, selector_prefix: str, enablement: Enablement) -> NoReturn:
    counters: dict[str, int] = {"dkim": 0, "cert": 0, "dns": 0, "mta_records": 0, "edge": 0}
    ticks: dict[str, Callable[[], None]] = {
        "dkim": lambda: _try_advance_dkim(domain, selector_prefix, counters),
        "cert": lambda: _try_advance_cert(domain, counters),
        "dns": lambda: _try_advance_dns(domain, counters, enablement),
        "mta_records": lambda: _try_advance_mta_records(domain, counters),
        # _try_advance_edge takes only `counters` -- Cloudflare's ranges are
        # global, so there is no per-domain argument.
        "edge": lambda: _try_advance_edge(counters),
    }
    while True:
        run_enabled_ticks(enablement, ticks)
        _sleep_with_triggers()


def main() -> NoReturn:
    domain = _require("DOMAIN")
    selector_prefix = os.environ.get("MTA_DKIM_SELECTOR_PREFIX", "s")
    try:
        rotation.validate_selector_base(selector_prefix)
    except ValueError as e:
        die(str(e))

    enablement = compute_enablement(
        dns_provider=os.environ.get("DNS_PROVIDER", "none"),
        cert_renewal=_bool_env("CERT_RENEWAL", False),
        edge_profile=os.environ.get("EDGE_PROFILE", "none"),
        # "MTA deployed" is the with-mta compose profile, injected into this
        # container's env as COMPOSE_PROFILES. NOT inferred from DNS_PROVIDER:
        # the Cloudflare edge profile also sets DNS_PROVIDER=cloudflare without
        # deploying the MTA.
        mta_deployed=mta_deployed_from_profiles(os.environ.get("COMPOSE_PROFILES", "")),
    )

    # DKIM init is unconditional (matches the pre-cert-renewal behaviour).
    # The mta container blocks startup waiting for state.json regardless of
    # DNS_PROVIDER, so we always emit a key. Cost is a few KB on the
    # postern-mta-data volume even in cert-only / edge-only deployments.
    state = ensure_initial_key(domain, selector_prefix)
    logger.info("rotation state on startup: %s, selectors=%s", state.state, state.active_selectors)

    if not (enablement.dkim_enabled or enablement.cert_enabled or enablement.edge_enabled):
        logger.info(
            "nothing to publish (DNS_PROVIDER=none, or CERT_RENEWAL=false and EDGE_PROFILE=none, "
            "or the built-in MTA is not deployed) -- exiting"
        )
        sys.exit(0)

    run_combined_loop(domain, selector_prefix, enablement)


if __name__ == "__main__":
    # Don't trap SIGTERM -- let tini deliver it cleanly.
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    main()
