#!/usr/bin/env python3
"""Provisioner entrypoint -- generates initial DKIM keys and runs rotation state machine.

The provisioner is a sibling of the mta container; the two coordinate via
trigger files on the shared `postern-mta-data` volume:

  .rotate-dkim         portal CLI -> provisioner    (advance state machine)
  .reload-opendkim     provisioner -> mta           (HUP opendkim after key change)

Responsibilities:

1. On startup, ensure a DKIM keypair exists. If state.json is absent, generate
   the first selector (`<prefix>-<YYYY-MM>`) and write a STABLE state. This runs
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
from pathlib import Path
from typing import NoReturn

import dns.exception
import dns.resolver

# postern_mta is COPYed into /usr/lib/python3.13/site-packages/ at image build time.
from postern_mta import dkim as mta_dkim  # noqa: E402
from postern_mta import rotation  # noqa: E402

# Cert renewal driver -- imported via the postern.* namespace (also COPYed in by Dockerfile).
from postern.cert import state as cert_state  # noqa: E402
from postern_provisioner import cert as cert_driver  # noqa: E402

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

    selector = rotation.make_selector(selector_prefix)
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
        new_selector = rotation.make_selector(selector_prefix)
        if new_selector in state.active_selectors:
            # Same month; treat as already-rotated.
            return state
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


def _sleep_with_triggers() -> None:
    """Sleep up to TICK_SECONDS, returning early if any trigger file appears."""
    slept = 0
    while slept < TICK_SECONDS:
        if _has_explicit_trigger() or _has_cert_trigger():
            break
        time.sleep(TRIGGER_POLL_SECONDS)
        slept += TRIGGER_POLL_SECONDS


def run_combined_loop(domain: str, selector_prefix: str, *, dkim_enabled: bool, cert_enabled: bool) -> NoReturn:
    counters: dict[str, int] = {"dkim": 0, "cert": 0}
    while True:
        if dkim_enabled:
            _try_advance_dkim(domain, selector_prefix, counters)
        if cert_enabled:
            _try_advance_cert(domain, counters)
        _sleep_with_triggers()


def main() -> NoReturn:
    domain = _require("DOMAIN")
    selector_prefix = os.environ.get("MTA_DKIM_SELECTOR_PREFIX", "postern")
    dns_provider = os.environ.get("DNS_PROVIDER", "none").strip().lower()
    cert_renewal = _bool_env("CERT_RENEWAL", False)

    # DKIM init is unconditional (matches the pre-cert-renewal behaviour).
    # The mta container blocks startup waiting for state.json regardless of
    # DNS_PROVIDER, so we always emit a key. Cost is a few KB on the
    # postern-mta-data volume even in cert-only deployments without mta.
    state = ensure_initial_key(domain, selector_prefix)
    logger.info("rotation state on startup: %s, selectors=%s", state.state, state.active_selectors)

    dkim_enabled = dns_provider != "none"

    if not dkim_enabled and not cert_renewal:
        logger.info("DNS_PROVIDER=none and CERT_RENEWAL=false -- nothing to do, exiting")
        sys.exit(0)

    run_combined_loop(domain, selector_prefix, dkim_enabled=dkim_enabled, cert_enabled=cert_renewal)


if __name__ == "__main__":
    # Don't trap SIGTERM -- let tini deliver it cleanly.
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    main()
