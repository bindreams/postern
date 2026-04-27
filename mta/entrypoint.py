#!/usr/bin/env python3
"""mta entrypoint -- starts Unbound, postsrsd, mta-sts-daemon, opendkim, then Postfix.

Reads env, renders config templates, waits for the provisioner to have generated
the initial DKIM keypair (via state.json on the shared volume), verifies DNS
records (refusing to start if MTA_VERIFY_DNS=true and any are missing), then
execs `postfix start-fg`.

Watches /var/lib/opendkim/.reload-opendkim in the background and HUPs opendkim
when the provisioner advances the rotation state machine.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import signal
import socket
import string
import subprocess
import sys
import threading
import time
from email.utils import parseaddr
from pathlib import Path
from typing import NoReturn

logging.basicConfig(level=logging.INFO, format="%(asctime)s mta-entrypoint %(levelname)s: %(message)s")
logger = logging.getLogger("entrypoint")

KEYDIR = Path("/var/lib/opendkim")
STATE_PATH = KEYDIR / "state.json"
RELOAD_TRIGGER = KEYDIR / ".reload-opendkim"
TEMPLATE_DIR = Path("/usr/local/share/mta-templates")


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


def _validate_admin_email(email: str, domain: str) -> None:
    addr = parseaddr(email)[1]
    if not addr or "@" not in addr:
        die(f"MTA_ADMIN_EMAIL={email!r} is not a valid email address")
    local, host = addr.rsplit("@", 1)
    if host.lower() == domain.lower():
        die(
            f"MTA_ADMIN_EMAIL ({email}) is on the same domain ({domain}) -- this would create "
            f"a forwarding loop. Use an external mailbox you read."
        )


def die(msg: str) -> NoReturn:
    logger.error(msg)
    sys.exit(1)


# Template rendering ===================================================================================================
def render_template(name: str, dest: Path, **vars: str) -> None:
    body = (TEMPLATE_DIR / name).read_text(encoding="utf-8")
    rendered = string.Template(body).substitute(vars)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(rendered, encoding="utf-8")


def regenerate_opendkim_tables(state: dict) -> None:
    """Re-emit /etc/opendkim/{KeyTable,SigningTable,TrustedHosts} from rotation state."""
    selectors: list[str] = state.get("active_selectors", [])
    if not selectors:
        return
    domain = os.environ["DOMAIN"]
    keytable = "\n".join(
        f"{selector}._domainkey.{domain} {domain}:{selector}:/var/lib/opendkim/{selector}.private"
        for selector in selectors
    )
    # SigningTable points by domain to the *latest* selector that should sign new mail.
    # Older selectors stay verifiable via the KeyTable but no longer sign.
    signing_selector = selectors[-1]
    signingtable = f"*@{domain} {signing_selector}._domainkey.{domain}\n"
    trustedhosts = "127.0.0.1\nlocalhost\n"
    Path("/etc/opendkim/KeyTable").write_text(keytable + "\n", encoding="utf-8")
    Path("/etc/opendkim/SigningTable").write_text(signingtable, encoding="utf-8")
    Path("/etc/opendkim/TrustedHosts").write_text(trustedhosts, encoding="utf-8")
    # opendkim runs as user `opendkim`, must be able to read the tables and key files.
    for path in ("/etc/opendkim/KeyTable", "/etc/opendkim/SigningTable", "/etc/opendkim/TrustedHosts"):
        shutil.chown(path, user="opendkim", group="opendkim")


# State.json ===========================================================================================================
def wait_for_state(timeout_s: int = 120) -> dict:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if STATE_PATH.exists():
            try:
                return json.loads(STATE_PATH.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as e:
                logger.warning("state.json unreadable, retrying: %s", e)
        time.sleep(1.0)
    die(
        f"provisioner has not generated initial DKIM keys after {timeout_s}s "
        f"(state.json at {STATE_PATH} missing); check provisioner logs"
    )


# Postmap helpers ======================================================================================================
def postmap_hash(path: Path) -> None:
    subprocess.run(["postmap", f"hash:{path}"], check=True)


# DNS verification =====================================================================================================
def verify_dns(domain: str, admin_email: str, require_dnssec: bool) -> None:
    sys.path.insert(0, "/usr/lib/python3.13/site-packages")
    import dns.resolver as _resolver

    from postern_mta import dkim as mta_dkim
    from postern_mta import dns as mta_dns
    from postern_mta import rotation

    state = rotation.read_state(keydir=KEYDIR)
    pubkeys = {selector: mta_dkim.read_local_pubkey(selector, keydir=KEYDIR) for selector in state.active_selectors}
    if not pubkeys:
        die("DKIM keys not present after wait_for_state -- provisioner output is inconsistent")

    # Use the local Unbound on 127.0.0.1 -- DANE/DNSSEC validation requires it.
    resolver = _resolver.Resolver(configure=False)
    resolver.nameservers = ["127.0.0.1"]
    resolver.lifetime = 10.0

    failures = mta_dns.verify(
        domain,
        pubkeys,
        admin_email=admin_email,
        require_dnssec=require_dnssec,
        resolver=resolver,
    )
    if failures:
        logger.error("DNS verification failed; the following records must be published or corrected:")
        for f in failures:
            logger.error("  %s", f)
        die("startup aborted (set MTA_VERIFY_DNS=false to bypass for dev/CI)")


# Service start helpers ================================================================================================
def start_unbound() -> subprocess.Popen:
    # auto-trust-anchor-file fetches the root key on first run (via unbound-anchor).
    Path("/var/lib/unbound").mkdir(parents=True, exist_ok=True)
    if not Path("/var/lib/unbound/root.key").exists():
        try:
            subprocess.run(["unbound-anchor", "-a", "/var/lib/unbound/root.key"], check=False)
        except OSError as e:
            logger.warning("unbound-anchor failed: %s", e)
    proc = subprocess.Popen(
        ["unbound", "-d", "-c", "/etc/unbound/unbound.conf"],
        stdout=sys.stdout,
        stderr=sys.stderr,
    )
    # Wait until it answers a query.
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", 53), timeout=1.0):
                return proc
        except OSError:
            time.sleep(0.5)
    die("Unbound did not start within 30s")


def start_postsrsd() -> subprocess.Popen:
    return subprocess.Popen(
        ["postsrsd", "-c", "/etc/postsrsd.conf"],
        stdout=sys.stdout,
        stderr=sys.stderr,
    )


def start_mta_sts_daemon() -> subprocess.Popen:
    return subprocess.Popen(
        ["postfix-mta-sts-daemon", "-c", "/etc/mta-sts-daemon.yml"],
        stdout=sys.stdout,
        stderr=sys.stderr,
    )


def start_opendkim() -> subprocess.Popen:
    return subprocess.Popen(
        ["opendkim", "-f", "-x", "/etc/opendkim/opendkim.conf"],
        stdout=sys.stdout,
        stderr=sys.stderr,
    )


# Reload watcher (background) ==========================================================================================
async def reload_watcher(opendkim_proc: subprocess.Popen, poll_seconds: float = 5.0) -> None:
    """Watch for .reload-opendkim trigger; on detection, HUP opendkim and re-render tables."""
    while True:
        await asyncio.sleep(poll_seconds)
        if not RELOAD_TRIGGER.exists():
            continue
        try:
            state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
            regenerate_opendkim_tables(state)
            opendkim_proc.send_signal(signal.SIGHUP)
            logger.info("opendkim reloaded after rotation")
        except (OSError, json.JSONDecodeError) as e:
            logger.warning("reload trigger present but reload failed: %s", e)
        finally:
            try:
                RELOAD_TRIGGER.unlink()
            except OSError:
                pass


# Main =================================================================================================================
def main() -> NoReturn:
    domain = _require("DOMAIN")
    verify_dns_enabled = _bool_env("MTA_VERIFY_DNS", default=True)
    require_dnssec = _bool_env("MTA_REQUIRE_DNSSEC", default=False)
    admin_email = os.environ.get("MTA_ADMIN_EMAIL", "").strip()
    bounce_local_part = (parseaddr(os.environ.get("SMTP_FROM", ""))[1] or "noreply@x").rsplit("@", 1)[0] or "noreply"
    dkim_selector_prefix = os.environ.get("MTA_DKIM_SELECTOR_PREFIX", "postern")
    mta_submit_cidr = os.environ.get("MTA_SUBMIT_CIDR", "172.30.42.0/29")
    e2e_transport_override = os.environ.get("MTA_E2E_TRANSPORT_OVERRIDE", "").strip()

    if verify_dns_enabled:
        if not admin_email:
            die("MTA_ADMIN_EMAIL is required in production (set MTA_VERIFY_DNS=false to bypass)")
        _validate_admin_email(admin_email, domain)

    logger.info("waiting for provisioner to generate initial DKIM key (state.json)...")
    state = wait_for_state()
    logger.info("rotation state: %s", state.get("state"))

    # Render configs.
    transport_override_block = ("transport_maps = hash:/etc/postfix/transport\n" if e2e_transport_override else "")
    render_template(
        "main.cf.tmpl",
        Path("/etc/postfix/main.cf"),
        DOMAIN=domain,
        MTA_SUBMIT_CIDR=mta_submit_cidr,
        TRANSPORT_OVERRIDE=transport_override_block,
    )
    render_template("master.cf.tmpl", Path("/etc/postfix/master.cf"))
    render_template(
        "opendkim.conf.tmpl",
        Path("/etc/opendkim/opendkim.conf"),
        DOMAIN=domain,
    )
    render_template("unbound.conf.tmpl", Path("/etc/unbound/unbound.conf"))
    render_template(
        "postsrsd.conf.tmpl",
        Path("/etc/postsrsd.conf"),
        DOMAIN=domain,
    )
    render_template("mta-sts-daemon.yml.tmpl", Path("/etc/mta-sts-daemon.yml"))
    render_template(
        "virtual.tmpl",
        Path("/etc/postfix/virtual"),
        DOMAIN=domain,
        BOUNCE_LOCAL_PART=bounce_local_part,
        MTA_ADMIN_EMAIL=admin_email or f"postmaster@{domain}",
    )
    render_template(
        "local_recipients.tmpl",
        Path("/etc/postfix/local_recipients"),
        DOMAIN=domain,
        BOUNCE_LOCAL_PART=bounce_local_part,
    )
    if e2e_transport_override:
        Path("/etc/postfix/transport").write_text(e2e_transport_override + "\n", encoding="utf-8")
        postmap_hash(Path("/etc/postfix/transport"))

    postmap_hash(Path("/etc/postfix/virtual"))
    postmap_hash(Path("/etc/postfix/local_recipients"))

    # postsrsd-secret: generate if missing.
    secret_path = KEYDIR / "postsrsd-secret"
    if not secret_path.exists():
        secret_path.write_bytes(os.urandom(32))
        os.chmod(secret_path, 0o600)
        shutil.chown(secret_path, user="opendkim", group="opendkim")

    regenerate_opendkim_tables(state)

    # /etc/resolv.conf -> Unbound. Some Alpine images ship a default resolv.conf
    # we need to overwrite (read_only:false in compose for this reason).
    Path("/etc/resolv.conf").write_text("nameserver 127.0.0.1\n", encoding="utf-8")

    # Start sidecars.
    unbound_proc = start_unbound()
    postsrsd_proc = start_postsrsd()
    mta_sts_proc = start_mta_sts_daemon()
    opendkim_proc = start_opendkim()
    logger.info("sidecars up: unbound, postsrsd, mta-sts-daemon, opendkim")

    if verify_dns_enabled:
        verify_dns(domain, admin_email, require_dnssec)
        logger.info("DNS verification passed")

    # Spawn the reload watcher in a background thread (asyncio.run blocks until cancelled).
    def _watcher_thread() -> None:
        asyncio.run(reload_watcher(opendkim_proc))

    threading.Thread(target=_watcher_thread, daemon=True).start()

    # Hand off to Postfix. tini at PID 1 reaps unbound/postsrsd/mta-sts-daemon/opendkim.
    logger.info("execing postfix start-fg")
    os.execvp("postfix", ["postfix", "start-fg"])


if __name__ == "__main__":
    main()
