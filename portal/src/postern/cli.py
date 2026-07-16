"""Admin CLI for managing users and connections."""

from __future__ import annotations

import asyncio
import secrets
from enum import Enum
from pathlib import Path

import typer

from postern import db
from postern.models import Connection, User
from postern.settings import Settings
from postern.ss_config import generate_password


class PluginChoice(str, Enum):
    """SIP003 plugin choice for a connection. Typer renders this as a
    click.Choice on the CLI. The .value is what callers see (e.g.
    `--plugin v2ray-plugin`), and what's persisted to the connections.plugin
    column."""

    v2ray = "v2ray-plugin"
    galoshes = "galoshes"


app = typer.Typer(name="postern")
user_app = typer.Typer(name="user", help="Manage users")
connection_app = typer.Typer(name="connection", help="Manage connections")
mta_app = typer.Typer(name="mta", help="Manage the built-in MTA")
cert_app = typer.Typer(name="cert", help="Manage TLS certificates (auto-renewal mode)")
app.add_typer(user_app)
app.add_typer(connection_app)
app.add_typer(mta_app)
app.add_typer(cert_app)


def _settings() -> Settings:
    return Settings()


def _trigger_reconcile(settings: Settings) -> Path:
    trigger = Path(settings.database_path).parent / ".reconcile-now"
    trigger.touch()
    return trigger


def run(coro):
    return asyncio.run(coro)


# User commands ========================================================================================================
@user_app.command("add")
def user_add(name: str, email: str) -> None:
    """Create a new user."""
    settings = _settings()

    async def _add():
        async with db.get_connection(settings.database_path) as database:
            await db.migrate(database)
            user = User(name=name, email=email)
            await db.create_user(database, user)
            return user

    user = run(_add())
    typer.echo(f"Created user {user.name} ({user.id})")


@user_app.command("list")
def user_list() -> None:
    """List all users."""
    settings = _settings()

    async def _list():
        async with db.get_connection(settings.database_path) as database:
            await db.migrate(database)
            return await db.list_users(database)

    users = run(_list())
    if not users:
        typer.echo("No users.")
        return
    for u in users:
        typer.echo(f"  {u.id}  {u.name}  <{u.email}>")


@user_app.command("disable")
def user_disable(email: str) -> None:
    """Disable all connections for a user."""
    settings = _settings()

    async def _disable():
        async with db.get_connection(settings.database_path) as database:
            await db.migrate(database)
            user = await db.get_user_by_email(database, email)
            if user is None:
                return None
            connections = await db.list_connections(database, user_id=user.id)
            for conn in connections:
                await db.set_connection_enabled(database, conn.id, False)
            return len(connections)

    count = run(_disable())
    if count is None:
        typer.echo(f"User not found: {email}")
        raise typer.Exit(1)
    typer.echo(f"Disabled {count} connection(s)")
    _trigger_reconcile(settings)


@user_app.command("delete")
def user_delete(email: str) -> None:
    """Delete a user and all their connections."""
    settings = _settings()

    async def _delete():
        async with db.get_connection(settings.database_path) as database:
            await db.migrate(database)
            user = await db.get_user_by_email(database, email)
            if user is None:
                return False
            await db.delete_user(database, user.id)
            return True

    if not run(_delete()):
        typer.echo(f"User not found: {email}")
        raise typer.Exit(1)
    typer.echo(f"Deleted user {email}")
    _trigger_reconcile(settings)


# Connection commands ==================================================================================================
@connection_app.command("add")
def connection_add(
    user_email: str,
    label: str,
    plugin: PluginChoice = typer.Option(
        PluginChoice.v2ray,
        "--plugin",
        help="SIP003 plugin: 'v2ray-plugin' (default) or 'galoshes' (adds UDP via yamux).",
    ),
) -> None:
    """Create a new connection for a user."""
    settings = _settings()

    async def _add():
        async with db.get_connection(settings.database_path) as database:
            await db.migrate(database)
            user = await db.get_user_by_email(database, user_email)
            if user is None:
                return None

            path_token = secrets.token_hex(12)
            password = generate_password()

            conn = Connection(
                user_id=user.id,
                path_token=path_token,
                label=label,
                password=password,
                plugin=plugin.value,
            )
            await db.create_connection(database, conn)
            return conn

    conn = run(_add())
    if conn is None:
        typer.echo(f"User not found: {user_email}")
        raise typer.Exit(1)
    typer.echo(f"Created connection {conn.id} ({conn.plugin})")
    _trigger_reconcile(settings)


@connection_app.command("list")
def connection_list(user_email: str | None = None) -> None:
    """List connections, optionally filtered by user."""
    settings = _settings()

    async def _list():
        async with db.get_connection(settings.database_path) as database:
            await db.migrate(database)
            user_id = None
            if user_email:
                user = await db.get_user_by_email(database, user_email)
                if user is None:
                    typer.echo(f"User not found: {user_email}")
                    raise typer.Exit(1)
                user_id = user.id
            return await db.list_connections(database, user_id=user_id)

    connections = run(_list())
    if not connections:
        typer.echo("No connections.")
        return
    for c in connections:
        status = "enabled" if c.enabled else "DISABLED"
        typer.echo(f"  {c.id}  {c.label}  [{c.plugin}]  {status}")


@connection_app.command("disable")
def connection_disable(id: str) -> None:
    """Disable a connection."""
    settings = _settings()

    async def _disable():
        async with db.get_connection(settings.database_path) as database:
            await db.migrate(database)
            return await db.set_connection_enabled(database, id, False)

    if not run(_disable()):
        typer.echo(f"Connection not found: {id}")
        raise typer.Exit(1)
    typer.echo("Connection disabled")
    _trigger_reconcile(settings)


@connection_app.command("enable")
def connection_enable(id: str) -> None:
    """Enable a connection."""
    settings = _settings()

    async def _enable():
        async with db.get_connection(settings.database_path) as database:
            await db.migrate(database)
            return await db.set_connection_enabled(database, id, True)

    if not run(_enable()):
        typer.echo(f"Connection not found: {id}")
        raise typer.Exit(1)
    typer.echo("Connection enabled")
    _trigger_reconcile(settings)


# Reconcile command ====================================================================================================
@app.command("reconcile")
def reconcile() -> None:
    """Wake the reconciler immediately instead of waiting for the next poll.

    Creates the trigger file the reconciler watches. Equivalent to `touch
    /data/.reconcile-now`, but works in the distroless production image which
    ships no shell or busybox.
    """
    trigger = _trigger_reconcile(_settings())
    typer.echo(f"Reconcile triggered: {trigger}")


# MTA commands =========================================================================================================
@mta_app.command("show-dns")
def mta_show_dns() -> None:
    """Print the DNS records the deployer must publish for the built-in MTA."""
    from postern.mta import dkim as mta_dkim
    from postern.mta import dns as mta_dns
    from postern.mta import rotation
    settings = _settings()

    state = rotation.read_state()
    pubkeys: dict[str, str] = {}
    for selector in state.active_selectors:
        try:
            pubkeys[selector] = mta_dkim.read_local_pubkey(selector)
        except mta_dkim.DkimKeyNotFoundError as e:
            typer.echo(f"warning: {e}", err=True)

    records = mta_dns.expected_records(
        settings.domain,
        pubkeys,
        admin_email=settings.mta_admin_email,
    )
    for label, lines in records.items():
        for line in lines:
            typer.echo(f"{label}\t{line}")


@mta_app.command("verify-dns")
def mta_verify_dns_cmd() -> None:
    """Resolve and check every required DNS record. Exits 1 if any fail."""
    from postern.mta import dkim as mta_dkim
    from postern.mta import dns as mta_dns
    from postern.mta import rotation
    settings = _settings()

    state = rotation.read_state()
    pubkeys: dict[str, str] = {}
    for selector in state.active_selectors:
        try:
            pubkeys[selector] = mta_dkim.read_local_pubkey(selector)
        except mta_dkim.DkimKeyNotFoundError as e:
            typer.echo(f"FAIL: {e}", err=True)
            raise typer.Exit(1)

    if not pubkeys:
        typer.echo(
            "FAIL: no DKIM keys yet -- has the provisioner generated the first keypair? "
            "Bring up the stack with `docker compose up -d` first.",
            err=True,
        )
        raise typer.Exit(1)

    # The CLI never has a validating local resolver (it uses Docker's embedded
    # DNS via the system stub), so DNSSEC enforcement is done here via the
    # external 2-of-3 consensus check. mta_dns.verify is always called with
    # require_dnssec=False to avoid the AD-bit check inside it running against
    # a non-validating resolver.
    from postern.mta import dnssec
    setting = settings.mta_require_dnssec  # bool | Literal["auto"]
    dnssec_failures: list[str] = []
    signed: bool | None = None
    if setting is True:
        dnssec_failures = dnssec.check(settings.domain)
    elif setting == "auto":
        consensus = dnssec.check(settings.domain)
        signed = not consensus
        # auto never fails the command; outcome is reported below.

    verify_failures = mta_dns.verify(
        settings.domain,
        pubkeys,
        admin_email=settings.mta_admin_email,
        require_dnssec=False,
    )

    all_failures = list(dnssec_failures) + list(verify_failures)
    if all_failures:
        for f in all_failures:
            typer.echo(f"FAIL: {f}", err=True)
        raise typer.Exit(1)
    typer.echo("All DNS records verified.")
    if setting == "auto":
        outcome = "enforce" if signed else "skip"
        typer.echo(f"DNSSEC: auto-detect resolved to {outcome} for {settings.domain}")


@mta_app.command("rotate-dkim")
def mta_rotate_dkim() -> None:
    """Trigger a manual DKIM rotation step. Writes a trigger file the provisioner watches."""
    from postern.mta import rotation
    path = rotation.trigger_rotation()
    typer.echo(f"Rotation requested: {path}. The provisioner advances the state machine on its next poll.")


@mta_app.command("rotation-status")
def mta_rotation_status() -> None:
    """Show current DKIM rotation state."""
    from postern.mta import rotation
    state = rotation.read_state()
    typer.echo(f"State: {state.state}")
    typer.echo(f"Schema version: {state.schema_version}")
    typer.echo(f"Active selectors: {', '.join(state.active_selectors) or '(none)'}")
    if state.retiring_selector:
        typer.echo(f"Retiring selector: {state.retiring_selector}")
    typer.echo(f"Last rotation: {state.last_rotation_iso or '(never)'}")
    typer.echo(f"Next rotation due: {state.next_rotation_iso or '(unscheduled)'}")
    if state.consecutive_failures:
        typer.echo(f"Consecutive failures: {state.consecutive_failures}")


@mta_app.command("dnssec-status")
def mta_dnssec_status() -> None:
    """Check whether the sending domain is DNSSEC-signed (uses external validating resolvers)."""
    from postern.mta import dnssec
    settings = _settings()
    failures = dnssec.check(settings.domain)
    signed = not failures
    if failures:
        for f in failures:
            typer.echo(f"FAIL: {f}", err=True)
    else:
        typer.echo(f"DNSSEC: {settings.domain} is signed and validating.")
    if settings.mta_require_dnssec == "auto":
        verb = "enforced" if signed else "skipped"
        typer.echo(f"With MTA_REQUIRE_DNSSEC=auto, this would be {verb} at startup.")
    if not signed:
        raise typer.Exit(1)


# Cert subcommands =====================================================================================================
def _cert_renewal_active(settings: Settings) -> bool:
    """Detect whether auto-renewal is wired into this deployment.

    True iff CERT_RENEWAL=true AND the cert volume is mounted (state.json
    is reachable, even if absent). False in BYO-certs mode.
    """
    if not settings.cert_renewal:
        return False
    from postern.cert import state as cert_state
    return cert_state.DEFAULT_CERTDIR.exists()


@cert_app.command("show")
def cert_show() -> None:
    """Show cert path, issuer, expiry, SAN list. Works in BYO and auto-renewal modes."""
    from postern.cert import inspect as cert_inspect
    from postern.cert import state as cert_state
    settings = _settings()
    fullchain = cert_state.DEFAULT_CERTDIR / "live" / settings.domain / "fullchain.pem"
    if not fullchain.exists():
        state = cert_state.read_state()
        typer.echo(f"no cert installed yet (state: {state.state})", err=True)
        raise typer.Exit(1)
    info = cert_inspect.read_cert(fullchain)
    typer.echo(f"path:      {fullchain}")
    typer.echo(f"issuer:    {info.issuer}")
    typer.echo(f"sans:      {', '.join(info.sans)}")
    typer.echo(f"not_before: {info.not_before.isoformat()}")
    typer.echo(f"not_after:  {info.not_after.isoformat()}")
    typer.echo(f"days_left:  {info.days_until_expiry():.1f}")
    state_path = cert_state.state_path()
    if state_path.exists():
        state = cert_state.read_state()
        typer.echo(f"state:     {state.state}")
        if state.last_issued_iso:
            typer.echo(f"last_issued: {state.last_issued_iso}")


@cert_app.command("verify")
def cert_verify() -> None:
    """Verify the deployed cert is valid, has the right SANs, and matches what nginx is serving.

    Five checks: file parseable; SANs == {<domain>, *.<domain>}; nginx-served cert
    matches on-disk; CAA record (if any) allows the issuer; state.json (if present)
    is consistent with on-disk cert.
    """
    import socket
    import ssl

    from postern.cert import inspect as cert_inspect
    from postern.cert import state as cert_state
    settings = _settings()
    fullchain = cert_state.DEFAULT_CERTDIR / "live" / settings.domain / "fullchain.pem"
    failures: list[str] = []

    # (1) parse
    try:
        info = cert_inspect.read_cert(fullchain)
    except (FileNotFoundError, ValueError) as e:
        typer.echo(f"FAIL: cannot parse cert at {fullchain}: {e}", err=True)
        raise typer.Exit(1)

    # (2) SAN list -- defends CT-leak hygiene
    expected_sans = {settings.domain, f"*.{settings.domain}"}
    if not info.sans_match(expected_sans):
        failures.append(f"SAN mismatch: expected {expected_sans}, got {set(info.sans)}")

    # (3) what nginx is serving (the portal container connects to nginx by name; not localhost)
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # we just want to read the cert
        with socket.create_connection(("nginx", 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=settings.domain) as ssock:
                served = ssock.getpeercert(binary_form=True)
        served_serial = cert_inspect.x509.load_der_x509_certificate(served).serial_number
        if served_serial != info.serial:
            failures.append(
                f"cert nginx is serving (serial {served_serial}) does not match on-disk cert (serial {info.serial})"
            )
    except (OSError, ssl.SSLError) as e:
        failures.append(f"could not connect to nginx:443 for cert verification: {e}")

    # (4) CAA RRset (best-effort: only fail if CAA exists and excludes the issuer)
    try:
        import dns.exception
        import dns.resolver
        ans = dns.resolver.resolve(settings.domain, "CAA")
        issuers = {r.value.decode() if isinstance(r.value, bytes) else r.value for r in ans}
        # Anchor on the URL; LE production = letsencrypt.org, staging = letsencrypt.org as well
        # so a CAA record with letsencrypt.org should accept either.
        expected_issuer = "letsencrypt.org"
        if not any(expected_issuer in i for i in issuers):
            failures.append(f"CAA record exists for {settings.domain} but doesn't include {expected_issuer}: {issuers}")
    except (dns.exception.DNSException, ImportError):
        # No CAA record is fine; CAA is opt-in.
        pass

    # (5) state.json consistency, if present
    state_path = cert_state.state_path()
    if state_path.exists():
        state = cert_state.read_state()
        if state.state == "INSTALLED" and set(state.sans) != set(info.sans):
            failures.append(f"state.json sans {set(state.sans)} disagree with on-disk sans {set(info.sans)}")

    if failures:
        for f in failures:
            typer.echo(f"FAIL: {f}", err=True)
        raise typer.Exit(1)
    typer.echo(f"cert OK: SANs={info.sans}, days_left={info.days_until_expiry():.1f}")


@cert_app.command("renew")
def cert_renew() -> None:
    """Trigger immediate renewal. Works only in auto-renewal mode."""
    settings = _settings()
    if not _cert_renewal_active(settings):
        typer.echo(
            "cert auto-renewal is not enabled in this deployment "
            "(set CERT_RENEWAL=true and add compose.cert.yaml to COMPOSE_FILE)",
            err=True,
        )
        raise typer.Exit(1)
    from postern.cert import state as cert_state
    path = cert_state.trigger_renewal()
    typer.echo(f"trigger written: {path}")


@cert_app.command("renewal-status")
def cert_renewal_status() -> None:
    """Show the cert renewal state machine."""
    from postern.cert import state as cert_state
    state = cert_state.read_state()
    typer.echo(f"state:                {state.state}")
    typer.echo(f"sans:                 {', '.join(state.sans) if state.sans else '(none)'}")
    typer.echo(f"not_after:            {state.not_after_iso or '(none)'}")
    typer.echo(f"last_issued:          {state.last_issued_iso or '(none)'}")
    typer.echo(f"last_attempt:         {state.last_attempt_iso or '(none)'}")
    typer.echo(f"consecutive_failures: {state.consecutive_failures}")
    typer.echo(f"acme_directory:       {state.acme_directory or '(none)'}")
    if state.state == "FAILED":
        typer.echo(f"last_failed_state:    {state.last_failed_state}")


dns_app = typer.Typer(name="dns", help="Manage cert-manager-driven DNS records (A/AAAA/CAA)")
app.add_typer(dns_app)


@dns_app.command("show")
def dns_show() -> None:
    """Show the apex/wildcard A/AAAA + CAA records the cert manager publishes,
    plus the current state.json view of what's been published."""
    from postern.cert import dns_records as dns_state
    settings = _settings()
    state = dns_state.read_state()

    pub_ipv4, pub_ipv6, pub_caa = dns_state.published_summary(state, settings.domain)
    typer.echo(f"domain:               {settings.domain}")
    typer.echo(f"public_ipv4:          {settings.public_ipv4 or '(unset)'}")
    typer.echo(f"public_ipv6:          {settings.public_ipv6 or '(unset)'}")
    typer.echo(f"last_published_ipv4:  {pub_ipv4 or '(unset)'}")
    typer.echo(f"last_published_ipv6:  {pub_ipv6 or '(unset)'}")
    typer.echo(f"last_published_caa:   {pub_caa or '(unset)'}")
    typer.echo(f"last_reconciled_iso:  {state.last_reconciled_iso or '(never)'}")
    typer.echo(f"consecutive_failures: {state.consecutive_failures}")
    typer.echo("")
    typer.echo("Records the reconciler publishes:")
    for fqdn in (settings.domain, f"*.{settings.domain}", f"mail.{settings.domain}"):
        typer.echo(f"  {fqdn:40} A     {settings.public_ipv4 or '(skipped: PUBLIC_IPV4 unset)'}")
        if settings.public_ipv6:
            typer.echo(f"  {fqdn:40} AAAA  {settings.public_ipv6}")
    typer.echo(f"  {settings.domain:40} CAA   0 issue \"letsencrypt.org\"")


@dns_app.command("verify")
def dns_verify() -> None:
    """Check live DNS matches the expected apex/wildcard A/AAAA + CAA records.
    Exits non-zero on drift."""
    import dns.exception
    import dns.resolver

    from postern.cert import dns_records as dns_state

    settings = _settings()
    if not settings.cert_renewal:
        typer.echo("CERT_RENEWAL is not enabled in this deployment", err=True)
        raise typer.Exit(1)

    resolver = dns.resolver.Resolver(configure=True)
    failures: list[str] = []

    def _query(name: str, rdtype: str) -> set[str]:
        try:
            ans = resolver.resolve(name, rdtype, raise_on_no_answer=False)
            return {r.to_text() for r in ans} if ans.rrset is not None else set()
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            return set()

    for fqdn in (settings.domain, f"*.{settings.domain}", f"mail.{settings.domain}"):
        # Wildcard query: resolvers expand *.<dom> only for unmatched names, so probe
        # a known sub-name to exercise the wildcard.
        probe = fqdn if not fqdn.startswith("*.") else "doctor-probe." + fqdn[2:]
        got = _query(probe, "A")
        if settings.public_ipv4 not in got:
            failures.append(f"A    {fqdn:40} expected {settings.public_ipv4}, got {got or '(empty)'}")
        if settings.public_ipv6:
            got6 = _query(probe, "AAAA")
            if settings.public_ipv6 not in got6:
                failures.append(f"AAAA {fqdn:40} expected {settings.public_ipv6}, got {got6 or '(empty)'}")

    caa = _query(settings.domain, "CAA")
    if not any('issue "letsencrypt.org"' in v for v in caa):
        failures.append(f"CAA  {settings.domain:40} expected 'issue \"letsencrypt.org\"', got {caa or '(empty)'}")

    state = dns_state.read_state()
    if state.last_reconciled_iso is None:
        failures.append("state: reconciler has not yet completed a tick (last_reconciled_iso is null)")

    if failures:
        for f in failures:
            typer.echo(f"FAIL: {f}", err=True)
        raise typer.Exit(1)
    typer.echo("dns OK: apex/wildcard A/AAAA + CAA match expected values")


@dns_app.command("publish")
def dns_publish() -> None:
    """Trigger the MTA-records reconciler to publish on the next provisioner
    tick (without waiting for the 1h cadence). Writes the .publish-mta-dns
    trigger file on the postern-mta-data volume; provisioner picks it up
    within TRIGGER_POLL_SECONDS (5s by default)."""
    keydir = Path("/var/lib/opendkim")
    trigger = keydir / ".publish-mta-dns"
    trigger.parent.mkdir(parents=True, exist_ok=True)
    trigger.touch()
    typer.echo(f"trigger written: {trigger}")


# ECH commands =========================================================================================================
ech_app = typer.Typer(name="ech", help="Verify the Cloudflare ECH front (Encrypted ClientHello)")
app.add_typer(ech_app)


@ech_app.command("show")
def ech_show() -> None:
    """Show ECH settings, the provisioner's zone-ECH state (incl. the last
    Cloudflare error), and whether the front is serving ech= (via DoH)."""
    from postern.ech import check_apex_ech
    from postern_provisioner import ech as ech_state
    settings = _settings()
    typer.echo(f"domain:                  {settings.domain}")
    typer.echo(f"ech_enabled:             {settings.ech_enabled}")
    typer.echo(f"ech_doh_url:             {settings.ech_doh_url}")
    typer.echo(f"edge_profile:            {settings.edge_profile}")
    typer.echo(f"dns_provider:            {settings.dns_provider}")
    typer.echo(f"edge_cf_manage_zone_ech: {settings.edge_cf_manage_zone_ech}")
    # Provisioner-written state (shared postern-mta-data volume). Surfaces the
    # verbatim Cloudflare error when enablement is failing (e.g. plan/token scope).
    state = ech_state.read_state()
    typer.echo(f"zone_ech_enabled_at:     {state.last_enabled_ok_iso or '(never)'}")
    typer.echo(f"zone_ech_failures:       {state.consecutive_failures}")
    typer.echo(f"zone_ech_last_error:     {state.last_error or '(none)'}")
    status = check_apex_ech(settings.domain, settings.ech_doh_url)
    typer.echo(f"front serving ech= :     {status}")


@ech_app.command("verify")
def ech_verify() -> None:
    """Check the apex HTTPS record serves ech= over DoH. Exit codes: 0 present,
    1 confirmed absent (front not serving ECH), 2 inconclusive (no record yet /
    DoH unreachable)."""
    from postern.ech import check_apex_ech
    settings = _settings()
    if not settings.ech_enabled:
        typer.echo("ECH_ENABLED is not set in this deployment", err=True)
        raise typer.Exit(1)
    status = check_apex_ech(settings.domain, settings.ech_doh_url)
    if status == "present":
        typer.echo(f"ech OK: {settings.domain} HTTPS record serves ech=")
        return
    if status == "absent":
        typer.echo(
            f"FAIL: {settings.domain} HTTPS record has no ech= param -- the front is not serving "
            "ECH. Check the Cloudflare zone ECH setting (postern manages it when "
            "EDGE_CF_MANAGE_ZONE_ECH=true) and that the apex is orange-clouded.",
            err=True,
        )
        raise typer.Exit(1)
    typer.echo(
        f"INCONCLUSIVE: no HTTPS record for {settings.domain} resolved over DoH "
        f"({settings.ech_doh_url}). CF may still be propagating, or DoH is unreachable.",
        err=True,
    )
    raise typer.Exit(2)


# Doctor ===============================================================================================================
def _tlsa_cert_hex(domain: str, certdir: Path = Path("/etc/letsencrypt")) -> str | None:
    """sha256(SubjectPublicKeyInfo) hex of the leaf cert for `domain`, or None
    if the cert isn't on disk yet (first-issuance bootstrap window)."""
    import hashlib

    fullchain = certdir / "live" / domain / "fullchain.pem"
    try:
        pem = fullchain.read_bytes()
    except FileNotFoundError:
        return None

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    leaf = x509.load_pem_x509_certificates(pem)[0]
    spki_der = leaf.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki_der).hexdigest()


@app.command("doctor")
def doctor_cmd(
    external_only: bool = typer.Option(False, "--external-only", help="Only run external (DS, PTR) checks"),
    postern_only: bool = typer.Option(False, "--postern-only", help="Only run postern-managed record checks"),
    connectivity_only: bool = typer.Option(False, "--connectivity-only", help="Only run connectivity probes"),
    output_json: bool = typer.Option(False, "--json", help="Emit structured JSON instead of the human table"),
) -> None:
    """Verify operator-prereqs and live record state.

    Three sections:
      1. External  -- things postern cannot publish itself (DS at registrar, PTR at VPS).
      2. Postern-managed -- live DNS matches what postern claims to publish.
      3. Connectivity -- :443/tcp serves a valid cert, :25/tcp is reachable.

    Exits non-zero on any FAIL so this is usable as a bring-up gate or CI smoke step.
    """
    from postern import doctor
    from postern.mta import dkim as mta_dkim
    from postern.mta import rotation

    settings = _settings()
    selected = (external_only, postern_only, connectivity_only)
    if sum(selected) > 1:
        typer.echo("at most one of --external-only/--postern-only/--connectivity-only may be set", err=True)
        raise typer.Exit(2)
    if external_only:
        sections: tuple[doctor.Section, ...] = (doctor.EXTERNAL, )
    elif postern_only:
        sections = (doctor.POSTERN_MANAGED, )
    elif connectivity_only:
        sections = (doctor.CONNECTIVITY, )
    else:
        sections = (doctor.EXTERNAL, doctor.POSTERN_MANAGED, doctor.CONNECTIVITY)

    pubkeys: dict[str, str] = {}
    state = rotation.read_state()
    for selector in state.active_selectors:
        try:
            pubkeys[selector] = mta_dkim.read_local_pubkey(selector)
        except mta_dkim.DkimKeyNotFoundError:
            pass

    doctor_settings = doctor.DoctorSettings(
        domain=settings.domain,
        public_ipv4=settings.public_ipv4,
        public_ipv6=settings.public_ipv6 or None,
        admin_email=settings.mta_admin_email,
        tlsa_cert_hex=_tlsa_cert_hex(settings.domain),
        dkim_pubkey_by_selector=pubkeys,
    )

    report = doctor.run_doctor(doctor_settings, sections=sections)
    typer.echo(doctor.render_json(report) if output_json else doctor.render_text(report), nl=False)
    raise typer.Exit(report.exit_code)


if __name__ == "__main__":
    app()
