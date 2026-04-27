"""Admin CLI for managing users and connections."""

from __future__ import annotations

import asyncio
import secrets
from pathlib import Path

import typer

from postern import db
from postern.models import Connection, User
from postern.settings import Settings
from postern.ss_config import generate_password

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
def connection_add(user_email: str, label: str) -> None:
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
            )
            await db.create_connection(database, conn)
            return conn

    conn = run(_add())
    if conn is None:
        typer.echo(f"User not found: {user_email}")
        raise typer.Exit(1)
    typer.echo(f"Created connection {conn.id}")
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
        typer.echo(f"  {c.id}  {c.label}  {status}")


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


if __name__ == "__main__":
    app()
