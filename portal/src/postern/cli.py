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
app.add_typer(user_app)
app.add_typer(connection_app)
app.add_typer(mta_app)


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


if __name__ == "__main__":
    app()
