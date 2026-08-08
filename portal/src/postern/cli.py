"""Admin CLI for managing users and connections."""

from __future__ import annotations

import asyncio
import secrets
from enum import Enum
from pathlib import Path

import typer

from postern import db, reconcile_wait
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


class EchChoice(str, Enum):
    """Per-connection ECH mode. .value is persisted to connections.ech."""

    never = "never"
    auto = "auto"
    always = "always"


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
    trigger = reconcile_wait.data_dir(settings.database_path) / ".reconcile-now"
    trigger.touch()
    return trigger


def _warn_if_identity_unresolved(settings: Settings) -> bool:
    """Print a loud warning when the reconciler cannot determine its own
    instance identity. In that state `_trigger_reconcile` above has no
    effect the next pass -- the reconciler skips ALL container work (see
    reconciler.reconcile) -- so a command that just reported success (e.g.
    `connection add`) would otherwise give no indication that no container
    will actually be created. Returns whether it warned.
    """
    from postern.reconciler import resolve_instance_id
    if resolve_instance_id(settings) is not None:
        return False
    typer.echo(
        "WARNING: could not determine this deployment's instance id (neither INSTANCE_ID "
        "nor COMPOSE_PROJECT_NAME is set) -- the reconciler will NOT create, remove, or "
        "restart any container until this is fixed. Check that the portal was started via "
        "`docker compose` with an up-to-date compose.yaml.",
        err=True,
    )
    return True


def _warn_if_disabled_connection_container_survives(settings: Settings, path_token: str) -> None:
    """Best-effort, read-only check: does this connection's container still
    exist but predate this instance's label (or belong to a different
    deployment)? If so the reconciler will never stop it on its own --
    surface the same manual-remediation guidance immediately, in the
    caller's own output, rather than leaving the operator to notice it
    only in the reconciler's logs. Called from both `connection disable`
    (connection stays in the DB, disabled) and `user delete` (connection
    row is gone entirely, cascaded away) -- in either case the connection
    is no longer in the reconciler's desired set, so its container is
    never again the target of a create() call and would otherwise get no
    signal at all. Never fatal: a Docker-side problem here is reported (not
    raised) and the caller still exits 0 -- the mutation itself already
    succeeded in the database, and this check is advisory, matching the
    reconciler's own equivalent-failure disposition (a logged warning, not
    a raised exception).
    """
    import docker
    import docker.errors
    from postern.reconciler import is_unlabelled_and_running

    name = f"ss-{path_token}"
    try:
        client = docker.DockerClient.from_env()
        try:
            container = client.containers.get(name)
        except docker.errors.NotFound:
            return
        finally:
            client.close()
    except Exception:
        typer.echo(
            f"NOTE: could not check whether container {name} for this connection is still running "
            "(docker-proxy unreachable?) -- if it predates instance labelling, the reconciler will "
            "not stop it automatically either; check manually.",
            err=True,
        )
        return

    if not is_unlabelled_and_running(container.labels or {}, container.status):
        return
    typer.echo(
        f"WARNING: container {name} for this connection is still running and predates instance "
        "labelling -- the reconciler will NOT stop it automatically. If you're sure it's safe, "
        f"remove it manually (`docker rm -f {name}`).",
        err=True,
    )


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
                return None, []
            connections = await db.list_connections(database, user_id=user.id)
            for conn in connections:
                await db.set_connection_enabled(database, conn.id, False)
            return len(connections), connections

    result = run(_disable())
    count, connections = result
    if count is None:
        typer.echo(f"User not found: {email}")
        raise typer.Exit(1)
    typer.echo(f"Disabled {count} connection(s)")
    _trigger_reconcile(settings)
    _warn_if_identity_unresolved(settings)
    # Same rationale as connection_disable/user_delete: a disabled connection's
    # container is never again a create() target, so the reconciler's own 409
    # path never sees it. Warn immediately, per connection, rather than only
    # via the reconciler's periodic log line on some later pass.
    for conn in connections:
        _warn_if_disabled_connection_container_survives(settings, conn.path_token)


@user_app.command("delete")
def user_delete(email: str) -> None:
    """Delete a user and all their connections."""
    settings = _settings()

    async def _delete():
        async with db.get_connection(settings.database_path) as database:
            await db.migrate(database)
            user = await db.get_user_by_email(database, email)
            if user is None:
                return None, []
            # Fetch connections BEFORE the cascade delete -- their path_tokens
            # are needed for the post-delete container check below, and once
            # delete_user runs, list_connections would return nothing for them.
            connections = await db.list_connections(database, user_id=user.id)
            await db.delete_user(database, user.id)
            return user, connections

    user, connections = run(_delete())
    if user is None:
        typer.echo(f"User not found: {email}")
        raise typer.Exit(1)
    typer.echo(f"Deleted user {email}")
    _trigger_reconcile(settings)
    _warn_if_identity_unresolved(settings)
    # delete_user cascades the connection rows away entirely -- unlike
    # `connection disable`, there is no DB row left for the reconciler's own
    # periodic check to ever match against, so this is the ONLY place a
    # legacy (pre-instance-labelling) container for one of these connections
    # ever gets flagged. See _warn_if_disabled_connection_container_survives.
    for conn in connections:
        _warn_if_disabled_connection_container_survives(settings, conn.path_token)


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
    ech: EchChoice = typer.Option(
        EchChoice.auto,
        "--ech",
        help="ECH mode: auto (default, opportunistic) / always (fail-closed) / never (off).",
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
            # Front self-check runs only AFTER the user is confirmed, so a bad email
            # doesn't cause a wasted DoH round-trip or a misleading "not serving ECH" error.
            if ech is EchChoice.always:
                if not settings.ech_doh_url:
                    typer.echo("--ech always requires ECH_DOH_URL to be set", err=True)
                    raise typer.Exit(1)
                from postern.ech import check_apex_ech
                status = check_apex_ech(settings.domain, settings.ech_doh_url)
                if status == "absent":
                    typer.echo(
                        f"refusing --ech always: {settings.domain} is not serving ECH (apex HTTPS record has no "
                        "ech=). A fail-closed connection would never connect. Use --ech auto, or enable ECH at "
                        "your front first.",
                        err=True,
                    )
                    raise typer.Exit(1)
                if status == "inconclusive":
                    typer.echo(
                        f"warning: could not confirm {settings.domain} serves ECH over DoH; creating anyway. "
                        "Verify with `postern ech verify`.",
                        err=True,
                    )
            conn = Connection(
                user_id=user.id,
                path_token=secrets.token_hex(12),
                password=generate_password(),
                label=label,
                plugin=plugin.value,
                ech=ech.value,
            )
            await db.create_connection(database, conn)
            return conn

    conn = run(_add())
    if conn is None:
        typer.echo(f"User not found: {user_email}")
        raise typer.Exit(1)
    typer.echo(f"Created connection {conn.id} ({conn.plugin}, ech={conn.ech})")
    _trigger_reconcile(settings)
    _warn_if_identity_unresolved(settings)


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
        typer.echo(f"  {c.id}  {c.label}  [{c.plugin}]  [ech:{c.ech}]  {status}")


@connection_app.command("tunnels")
def connection_tunnels() -> None:
    """Print the container name of every enabled connection, one per line.

    Machine-readable: stdout carries the names and nothing else, warnings go to
    stderr. Disabled connections have no tunnel and are not listed.
    """
    from postern.reconciler import _container_name
    settings = _settings()

    async def _tunnels() -> list[str]:
        async with db.get_connection(settings.database_path) as database:
            await db.migrate(database)
            connections = await db.list_connections(database)
            return sorted(_container_name(c) for c in connections if c.enabled)

    for name in run(_tunnels()):
        typer.echo(name)
    # Exit 1, not 0: with no instance id the reconciler creates no containers at
    # all, so this list is not what will exist. scripts/deploy.sh must refuse to
    # feed it to the gate. `postern reconcile` already exits 1 in this state.
    if _warn_if_identity_unresolved(settings):
        raise typer.Exit(code=1)


@connection_app.command("disable")
def connection_disable(id: str) -> None:
    """Disable a connection."""
    settings = _settings()

    async def _disable():
        async with db.get_connection(settings.database_path) as database:
            await db.migrate(database)
            conn = await db.get_connection_by_id(database, id)
            disabled = await db.set_connection_enabled(database, id, False)
            return conn, disabled

    conn, disabled = run(_disable())
    if not disabled:
        typer.echo(f"Connection not found: {id}")
        raise typer.Exit(1)
    typer.echo("Connection disabled")
    _trigger_reconcile(settings)
    _warn_if_identity_unresolved(settings)
    if conn is not None:
        _warn_if_disabled_connection_container_survives(settings, conn.path_token)


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
    _warn_if_identity_unresolved(settings)


# Reconcile command ====================================================================================================
@app.command("reconcile")
def reconcile(
    wait: bool = typer.Option(False, "--wait", help="Block until the reconciler finishes a pass."),
    wait_timeout: float = typer.Option(
        0.0,
        "--wait-timeout",
        min=0.0,
        help="Fail if the pass has not finished within this many seconds. 0 (default) waits indefinitely.",
    ),
) -> None:
    """Wake the reconciler immediately instead of waiting for the next poll.

    Creates the trigger file the reconciler watches. Equivalent to `touch
    /data/.reconcile-now`, but works in the distroless production image which
    ships no shell or busybox.

    With --wait, register a FIFO first and block on it until the loop reports the
    outcome of a pass -- the ordering guarantee a deploy needs before it can assert
    anything about the ss-* containers (see scripts/deploy.sh). A finished pass is
    not a converged one (see reconcile_wait.wait_for_notify); proving convergence is
    scripts/verify-deploy.py's job.
    """
    settings = _settings()

    # `--wait-timeout` only has an effect inside the --wait branch below. A nonzero
    # value without --wait would otherwise be silently discarded by the early
    # return two lines down -- the opposite of what an operator who passed it
    # asked for. Zero is exempt: it is the default and means "no bound" either way,
    # so it is not a value that could be silently ignored.
    if wait_timeout and not wait:
        typer.echo("--wait-timeout has no effect without --wait", err=True)
        raise typer.Exit(1)

    if not wait:
        trigger = _trigger_reconcile(settings)
        typer.echo(f"Reconcile triggered: {trigger}")
        if _warn_if_identity_unresolved(settings):
            raise typer.Exit(code=1)
        return

    try:
        waiter = reconcile_wait.register_waiter(settings.database_path)
    except OSError as exc:
        typer.echo(
            f"Cannot register a reconcile waiter in {reconcile_wait.waiters_dir(settings.database_path)}: {exc}",
            err=True,
        )
        raise typer.Exit(1) from exc

    try:
        try:
            trigger = _trigger_reconcile(settings)
        except OSError as exc:
            # Same directory, same failure modes (read-only volume, full disk) as
            # register_waiter above -- give it the same clean disposition instead
            # of letting the exception escape as a raw traceback.
            typer.echo(f"Cannot touch the reconcile trigger file: {exc}", err=True)
            raise typer.Exit(1) from exc
        typer.echo(f"Reconcile triggered: {trigger}; waiting for the pass to finish")
        outcome = reconcile_wait.wait_for_notify(waiter, timeout=wait_timeout or None)
    finally:
        reconcile_wait.close_waiter(waiter)

    identity_unresolved = _warn_if_identity_unresolved(settings)

    if outcome is None:
        typer.echo(
            f"Reconciler did not complete a pass within {wait_timeout}s. "
            "Is the portal running? Check `docker compose logs portal`.",
            err=True,
        )
        raise typer.Exit(1)
    if outcome == "failed":
        typer.echo(
            "The reconcile pass did not complete -- it raised, or the portal is shutting down. "
            "Check `docker compose logs portal`.",
            err=True,
        )
        raise typer.Exit(1)

    typer.echo("Reconcile pass finished")
    if identity_unresolved:
        raise typer.Exit(code=1)


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


edge_app = typer.Typer(name="edge", help="Inspect the Cloudflare edge (zone SSL/TLS mode)")
app.add_typer(edge_app)


@edge_app.command("ssl-status")
def edge_ssl_status() -> None:
    """Show the Cloudflare zone SSL/TLS-mode settings and the provisioner's
    convergence state (incl. the last Cloudflare error)."""
    from postern_provisioner import ssl_mode as ssl_state
    settings = _settings()
    typer.echo(f"domain:                   {settings.domain}")
    typer.echo(f"edge_profile:             {settings.edge_profile}")
    typer.echo(f"dns_provider:             {settings.dns_provider}")
    typer.echo(f"edge_cf_manage_ssl_mode:  {settings.edge_cf_manage_ssl_mode}")
    typer.echo(f"edge_cf_ssl_mode:         {settings.edge_cf_ssl_mode}")  # configured target
    # Provisioner-written state (shared postern-mta-data volume); see
    # SslModeState.last_observed_mode for the raise-only target-vs-actual semantics.
    state = ssl_state.read_state()
    typer.echo(f"zone_ssl_set_at:          {state.last_set_ok_iso or '(never)'}")
    typer.echo(f"zone_ssl_current_mode:    {state.last_observed_mode or '(unknown)'}")
    typer.echo(f"zone_ssl_failures:        {state.consecutive_failures}")
    typer.echo(f"zone_ssl_last_error:      {state.last_error or '(none)'}")


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


@app.command("version")
def version_cmd(output_json: bool = typer.Option(False, "--json", help="Emit structured JSON")) -> None:
    """Print the package version and the git revision this image was built from.

    The revision comes from POSTERN_REVISION, set from the GIT_REVISION build
    arg in portal/Dockerfile. "unknown" means the image was built without it --
    the deployment has no provenance and `scripts/verify-deploy.py` will fail.
    """
    import json
    import os
    from importlib import metadata

    revision = os.environ.get("POSTERN_REVISION", "").strip() or "unknown"
    try:
        package_version = metadata.version("postern")
    except metadata.PackageNotFoundError:
        package_version = "unknown"

    if output_json:
        typer.echo(json.dumps({"version": package_version, "revision": revision}, indent=2))
    else:
        typer.echo(f"postern {package_version}")
        typer.echo(f"revision: {revision}")


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
