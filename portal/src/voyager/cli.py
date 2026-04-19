"""Admin CLI for managing users and connections."""

from __future__ import annotations

import asyncio
import secrets
from pathlib import Path

import typer

from voyager import db
from voyager.models import Connection, User
from voyager.settings import Settings
from voyager.ss_config import generate_password

app = typer.Typer(name="voyager")
user_app = typer.Typer(name="user", help="Manage users")
connection_app = typer.Typer(name="connection", help="Manage connections")
app.add_typer(user_app)
app.add_typer(connection_app)


def _settings() -> Settings:
    return Settings()


def _trigger_reconcile(settings: Settings) -> None:
    trigger = Path(settings.database_path).parent / ".reconcile-now"
    trigger.touch()


def run(coro):
    return asyncio.run(coro)


# User commands ========================================================================================================
@user_app.command("add")
def user_add(name: str, email: str) -> None:
    """Create a new user."""
    settings = _settings()

    async def _add():
        database = await db.get_connection(settings.database_path)
        await db.migrate(database)
        user = User(name=name, email=email)
        await db.create_user(database, user)
        await database.close()
        return user

    user = run(_add())
    typer.echo(f"Created user {user.name} ({user.id})")


@user_app.command("list")
def user_list() -> None:
    """List all users."""
    settings = _settings()

    async def _list():
        database = await db.get_connection(settings.database_path)
        await db.migrate(database)
        users = await db.list_users(database)
        await database.close()
        return users

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
        database = await db.get_connection(settings.database_path)
        await db.migrate(database)
        user = await db.get_user_by_email(database, email)
        if user is None:
            await database.close()
            return None
        connections = await db.list_connections(database, user_id=user.id)
        for conn in connections:
            await db.set_connection_enabled(database, conn.id, False)
        await database.close()
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
        database = await db.get_connection(settings.database_path)
        await db.migrate(database)
        user = await db.get_user_by_email(database, email)
        if user is None:
            await database.close()
            return False
        await db.delete_user(database, user.id)
        await database.close()
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
        database = await db.get_connection(settings.database_path)
        await db.migrate(database)
        user = await db.get_user_by_email(database, user_email)
        if user is None:
            await database.close()
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
        await database.close()
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
        database = await db.get_connection(settings.database_path)
        await db.migrate(database)
        user_id = None
        if user_email:
            user = await db.get_user_by_email(database, user_email)
            if user is None:
                await database.close()
                typer.echo(f"User not found: {user_email}")
                raise typer.Exit(1)
            user_id = user.id
        connections = await db.list_connections(database, user_id=user_id)
        await database.close()
        return connections

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
        database = await db.get_connection(settings.database_path)
        await db.migrate(database)
        result = await db.set_connection_enabled(database, id, False)
        await database.close()
        return result

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
        database = await db.get_connection(settings.database_path)
        await db.migrate(database)
        result = await db.set_connection_enabled(database, id, True)
        await database.close()
        return result

    if not run(_enable()):
        typer.echo(f"Connection not found: {id}")
        raise typer.Exit(1)
    typer.echo("Connection enabled")
    _trigger_reconcile(settings)


if __name__ == "__main__":
    app()
