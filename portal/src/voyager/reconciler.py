"""Container reconciliation loop.

Ensures Docker containers match the desired state in the database.
Runs as a background asyncio task in the FastAPI lifespan.
"""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path

import docker
import docker.errors
import docker.types
from docker.models.containers import Container

from voyager import db
from voyager.models import Connection
from voyager.settings import Settings
from voyager.ss_config import server_config_b64

logger = logging.getLogger(__name__)

MANAGED_LABEL = "voyager.managed"
MANAGED_VALUE = "true"


def _container_name(conn: Connection) -> str:
    return f"ss-{conn.path_token}"


def _get_docker_client() -> docker.DockerClient:
    return docker.DockerClient.from_env()


def _list_managed_containers(client: docker.DockerClient) -> dict[str, Container]:
    """Return a dict of container_name -> container for all managed containers."""
    containers = client.containers.list(all=True, filters={"label": f"{MANAGED_LABEL}={MANAGED_VALUE}"})
    return {c.name: c for c in containers}


def _image_exists(client: docker.DockerClient, image_name: str) -> bool:
    try:
        client.images.get(image_name)
        return True
    except docker.errors.ImageNotFound:
        return False


def _create_container(client: docker.DockerClient, conn: Connection, settings: Settings) -> None:
    """Create and start an SS container for the given connection."""
    name = _container_name(conn)
    config_b64 = server_config_b64(conn, settings.domain)

    logger.info("Creating container %s for connection %s", name, conn.id)

    client.containers.run(
        image=settings.shadowsocks_image,
        name=name,
        detach=True,
        environment={"SS_CONFIG": config_b64},
        labels={MANAGED_LABEL: MANAGED_VALUE},
        log_config=docker.types.LogConfig(type="none"),
        restart_policy={"Name": "unless-stopped"},
        tmpfs={"/tmp": ""},
        network=settings.shadowsocks_network,
    )


def _remove_container(container: Container) -> None:
    """Stop and remove a container."""
    logger.info("Removing container %s", container.name)
    try:
        container.stop(timeout=10)
    except Exception:
        pass
    try:
        container.remove(force=True)
    except Exception:
        logger.exception("Failed to remove container %s", container.name)


def _reconcile_once(
    client: docker.DockerClient,
    connections: list[Connection],
    settings: Settings,
) -> None:
    """Single reconciliation pass. Called from the async loop in a thread."""
    managed = _list_managed_containers(client)
    desired_names = {_container_name(c) for c in connections}

    # Create missing containers ----------------------------------------------------------------------------------------
    for conn in connections:
        name = _container_name(conn)
        if name not in managed:
            try:
                _create_container(client, conn, settings)
            except Exception:
                logger.exception("Failed to create container %s", name)

    # Remove orphan containers -----------------------------------------------------------------------------------------
    for name, container in managed.items():
        if name not in desired_names:
            _remove_container(container)

    # Restart exited containers ----------------------------------------------------------------------------------------
    # Re-fetch after creates/removes
    managed = _list_managed_containers(client)
    for name, container in managed.items():
        if name in desired_names and container.status == "exited":
            logger.info("Restarting exited container %s", name)
            try:
                container.start()
            except Exception:
                logger.exception("Failed to restart container %s", name)

    # Check for image updates ------------------------------------------------------------------------------------------
    try:
        current_image = client.images.get(settings.shadowsocks_image)
        for name, container in managed.items():
            if name in desired_names and container.image.id != current_image.id:
                logger.info("Image changed for %s, recreating", name)
                conn = next(c for c in connections if _container_name(c) == name)
                _remove_container(container)
                try:
                    _create_container(client, conn, settings)
                except Exception:
                    logger.exception("Failed to recreate container %s", name)
    except docker.errors.ImageNotFound:
        pass  # Image not built yet; skip upgrade check


async def reconcile(database_path: str, settings: Settings) -> None:
    """Run a single reconciliation pass."""
    client = _get_docker_client()

    if not _image_exists(client, settings.shadowsocks_image):
        logger.error(
            "Image '%s' not found. Build it from the repo root with: "
            "docker build -f shadowsocks/Dockerfile -t %s .",
            settings.shadowsocks_image,
            settings.shadowsocks_image,
        )
        client.close()
        return

    database = await db.get_connection(database_path)
    try:
        connections = await db.list_connections(database, enabled_only=True)
        await asyncio.to_thread(_reconcile_once, client, connections, settings)
        await db.cleanup_expired(database)
    finally:
        await database.close()
        client.close()


async def reconciliation_loop(database_path: str, settings: Settings) -> None:
    """Main reconciliation loop. Runs until cancelled."""
    trigger_path = Path(os.path.dirname(database_path)) / ".reconcile-now"

    while True:
        try:
            await reconcile(database_path, settings)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Reconciliation failed")

        # Wait for interval or trigger file
        for _ in range(settings.reconcile_interval_seconds):
            if trigger_path.exists():
                try:
                    trigger_path.unlink()
                except OSError:
                    pass
                break
            await asyncio.sleep(1)


async def cleanup_all_containers() -> None:
    """Stop and remove all managed containers. Called on shutdown."""
    logger.info("Cleaning up all managed containers")
    try:
        client = _get_docker_client()
        managed = _list_managed_containers(client)
        for name, container in managed.items():
            _remove_container(container)
        client.close()
    except Exception:
        logger.exception("Failed to cleanup containers")
