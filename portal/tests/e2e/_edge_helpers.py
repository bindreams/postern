"""Helpers bound to the ``postern-e2e-edge`` compose project.

Thin wrappers around ``_helpers.compose`` / ``_helpers.compose_exec`` that bind
the project name and compose-file list, plus utilities for seeding the
postern-edge volume and restarting nginx.

Tests import from here; ``_helpers`` stays single-project (the base e2e stack).
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

from . import _helpers
from ._helpers import TESTS_E2E_DIR, run

PROJECT_EDGE = "postern-e2e-edge"
COMPOSE_FILES_EDGE: tuple[Path, ...] = (TESTS_E2E_DIR / "e2e-edge.compose.yaml", )

EDGE_BASE_URL = "https://postern.test:8453"
# container_name pinned in e2e-edge.compose.yaml; used for docker restart.
EDGE_NGINX_CONTAINER = "postern-e2e-edge-nginx"
# Named volume that nginx reads RO; helper containers write RW to seed it.
EDGE_VOLUME_NAME = "postern-e2e-edge-edge"

# Sanity-check: a naming collision would make two e2e projects fight over the
# same Docker resources (networks, volumes).
assert PROJECT_EDGE != _helpers.PROJECT, "PROJECT_EDGE must differ from _helpers.PROJECT"


# Compose primitives ===================================================================================================
def compose_edge(*args: str) -> list[str]:
    return _helpers.compose(*args, project=PROJECT_EDGE, files=COMPOSE_FILES_EDGE)


# Edge-volume helpers ==================================================================================================
def _wait_nginx_healthy(*, timeout: float = 30.0) -> None:
    """Poll Docker's healthcheck status for the edge nginx container until healthy.

    Gates readiness on Docker's own healthcheck primitive -- the container is
    not considered ready until its healthcheck reports ``healthy``.  ``timeout``
    is the failure bound surfaced to the operator ("nginx did not become healthy
    after {timeout}s").
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Health.Status}}", EDGE_NGINX_CONTAINER],
            capture_output=True,
            text=True,
        )
        if result.stdout.strip() == "healthy":
            return
        time.sleep(0.5)
    raise AssertionError(f"edge nginx did not become healthy after {timeout}s")


def seed_edge_ranges(*, ranges_conf: str = "set_real_ip_from 0.0.0.0/0;\n") -> None:
    """Write a Cloudflare-ranges conf into the postern-edge volume and restart nginx.

    Uses an ephemeral one-off container (local/nginx, UID 0 so it can write to
    the root-owned volume) with an atomic rename (mv) so the inotifyd watcher
    inside nginx also sees IN_MOVED_TO.  After writing, RESTART the nginx
    container -- not just ``nginx -s reload`` -- so render.sh re-runs and the
    new config is guaranteed loaded once the container reports healthy.

    ``ranges_conf`` defaults to ``set_real_ip_from 0.0.0.0/0;`` (trust all
    sources) so CF-Connecting-IP is recovered from any test client IP.  Pass a
    narrower CIDR when you need to test trust boundaries.
    """
    # Write via stdin to avoid shell-quoting the ranges_conf content.
    run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "-i",
            "--user",
            "0",  # UID 0 can write to the root-owned volume mount
            "--entrypoint",
            "sh",
            "--volume",
            f"{EDGE_VOLUME_NAME}:/edge",
            "local/nginx",
            "-c",
            "cat > /edge/.cloudflare-ranges.conf.tmp && "
            "mv /edge/.cloudflare-ranges.conf.tmp /edge/cloudflare-ranges.conf",
        ],
        input=ranges_conf,
    )
    # Restart (not just reload) so render.sh re-runs; new config guaranteed
    # loaded once Docker's healthcheck reports healthy.
    run(["docker", "restart", EDGE_NGINX_CONTAINER])
    _wait_nginx_healthy()


def remove_edge_ranges() -> None:
    """Remove the seeded ranges file and restart nginx (fixture teardown)."""
    run([
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--user",
        "0",
        "--entrypoint",
        "sh",
        "--volume",
        f"{EDGE_VOLUME_NAME}:/edge",
        "local/nginx",
        "-c",
        "rm -f /edge/cloudflare-ranges.conf",
    ])
    run(["docker", "restart", EDGE_NGINX_CONTAINER])
    _wait_nginx_healthy()
