"""Helpers bound to the ``postern-e2e-mta`` compose project.

Thin wrappers around ``_helpers.compose`` / ``_helpers.compose_exec`` that bind
the project name and compose-file list. Plus a few MTA-specific utilities for
reading the DKIM volume, inspecting docker state, and waiting for healthy
containers.

Tests should import from here; ``_helpers`` stays single-project (the existing
``e2e.compose.yaml`` stack).
"""

from __future__ import annotations

import json
import logging
import subprocess
import time
from pathlib import Path

from . import _helpers
from ._helpers import TESTS_E2E_DIR, run

logger = logging.getLogger(__name__)

PROJECT_MTA = "postern-e2e-mta"
COMPOSE_FILES_MTA: tuple[Path, ...] = (
    TESTS_E2E_DIR / "e2e.compose.yaml",
    TESTS_E2E_DIR / "e2e-mta.compose.yaml",
)

# Refuse to silently use the wrong project. If a future refactor makes these match
# the base e2e project, fixtures targeting different stacks would collide.
assert PROJECT_MTA != _helpers.PROJECT, ("PROJECT_MTA must differ from _helpers.PROJECT to keep stacks isolated")


# Compose primitives ===================================================================================================
def compose_mta(*args: str) -> list[str]:
    return _helpers.compose(*args, project=PROJECT_MTA, files=COMPOSE_FILES_MTA)


def compose_mta_exec(
    *cmd: str,
    service: str = "portal",
    stdin: str | None = None,
) -> subprocess.CompletedProcess:
    return _helpers.compose_exec(*cmd, service=service, project=PROJECT_MTA, files=COMPOSE_FILES_MTA, stdin=stdin)


def mta_exec(*cmd: str, stdin: str | None = None) -> subprocess.CompletedProcess:
    return compose_mta_exec(*cmd, service="mta", stdin=stdin)


def portal_mta_exec(*cmd: str, stdin: str | None = None) -> subprocess.CompletedProcess:
    return compose_mta_exec(*cmd, service="portal", stdin=stdin)


# DKIM volume access (read via the mta container) ======================================================================
def read_dkim_volume_file(path: str) -> str:
    """Read a file under ``/var/lib/opendkim/`` via the mta container.

    We read from mta (not portal) because:
    - state.json is written by the provisioner via tempfile.mkstemp -> mode 0600,
      owned by opendkim (110:110). The portal runs as the unprivileged
      ``nonroot`` user (UID 65532) and cannot read 0600 files even through the
      :ro mount.
    - The mta container's runtime is alpine-base-dev (busybox + cat). Running
      as the image default user (root in -dev), it can read any file regardless
      of mode.
    """
    if not path.startswith("/var/lib/opendkim/") and not path.startswith("var/lib/opendkim/"):
        # Accept relative names like "state.json" or "<selector>.txt".
        path = f"/var/lib/opendkim/{path.lstrip('/')}"
    return mta_exec("cat", path).stdout


def get_provisioner_state() -> dict:
    """Return the parsed contents of state.json from the DKIM volume."""
    return json.loads(read_dkim_volume_file("state.json"))


# Docker introspection (host-side) =====================================================================================
def get_container_id(service: str) -> str:
    """Resolve a service name to its container ID for `docker inspect`.

    Uses ``compose ps -aq <service>`` (-a to include exited containers) so we
    don't have to guess the ``<project>-<service>-N`` naming Compose uses
    internally. The provisioner is ``restart: 'no'`` and intentionally exits
    after generating the keypair, so it's "exited" by the time tests inspect it.
    """
    cid = run(compose_mta("ps", "-aq", service)).stdout.strip()
    if not cid:
        raise AssertionError(f"no container for service {service!r} in project {PROJECT_MTA}")
    return cid.splitlines()[0]


def docker_inspect(container_id: str, fmt: str) -> str:
    return run(["docker", "inspect", container_id, "--format", fmt]).stdout.strip()


def network_inspect(name: str) -> dict:
    out = run(["docker", "network", "inspect", name]).stdout
    parsed = json.loads(out)
    if not parsed:
        raise AssertionError(f"docker network {name!r} not found")
    return parsed[0]


def wait_for_healthy(container_id: str, *, timeout: float = 60.0) -> None:
    """Poll docker until a container's health status is ``healthy`` (or fail)."""
    deadline = time.monotonic() + timeout
    last = "<unknown>"
    while time.monotonic() < deadline:
        try:
            last = docker_inspect(container_id, "{{.State.Health.Status}}")
        except subprocess.CalledProcessError:
            last = "<inspect-failed>"
        if last == "healthy":
            return
        time.sleep(0.5)
    raise AssertionError(f"container {container_id} not healthy after {timeout}s (last status: {last!r})")
