"""Shared utilities for e2e tests. Conftest fixtures and tests both import from here.

The split exists because pytest treats conftest.py specially -- importing from it
across files in the same directory is fragile. Putting the utilities in a regular
module sidesteps that.

The compose primitives (``compose``, ``compose_exec``) accept ``project`` and
``files`` kwargs so the same helpers can drive a second compose project (the MTA
overlay; see ``_mta_helpers.py``). The defaults preserve the original
single-project behaviour for ``test_tunnel.py``.
"""

from __future__ import annotations

import re
import subprocess
import time
from pathlib import Path

# Resolve key paths once.
TESTS_E2E_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = TESTS_E2E_DIR.parents[2]
COMPOSE_FILE = TESTS_E2E_DIR / "e2e.compose.yaml"
COMPOSE_FILES: tuple[Path, ...] = (COMPOSE_FILE, )
PROJECT = "postern-e2e"

PORTAL_BASE_URL = "https://postern.test:8443"
MAILPIT_BASE_URL = "http://localhost:8025"


# Compose primitives ===================================================================================================
def compose(
    *args: str,
    project: str = PROJECT,
    files: tuple[Path, ...] = COMPOSE_FILES,
) -> list[str]:
    file_args: list[str] = []
    for f in files:
        file_args.extend(("-f", str(f)))
    return ["docker", "compose", "-p", project, *file_args, *args]


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kwargs)


def compose_exec(
    *cmd: str,
    service: str = "portal",
    project: str = PROJECT,
    files: tuple[Path, ...] = COMPOSE_FILES,
    stdin: str | None = None,
) -> subprocess.CompletedProcess:
    if stdin is not None:
        return run(compose("exec", "-T", service, *cmd, project=project, files=files), input=stdin)
    return run(compose("exec", "-T", service, *cmd, project=project, files=files))


def postern_cli(*args: str) -> subprocess.CompletedProcess:
    return compose_exec("postern", *args)


def trigger_reconcile() -> None:
    compose_exec("postern", "reconcile")


def query_db(sql: str, *params: str) -> str:
    """SELECT in the portal container; returns the first column of the first row (or '')."""
    py = (
        "import sqlite3, sys\n"
        "row = sqlite3.connect('/data/postern.db').execute("
        f"{sql!r}, sys.argv[1:]).fetchone()\n"
        "print(row[0] if row else '')\n"
    )
    return compose_exec("python", "-c", py, *params).stdout.strip()


# Container introspection ==============================================================================================
def container_exists(name: str) -> bool:
    result = subprocess.run(
        ["docker", "ps", "-a", "--filter", f"name=^{name}$", "--format", "{{.Names}}"],
        capture_output=True,
        text=True,
        check=True,
    )
    return name in result.stdout.split()


def wait_for_container(name: str, *, timeout: float = 15.0, present: bool = True) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if container_exists(name) == present:
            return
        time.sleep(0.25)
    raise AssertionError(f"Container {name} {'still missing' if present else 'still present'} after {timeout}s")


# Path-token regex used by the connection fixture
CONNECTION_ID_RE = re.compile(r"Created connection ([0-9a-f-]{36})")
