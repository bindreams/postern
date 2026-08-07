"""Regression tests for compose-level wiring the reconciler depends on:
COMPOSE_PROJECT_NAME forwarding, and SHADOWSOCKS_NETWORK's network-name /
portal-env sync.

That sync is the canonical rationale for this module: Compose interpolates
`${VAR}` from the shell (or --env-file), while a service's `env_file:` is a
separate lookup against ./.env, and the two can disagree. Static YAML checks
below; `test_compose_config_*` shells out to the real Compose CLI.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from ._compose import load_compose

# tests/ -> portal/ -> repo root
REPO_ROOT = Path(__file__).resolve().parent.parent.parent

COMPOSE_PROJECT_NAME_EXPR = "${COMPOSE_PROJECT_NAME:-}"


def _load_compose(relpath: str) -> dict:
    return load_compose(REPO_ROOT / relpath)


# COMPOSE_PROJECT_NAME forwarding ======================================================================================
def test_production_portal_forwards_compose_project_name():
    compose = _load_compose("compose.yaml")
    env = compose["services"]["portal"]["environment"]
    assert env.get("COMPOSE_PROJECT_NAME") == COMPOSE_PROJECT_NAME_EXPR, (
        "compose.yaml's portal service must forward COMPOSE_PROJECT_NAME so "
        "reconciler.resolve_instance_id can auto-derive this deployment's instance "
        f"id; got {env.get('COMPOSE_PROJECT_NAME')!r}"
    )


def test_e2e_portal_forwards_compose_project_name():
    compose = _load_compose("portal/tests/e2e/e2e.compose.yaml")
    env = compose["services"]["portal"]["environment"]
    assert env.get("COMPOSE_PROJECT_NAME") == COMPOSE_PROJECT_NAME_EXPR


def test_e2e_edge_portal_forwards_compose_project_name():
    compose = _load_compose("portal/tests/e2e/e2e-edge.compose.yaml")
    env = compose["services"]["portal"]["environment"]
    assert env.get("COMPOSE_PROJECT_NAME") == COMPOSE_PROJECT_NAME_EXPR


# shadowsocks network name sync ========================================================================================
SHADOWSOCKS_NETWORK_EXPR = "${SHADOWSOCKS_NETWORK:-shadowsocks}"


def test_production_shadowsocks_network_name_and_portal_env_read_the_same_expression():
    """Network name and portal env must interpolate the identical expression --
    see the module docstring for why `env_file:` alone can't guarantee that."""
    compose = _load_compose("compose.yaml")

    net_name = compose["networks"]["shadowsocks"]["name"]
    assert net_name == SHADOWSOCKS_NETWORK_EXPR, (
        f"compose.yaml's networks.shadowsocks.name must be {SHADOWSOCKS_NETWORK_EXPR!r}; got {net_name!r}. "
        "A hardcoded literal means an operator's SHADOWSOCKS_NETWORK override renames nothing."
    )

    portal_env = compose["services"]["portal"]["environment"].get("SHADOWSOCKS_NETWORK")
    assert portal_env == SHADOWSOCKS_NETWORK_EXPR, (
        "compose.yaml's portal service must set SHADOWSOCKS_NETWORK in its own environment: block to the "
        f"identical expression as networks.shadowsocks.name ({SHADOWSOCKS_NETWORK_EXPR!r}), not rely on "
        f"env_file: .env for it; got {portal_env!r}."
    )


def test_production_nginx_joins_the_shadowsocks_network():
    """The fix is only worth anything if nginx is on the network the portal
    puts tunnels on -- nginx proxies `http://ss-<token>` by Docker-DNS name."""
    compose = _load_compose("compose.yaml")
    assert "shadowsocks" in compose["services"]["nginx"]["networks"]


@pytest.mark.parametrize(
    "compose_relpath", ["portal/tests/e2e/e2e.compose.yaml", "portal/tests/e2e/e2e-edge.compose.yaml"]
)
def test_e2e_portal_and_nginx_agree_on_the_shadowsocks_network(compose_relpath):
    """Each e2e stack hardcodes two independent literals -- the portal's env var
    and the network's `name:` -- rather than interpolating, keeping a name that
    can never collide with a production network on a shared daemon. Match them
    through the service that has to reach the tunnels: the portal's
    SHADOWSOCKS_NETWORK must resolve to a network `nginx` actually joins.
    Asserting merely that the name is *declared somewhere* in the file would
    pass for any decoy network (e2e.compose.yaml declares three)."""
    compose = _load_compose(compose_relpath)
    portal_env = compose["services"]["portal"]["environment"]["SHADOWSOCKS_NETWORK"]
    networks = compose["networks"] or {}
    nginx_net_names = {(networks.get(key) or {}).get("name") for key in compose["services"]["nginx"]["networks"]}
    assert portal_env in nginx_net_names, (
        f"portal's SHADOWSOCKS_NETWORK={portal_env!r} is not a network nginx joins "
        f"(nginx is on {sorted(n for n in nginx_net_names if n)}); nginx could not reach any ss-* container"
    )


# Real Compose-CLI resolution ==========================================================================================
def _compose_config(tmp_path: Path, shell_env: str | None, env_file_value: str | None) -> dict:
    """Resolve compose.yaml with the real Compose CLI and return its JSON.

    compose.yaml is copied into `tmp_path` because the portal's `env_file: .env`
    resolves against the project directory: pointing the CLI at the repo's own
    compose.yaml would read the operator's real .env (or fail without one). The
    copy is byte-identical, so what is resolved is the shipped file.
    """
    shutil.copy(REPO_ROOT / "compose.yaml", tmp_path / "compose.yaml")
    lines = ["SECRET_KEY=test-only\n"]
    if env_file_value is not None:
        lines.append(f"SHADOWSOCKS_NETWORK={env_file_value}\n")
    (tmp_path / ".env").write_text("".join(lines), encoding="utf-8")

    env = {k: v for k, v in os.environ.items() if k != "SHADOWSOCKS_NETWORK"}
    if shell_env is not None:
        env["SHADOWSOCKS_NETWORK"] = shell_env
    proc = subprocess.run(
        ["docker", "compose", "-f", "compose.yaml", "config", "--format", "json"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        # `config` is a local parse and normally returns in well under a second,
        # but it is still a child process: a hung Docker-context probe or a
        # credential-helper prompt would otherwise wedge the whole pytest run
        # with no output. TimeoutExpired propagating is the failure bound.
        timeout=60,
    )
    assert proc.returncode == 0, f"`docker compose config` failed:\n{proc.stderr}"
    return json.loads(proc.stdout)


@pytest.mark.compose_cli
@pytest.mark.parametrize(
    ("shell_env", "env_file_value", "expected"),
    [
        (None, None, "shadowsocks"),  # nothing set anywhere -> the documented default
        (None, "", "shadowsocks"),  # set-but-empty in .env -> `:-` falls back, matching Settings
        ("", None, "shadowsocks"),  # set-but-empty in the SHELL -- the `:-` vs `-` distinction
        (None, "from-env-file", "from-env-file"),  # .env alone feeds interpolation too
        ("from-shell", None, "from-shell"),  # shell alone
        ("from-shell", "from-env-file", "from-shell"),  # THE regression: the two sources disagree
    ],
)
def test_compose_config_resolves_network_name_and_portal_env_identically(
    tmp_path: Path, shell_env: str | None, env_file_value: str | None, expected: str
):
    """The real Compose CLI must resolve the network's name and the portal's
    SHADOWSOCKS_NETWORK to the SAME value under every source combination --
    the last case being the one no YAML parse can check (see the module
    docstring for why the two sources can disagree).
    """
    config = _compose_config(tmp_path, shell_env, env_file_value)
    net_name = config["networks"]["shadowsocks"]["name"]
    # `.get` with a sentinel, not `[...]`: with the wiring absent the portal has
    # no such key at all, and a KeyError would report as an error rather than as
    # this assertion's diff.
    portal_env = config["services"]["portal"]["environment"].get("SHADOWSOCKS_NETWORK", "<absent>")
    assert (net_name, portal_env) == (expected, expected)
