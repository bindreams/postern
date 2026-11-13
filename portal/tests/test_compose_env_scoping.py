"""Each compose service receives exactly the variables it reads (issue #292).

No compose file uses `env_file:`. Every service lists its variables under
`environment:` as bare passthrough keys, so a variable reaches a service through
one channel only, and an unset variable stays absent in the container (the
portal and provisioner treat "set but empty" differently from "unset").

The read sets are derived from source, so a new `Settings` field, entrypoint
variable or DNS provider that is not wired into compose fails here.
Static checks parse the YAML; `compose_cli` tests resolve it with the real
Compose CLI (no daemon).
"""
from __future__ import annotations

import os
import re
import shutil
from pathlib import Path

import pytest

from postern.settings import Settings

from ._compose import (
    ALL_COMPOSE_FILES,
    REPO_ROOT,
    load_compose,
    repo_relative,
    run_compose_config,
    service_environment,
)

COMPOSE = REPO_ROOT / "compose.yaml"
E2E_MTA_REAL = REPO_ROOT / "portal" / "tests" / "e2e" / "e2e-mta-real.compose.yaml"

# What each service reads, derived from source =========================================================================
_STRING_LITERAL = r'"([A-Z][A-Z0-9_]*)"'
_PY_ENV_READ = re.compile(
    rf"os\.environ(?:\.get\(|\[)\s*{_STRING_LITERAL}|_require\(\s*{_STRING_LITERAL}|_bool_env\(\s*{_STRING_LITERAL}"
)


def _python_env_reads(*relpaths: str) -> set[str]:
    names: set[str] = set()
    for relpath in relpaths:
        text = (REPO_ROOT / relpath).read_text(encoding="utf-8")
        names.update(name for match in _PY_ENV_READ.finditer(text) for name in match.groups() if name)
    return names


def _go_provider_vars() -> frozenset[str]:
    """Every variable `newProvider` reads in provisioner/postern-dns/main.go, the one
    place libdns-native names enter the stack (`lego_env.py` translates the same set)."""
    source = (REPO_ROOT / "provisioner" / "postern-dns" / "main.go").read_text(encoding="utf-8")
    body = source[source.index("func newProvider("):]
    body = body[:body.index("\n}\n")]
    code = "\n".join(line for line in body.splitlines() if not line.lstrip().startswith("//"))
    names = frozenset(re.findall(r'os\.Getenv\("([A-Z0-9_]+)"\)', code))
    assert names, "no os.Getenv names found in newProvider -- the derivation rotted"
    return names


def _nginx_reads() -> set[str]:
    """Names in the `#   NAME  (...)` list in render.sh's header comment."""
    header = (REPO_ROOT / "nginx" / "render.sh").read_text(encoding="utf-8").split("render_templates()")[0]
    return set(re.findall(r"^#   ([A-Z][A-Z0-9_]+)\s", header, re.M))


PROVIDER_VARS = _go_provider_vars()

# Test hooks the e2e compose files set explicitly; production does not deliver them.
_MTA_TEST_HOOKS = {"MTA_E2E_TRANSPORT_OVERRIDE"}
# Read only by the pebble e2e provider, which the e2e stack sets itself.
_PROVISIONER_TEST_HOOKS = {"LEGO_EXEC_PATH"}

READS = {
    "portal": {field.upper()
               for field in Settings.model_fields},
    "mta": _python_env_reads("mta/entrypoint.py") - _MTA_TEST_HOOKS,
    "provisioner": (
        _python_env_reads("provisioner/entrypoint.py", "portal/src/postern_provisioner/healthcheck.py") | PROVIDER_VARS
    ) - _PROVISIONER_TEST_HOOKS,
    "nginx": _nginx_reads(),
}

# Secrets, by the one service that owns them. Compared by value in the CLI test.
PORTAL_SECRETS = ("SECRET_KEY", "SMTP_PASSWORD", "SMTP_USER")
OWNED_SECRETS = {
    "portal": PORTAL_SECRETS,
    "provisioner": tuple(sorted(PROVIDER_VARS)),
}


# Static pins ==========================================================================================================
def test_no_compose_file_loads_an_env_file():
    problems = [
        f"{repo_relative(path)}: service {name!r} sets env_file" for path in ALL_COMPOSE_FILES()
        for name, service in (load_compose(path).get("services") or {}).items() if "env_file" in (service or {})
    ]
    assert not problems, "\n".join(problems)


def test_provider_credentials_reach_only_the_provisioner():
    problems = [
        f"{repo_relative(path)}: service {name!r} receives {sorted(leaked)}" for path in ALL_COMPOSE_FILES()
        for name in (load_compose(path).get("services") or {})
        if name != "provisioner" and (leaked := PROVIDER_VARS & service_environment(path, name).keys())
    ]
    assert not problems, "\n".join(problems)


@pytest.mark.parametrize("path", [COMPOSE, E2E_MTA_REAL], ids=repo_relative)
def test_provisioner_receives_every_provider_variable(path: Path):
    missing = PROVIDER_VARS - service_environment(path, "provisioner").keys()
    assert not missing, f"{repo_relative(path)}: provisioner lacks {sorted(missing)}"


@pytest.mark.parametrize("service", sorted(READS))
def test_every_service_environment_covers_what_the_service_reads(service: str):
    reads = READS[service]
    assert reads, f"derived read set for {service} is empty -- the derivation rotted"
    missing = reads - service_environment(COMPOSE, service).keys()
    assert not missing, f"compose.yaml's {service} never receives {sorted(missing)}, which its code reads"


# Resolved by the real Compose CLI =====================================================================================
_OVERLAY_COMBINATIONS = [
    ["compose.yaml"],
    ["compose.yaml", "compose.cert.yaml"],
    ["compose.yaml", "compose.cert.yaml", "compose.gateway.yaml"],
    ["compose.yaml", "compose.edge.yaml"],
]
_ALL_PROFILES = "with-mta,with-cert-renewal,with-edge"
# Everything these tests set or assert on, so a value exported in the developer's own shell cannot leak in.
_SCRUBBED = {field.upper()
             for field in Settings.model_fields
             } | PROVIDER_VARS | {"COMPOSE_FILE", "COMPOSE_PROFILES", "COMPOSE_PROJECT_NAME", "GIT_REVISION"}


def _project(tmp_path: Path, files: list[str], dotenv: dict[str, str]) -> Path:
    for name in files:
        shutil.copy(REPO_ROOT / name, tmp_path / name)
    (tmp_path / ".env").write_text("".join(f"{k}={v}\n" for k, v in dotenv.items()), encoding="utf-8")
    return tmp_path


def _resolve(project: Path, files: list[str], shell: dict[str, str] | None = None) -> dict:
    env = {k: v for k, v in os.environ.items() if k not in _SCRUBBED}
    env["COMPOSE_PROFILES"] = _ALL_PROFILES
    env.update(shell or {})
    args = [arg for name in files for arg in ("-f", name)]
    return run_compose_config(args, project, env)


def _env_of(config: dict, service: str) -> dict[str, str | None]:
    return config["services"][service].get("environment") or {}


@pytest.mark.compose_cli
@pytest.mark.parametrize("files", _OVERLAY_COMBINATIONS, ids="+".join)
def test_no_secret_reaches_a_service_that_does_not_read_it(tmp_path: Path, files: list[str]):
    """Checked by VALUE, so a secret re-exposed under another name is caught too."""
    sentinels = {name: f"sentinel-{name.lower()}" for names in OWNED_SECRETS.values() for name in names}
    project = _project(tmp_path, files, {"SECRET_KEY": sentinels["SECRET_KEY"], "DOMAIN": "postern.test", **sentinels})
    config = _resolve(project, files)
    problems = []
    for service in config["services"]:
        values = [str(v) for v in _env_of(config, service).values() if v is not None]
        for owner, names in OWNED_SECRETS.items():
            if service == owner:
                absent = [n for n in names if sentinels[n] not in values]
                if absent:
                    problems.append(f"{service} does not receive its own {absent}")
                continue
            leaked = [n for n in names if any(sentinels[n] in value for value in values)]
            if leaked:
                problems.append(f"{service} receives {owner}'s {leaked}")
    assert not problems, "\n".join(problems)


@pytest.mark.compose_cli
def test_unset_variables_are_absent_not_empty(tmp_path: Path):
    """Interpolating `${VAR:-}` would turn an unset variable into "" -- the provisioner's
    `_bool_env` then reads a default-true setting as False, and the portal's `Settings`
    rejects explicitly-set EDGE_CF_* fields under a non-cloudflare profile."""
    files = ["compose.yaml"]
    project = _project(tmp_path, files, {"SECRET_KEY": "x", "DOMAIN": "postern.test"})
    config = _resolve(project, files)
    portal = _env_of(config, "portal")
    provisioner = _env_of(config, "provisioner")
    for name in (
        "EDGE_CF_MANAGE_ZONE_ECH", "EDGE_CF_MANAGE_SSL_MODE", "EDGE_CF_SSL_MODE", "EDGE_CF_AUTHENTICATED_ORIGIN_PULL",
        "SMTP_PASSWORD"
    ):
        assert portal.get(name) is None, f"portal: unset {name} resolved to {portal.get(name)!r}"
    assert provisioner.get("EDGE_CF_MANAGE_SSL_MODE") is None
    assert provisioner.get("CLOUDFLARE_API_TOKEN") is None


@pytest.mark.compose_cli
def test_dot_env_values_reach_their_service_and_the_shell_wins(tmp_path: Path):
    """The contract in docs/deployment/configuration.md: a variable in `.env` reaches the
    container that reads it, and a value exported in the shell running `docker compose`
    overrides `.env`."""
    files = ["compose.yaml"]
    project = _project(
        tmp_path, files, {
            "SECRET_KEY": "k",
            "DOMAIN": "postern.test",
            "SMTP_PASSWORD": "from-dot-env",
            "CLOUDFLARE_API_TOKEN": "from-dot-env",
        }
    )
    config = _resolve(project, files)
    assert _env_of(config, "portal")["SMTP_PASSWORD"] == "from-dot-env"
    assert _env_of(config, "provisioner")["CLOUDFLARE_API_TOKEN"] == "from-dot-env"

    config = _resolve(project, files, shell={"CLOUDFLARE_API_TOKEN": "from-shell", "SMTP_PASSWORD": "from-shell"})
    assert _env_of(config, "portal")["SMTP_PASSWORD"] == "from-shell"
    assert _env_of(config, "provisioner")["CLOUDFLARE_API_TOKEN"] == "from-shell"


@pytest.mark.compose_cli
@pytest.mark.parametrize(
    "dotenv", [{"DOMAIN": "postern.test"}, {"DOMAIN": "postern.test", "SECRET_KEY": ""}],
    ids=["secret-key-missing", "secret-key-empty"]
)
def test_a_missing_or_empty_secret_key_is_refused(tmp_path: Path, dotenv: dict[str, str]):
    """`env_file: .env` made every compose command fail without a usable `.env`, which
    scripts/deploy.sh relies on to refuse early; `SECRET_KEY: ${SECRET_KEY:?...}` keeps that."""
    project = _project(tmp_path, ["compose.yaml"], dotenv)
    with pytest.raises(AssertionError, match="SECRET_KEY"):
        _resolve(project, ["compose.yaml"])
