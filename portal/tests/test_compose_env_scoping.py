"""Each compose service receives exactly the variables it reads.

No compose file uses `env_file:`. Every service lists its variables under
`environment:` as bare passthrough keys, so a variable reaches a service through
one channel only, and an unset variable stays absent in the container (the
portal and provisioner treat "set but empty" differently from "unset").

The read sets are derived from source, so a new `Settings` field, entrypoint
variable or DNS provider that is not wired into compose fails here, and so does
a variable compose delivers that nothing reads.
Static checks parse the YAML; `compose_cli` tests resolve it with the real
Compose CLI (no daemon).
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from postern.settings import Settings

from ._compose import (
    ALL_COMPOSE_FILES,
    REPO_ROOT,
    compose_project,
    load_compose,
    repo_relative,
    resolve_compose,
    service_environment,
)

COMPOSE = REPO_ROOT / "compose.yaml"
E2E_MTA_REAL = REPO_ROOT / "portal" / "tests" / "e2e" / "e2e-mta-real.compose.yaml"

# What each service reads, derived from source =========================================================================
_STRING_LITERAL = r"""["']([A-Z][A-Z0-9_]*)["']"""
# Every spelling of an environment read in the Python sources: os.environ[...], os.environ.get(...), os.getenv(...),
# env.get(...) / self.env.get(...) (an injected copy of os.environ), and the entrypoints' own _require / _bool_env.
_PY_ENV_READ = re.compile(
    r"(?:os\.environ(?:\.get\(|\[)|os\.getenv\(|\benv\.get\(|\benv\[|\b_require\(|\b_bool_env\()\s*" + _STRING_LITERAL
)
# lego_env.py also passes a provider's variables through in a loop: `for k in ("A", "B"): if k in env`.
_PY_ENV_TUPLE = re.compile(r"\bfor \w+ in \(((?:\s*[\"'][A-Z][A-Z0-9_]*[\"'],?)+)\s*\)")
_SH_ENV_READ = re.compile(r"\$\{?([A-Z][A-Z0-9_]*)")

# Test hooks the e2e compose files set explicitly; production does not deliver them.
_MTA_TEST_HOOKS = {"MTA_E2E_TRANSPORT_OVERRIDE"}
# Read only by the pebble e2e provider, which the e2e stack sets itself.
_PROVISIONER_TEST_HOOKS = {"LEGO_EXEC_PATH"}
# Injection seams of the nginx scripts (their unit tests set them), a render-internal template token and a local.
_NGINX_SEAMS = {
    "TEMPLATE_DIR", "TARGET_DIR", "PROXY_PROTOCOL_LISTEN", "EDGE_DIR", "EDGE_SELF", "EDGE_NGINX", "EDGE_INOTIFYD",
    "EDGE_WATCHER_PID"
}
# Names a service receives that its own source never spells out: the Docker SDK reads DOCKER_HOST.
_RECEIVED_WITHOUT_BEING_SPELLED = {"portal": {"DOCKER_HOST"}}

# Lego's documented environment variables for the eight DNS_PROVIDERs (credentials and tuning), from
# https://github.com/go-acme/lego/blob/v4.35.2/providers/dns/<slug>/<slug>.toml, plus AWS_SESSION_TOKEN, which the
# route53 description names. The provisioner runs lego with its whole environment, so lego reads these without any
# Postern code naming them. A new lego version means re-reading those pages (see test_lego_variables_match_the_pin).
# Left out on purpose: route53's file-based credentials (AWS_PROFILE, AWS_SHARED_CREDENTIALS_FILE, AWS_SDK_LOAD_CONFIG).
# The provisioner is read-only with no ~/.aws, so they can only break it (a profile that names nothing is an error).
# Static keys, optionally with AWS_SESSION_TOKEN, are the supported route53 credentials.
_LEGO_DOCS_VERSION = "v4.35.2"
_LEGO_TUNING = ("POLLING_INTERVAL", "PROPAGATION_TIMEOUT", "TTL", "HTTP_TIMEOUT")
LEGO_NATIVE_VARS = frozenset({
    # cloudflare
    "CF_API_EMAIL", "CF_API_KEY", "CF_DNS_API_TOKEN", "CF_ZONE_API_TOKEN", "CLOUDFLARE_EMAIL", "CLOUDFLARE_API_KEY",
    "CLOUDFLARE_DNS_API_TOKEN", "CLOUDFLARE_ZONE_API_TOKEN", "CLOUDFLARE_BASE_URL",
    *(f"CLOUDFLARE_{t}" for t in _LEGO_TUNING),
    # route53
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_REGION", "AWS_HOSTED_ZONE_ID",
    "AWS_ASSUME_ROLE_ARN", "AWS_EXTERNAL_ID", "AWS_WAIT_FOR_RECORD_SETS_CHANGED", "AWS_PRIVATE_ZONE", "AWS_MAX_RETRIES",
    "AWS_POLLING_INTERVAL", "AWS_PROPAGATION_TIMEOUT", "AWS_TTL",
    # gandi (lego slug gandiv5)
    "GANDIV5_PERSONAL_ACCESS_TOKEN", "GANDIV5_API_KEY", *(f"GANDIV5_{t}" for t in _LEGO_TUNING),
    # digitalocean
    "DO_AUTH_TOKEN", "DO_API_URL", "DO_POLLING_INTERVAL", "DO_PROPAGATION_TIMEOUT", "DO_TTL", "DO_HTTP_TIMEOUT",
    # ovh
    "OVH_ENDPOINT", "OVH_APPLICATION_KEY", "OVH_APPLICATION_SECRET", "OVH_CONSUMER_KEY", "OVH_CLIENT_ID",
    "OVH_CLIENT_SECRET", "OVH_ACCESS_TOKEN", *(f"OVH_{t}" for t in _LEGO_TUNING),
    # hetzner
    "HETZNER_API_TOKEN", *(f"HETZNER_{t}" for t in _LEGO_TUNING),
    # linode (lego slug linodev4)
    "LINODE_TOKEN", *(f"LINODE_{t}" for t in _LEGO_TUNING),
    # namecheap
    "NAMECHEAP_API_USER", "NAMECHEAP_API_KEY", "NAMECHEAP_SANDBOX", *(f"NAMECHEAP_{t}" for t in _LEGO_TUNING),
})  # yapf: disable


def _read(*relpaths: str) -> str:
    return "\n".join((REPO_ROOT / relpath).read_text(encoding="utf-8") for relpath in relpaths)


def _python_env_reads(*relpaths: str) -> set[str]:
    text = _read(*relpaths)
    names = {name for match in _PY_ENV_READ.finditer(text) for name in match.groups()}
    for match in _PY_ENV_TUPLE.finditer(text):
        names.update(re.findall(_STRING_LITERAL, match.group(1)))
    return names


def _shell_env_reads(*relpaths: str) -> set[str]:
    code = "\n".join(line for line in _read(*relpaths).splitlines() if not line.lstrip().startswith("#"))
    return set(_SH_ENV_READ.findall(code))


def _go_provider_vars() -> frozenset[str]:
    """Every variable `newProvider` reads in provisioner/postern-dns/main.go, the one
    place libdns-native names enter the stack (`lego_env.py` translates the same set)."""
    source = _read("provisioner/postern-dns/main.go")
    body = source[source.index("func newProvider("):]
    body = body[:body.index("\n}\n")]
    code = "\n".join(line for line in body.splitlines() if not line.lstrip().startswith("//"))
    return frozenset(re.findall(r'os\.Getenv\("([A-Z0-9_]+)"\)', code))


def _provisioner_python_modules() -> list[str]:
    modules = sorted(str(p.relative_to(REPO_ROOT)) for p in (REPO_ROOT / "portal/src/postern_provisioner").glob("*.py"))
    return ["provisioner/entrypoint.py", *modules]


@pytest.fixture(scope="module")
def provider_vars() -> frozenset[str]:
    names = _go_provider_vars()
    assert names, "no os.Getenv names found in newProvider -- the derivation rotted"
    return names


@pytest.fixture(scope="module")
def provisioner_provider_vars(provider_vars: frozenset[str]) -> frozenset[str]:
    """Every DNS provider variable the provisioner must receive: postern-dns's and lego's own."""
    return provider_vars | LEGO_NATIVE_VARS


@pytest.fixture(scope="module")
def reads(provisioner_provider_vars: frozenset[str]) -> dict[str, set[str]]:
    """What each service's code reads, derived from source."""
    derived = {
        "portal": {field.upper()
                   for field in Settings.model_fields},
        "mta": _python_env_reads("mta/entrypoint.py") - _MTA_TEST_HOOKS,
        "provisioner": (_python_env_reads(*_provisioner_python_modules()) | provisioner_provider_vars)
                       - _PROVISIONER_TEST_HOOKS,
        "nginx": _shell_env_reads("nginx/render.sh", "nginx/nginx-entrypoint.sh", "nginx/edge.sh") - _NGINX_SEAMS,
    }  # yapf: disable
    for service, names in derived.items():
        assert names, f"derived read set for {service} is empty -- the derivation rotted"
    return derived


# Static pins ==========================================================================================================
def test_no_compose_file_loads_an_env_file():
    problems = [
        f"{repo_relative(path)}: service {name!r} sets env_file" for path in ALL_COMPOSE_FILES()
        for name, service in (load_compose(path).get("services") or {}).items() if "env_file" in (service or {})
    ]
    assert not problems, "\n".join(problems)


def test_provider_credentials_reach_only_the_provisioner(provisioner_provider_vars: frozenset[str]):
    problems = [
        f"{repo_relative(path)}: service {name!r} receives {sorted(leaked)}" for path in ALL_COMPOSE_FILES()
        for name in (load_compose(path).get("services") or {})
        if name != "provisioner" and (leaked := provisioner_provider_vars & service_environment(path, name).keys())
    ]
    assert not problems, "\n".join(problems)


def test_the_e2e_real_provisioner_receives_every_provider_variable_production_does(
    provisioner_provider_vars: frozenset[str]
):
    """The overlay's provisioner is the production one with a real DNS provider (maintainer-run); a
    credential the production list delivers but the overlay drops fails only on that manual run."""
    missing = provisioner_provider_vars - service_environment(E2E_MTA_REAL, "provisioner").keys()
    assert not missing, f"{repo_relative(E2E_MTA_REAL)}: provisioner lacks {sorted(missing)}"


@pytest.mark.parametrize("service", ["portal", "mta", "provisioner", "nginx"])
def test_every_service_receives_exactly_what_it_reads(service: str, reads: dict[str, set[str]]):
    received = service_environment(COMPOSE, service).keys()
    missing = reads[service] - received
    unread = received - reads[service] - _RECEIVED_WITHOUT_BEING_SPELLED.get(service, set())
    problems = []
    if missing:
        problems.append(f"compose.yaml's {service} never receives {sorted(missing)}, which its code reads")
    if unread:
        problems.append(f"compose.yaml's {service} receives {sorted(unread)}, which nothing in it reads")
    assert not problems, "\n".join(problems)


def test_lego_variables_match_the_pin():
    """LEGO_NATIVE_VARS was read off lego's provider pages at one version."""
    pinned = re.search(r"github\.com/go-acme/lego/v4/cmd/lego@(v[0-9.]+)", _read("provisioner/Dockerfile"))
    assert pinned, "provisioner/Dockerfile no longer pins lego with `go install ...lego@<version>`"
    assert pinned.group(1) == _LEGO_DOCS_VERSION, (
        f"lego is pinned at {pinned.group(1)} but LEGO_NATIVE_VARS was read from {_LEGO_DOCS_VERSION}: re-read the "
        "providers/dns/<slug>/<slug>.toml pages for the eight providers and update the set and the version"
    )


# Resolved by the real Compose CLI =====================================================================================
_OVERLAY_COMBINATIONS = [
    ["compose.yaml"],
    ["compose.yaml", "compose.cert.yaml"],
    ["compose.yaml", "compose.cert.yaml", "compose.gateway.yaml"],
    ["compose.yaml", "compose.edge.yaml"],
]
_ALL_PROFILES = "with-mta,with-cert-renewal,with-edge"


def _resolve(
    project: Path, files: list[str], provider_vars: frozenset[str], shell: dict[str, str] | None = None
) -> dict:
    """Resolve with every profile on and nothing but `shell` (and the provider names) from the developer's shell."""
    return resolve_compose(project, files, {"COMPOSE_PROFILES": _ALL_PROFILES, **(shell or {})}, scrub=provider_vars)


def _env_of(config: dict, service: str) -> dict[str, str | None]:
    return config["services"][service].get("environment") or {}


@pytest.mark.compose_cli
@pytest.mark.parametrize("files", _OVERLAY_COMBINATIONS, ids="+".join)
def test_no_secret_reaches_a_service_that_does_not_read_it(
    tmp_path: Path, files: list[str], provisioner_provider_vars: frozenset[str]
):
    """Checked by VALUE, so a secret re-exposed under another name is caught too."""
    owned = {
        "portal": ("SECRET_KEY", "SMTP_PASSWORD", "SMTP_USER"),
        "provisioner": tuple(sorted(provisioner_provider_vars)),
    }
    sentinels = {name: f"sentinel-{name.lower()}-end" for names in owned.values() for name in names}
    project = compose_project(tmp_path, files, {"DOMAIN": "postern.test", **sentinels})
    config = _resolve(project, files, provisioner_provider_vars)
    problems = []
    for service in config["services"]:
        values = [str(v) for v in _env_of(config, service).values() if v is not None]
        for owner, names in owned.items():
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
def test_unset_variables_are_absent_not_empty(tmp_path: Path, provisioner_provider_vars: frozenset[str]):
    """Interpolating `${VAR:-}` would turn an unset variable into "" -- the provisioner's
    `_bool_env` then reads a default-true setting as False, and the portal's `Settings`
    rejects explicitly-set EDGE_CF_* fields under a non-cloudflare profile. So every bare
    passthrough key, in every service, resolves to absent when nothing sets it."""
    files = ["compose.yaml"]
    project = compose_project(tmp_path, files, {"SECRET_KEY": "x", "DOMAIN": "postern.test"})
    config = _resolve(project, files, provisioner_provider_vars)
    declared = load_compose(COMPOSE)["services"]
    checked = set()
    problems = []
    for service in config["services"]:
        keys = service_environment(COMPOSE, service)
        resolved = _env_of(config, service)
        undeclared = resolved.keys() - keys.keys()
        if undeclared:
            problems.append(f"{service} receives {sorted(undeclared)}, which compose.yaml does not declare")
        assert service in declared, f"{service} resolved but is not in compose.yaml"
        for name, value in keys.items():
            if value is not None or name in {"SECRET_KEY", "DOMAIN"}:
                continue
            checked.add(name)
            if resolved.get(name) is not None:
                problems.append(f"{service}: unset {name} resolved to {resolved[name]!r}")
    assert not problems, "\n".join(problems)
    assert {"EDGE_CF_MANAGE_ZONE_ECH", "EDGE_CF_MANAGE_SSL_MODE", "SMTP_PASSWORD", "CLOUDFLARE_API_TOKEN"} <= checked


@pytest.mark.compose_cli
def test_dot_env_values_reach_their_service_and_the_shell_wins(
    tmp_path: Path, provisioner_provider_vars: frozenset[str]
):
    """The contract in docs/deployment/configuration.md: a variable in `.env` reaches the
    container that reads it, and a value exported in the shell running `docker compose`
    overrides `.env`."""
    files = ["compose.yaml"]
    project = compose_project(
        tmp_path, files, {
            "SECRET_KEY": "k",
            "DOMAIN": "postern.test",
            "SMTP_PASSWORD": "from-dot-env",
            "CLOUDFLARE_API_TOKEN": "from-dot-env",
        }
    )
    config = _resolve(project, files, provisioner_provider_vars)
    assert _env_of(config, "portal")["SMTP_PASSWORD"] == "from-dot-env"
    assert _env_of(config, "provisioner")["CLOUDFLARE_API_TOKEN"] == "from-dot-env"

    shell = {"CLOUDFLARE_API_TOKEN": "from-shell", "SMTP_PASSWORD": "from-shell"}
    config = _resolve(project, files, provisioner_provider_vars, shell)
    assert _env_of(config, "portal")["SMTP_PASSWORD"] == "from-shell"
    assert _env_of(config, "provisioner")["CLOUDFLARE_API_TOKEN"] == "from-shell"


@pytest.mark.compose_cli
@pytest.mark.parametrize(
    "dotenv", [{"DOMAIN": "postern.test"}, {"DOMAIN": "postern.test", "SECRET_KEY": ""}],
    ids=["secret-key-missing", "secret-key-empty"]
)
def test_a_missing_or_empty_secret_key_is_refused(
    tmp_path: Path, dotenv: dict[str, str], provisioner_provider_vars: frozenset[str]
):
    """`env_file: .env` made every compose command fail without a usable `.env`, which
    scripts/deploy.sh relies on to refuse early; `SECRET_KEY: ${SECRET_KEY:?...}` keeps that."""
    project = compose_project(tmp_path, ["compose.yaml"], dotenv)
    with pytest.raises(AssertionError, match="SECRET_KEY"):
        _resolve(project, ["compose.yaml"], provisioner_provider_vars)
