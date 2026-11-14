"""One tolerant Compose YAML loader, and the Compose-CLI helpers, for the compose-asserting unit tests.

`compose.gateway.yaml` uses Docker Compose's `!reset` merge tag (`ports: !reset []`),
which plain `yaml.safe_load` rejects with a ConstructorError. Every test that
parses a compose file needs this loader, not just the gateway one.

Only `!reset` is registered; add `!override` (with its own test) when a file
first needs it -- not before.
"""
from __future__ import annotations

import functools
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path
from types import ModuleType

import yaml

from postern.settings import Settings

# tests/ -> portal/ -> repo root
REPO_ROOT = Path(__file__).resolve().parent.parent.parent


class ComposeLoader(yaml.SafeLoader):
    """SafeLoader plus Compose's `!reset` merge tag. Subclassed so the constructor
    stays local -- registering on yaml.SafeLoader itself would mutate shared state
    for every other consumer in the process."""


# `!reset X` means "drop the inherited value". These tests read one file at a
# time and never perform the merge themselves, so resolving it to None is exact.
ComposeLoader.add_constructor("!reset", lambda loader, node: None)


def _narrow_implicit_resolver(
    loader: type[yaml.SafeLoader], tag: str, regexp: re.Pattern[str], first_chars: str
) -> None:
    """Replace `loader`'s stock (YAML 1.1) implicit resolver for `tag` with a
    narrower one, so ComposeLoader's scalar resolution for that tag agrees
    with Compose's own parser (go-yaml.v3) instead of PyYAML's default. Shared
    by every tag that needs this narrowing -- see the two call sites below for
    which ones, and why -- so the next one found is a one-line call instead of
    a fresh copy of this filter-then-add pattern.
    """
    loader.yaml_implicit_resolvers = {
        first_char: [(t, r) for t, r in resolvers if t != tag]
        for first_char, resolvers in loader.yaml_implicit_resolvers.items()
    }
    loader.add_implicit_resolver(tag, regexp, list(first_chars))


# PyYAML's built-in `int` resolver follows YAML 1.1, which includes a
# sexagesimal (base-60) branch: an unquoted short-form port entry like
# `- 25:25` resolves to the int 1525, not the string "25:25". Docker Compose's
# own parser (go-yaml.v3, YAML 1.2) has no such branch and reads the identical
# line as the string "25:25" -- so this narrowing is safe for both untyped
# list/map scalars and schema-typed numeric fields. Every compose file in
# this repo currently quotes its `ports:` entries, so
# this has never fired here, but a future unquoted `HOST:CONTAINER` port
# would silently misparse whenever the CONTAINER segment is under 60 -- the
# HOST segment is unbounded, e.g. `587:25` -- and every guard depending on
# `parse_published_ports` seeing a string would then either miss it entirely
# or misdiagnose why. Re-registered without the sexagesimal alternative --
# every other branch is copied verbatim from PyYAML's own stock regex.
_YAML_1_2_INT_RE = re.compile(
    r"""^(?:[-+]?0b[0-1_]+
        |[-+]?0[0-7_]+
        |[-+]?(?:0|[1-9][0-9_]*)
        |[-+]?0x[0-9a-fA-F_]+)$""", re.X
)
_narrow_implicit_resolver(ComposeLoader, "tag:yaml.org,2002:int", _YAML_1_2_INT_RE, "-+0123456789")

# Same defect, same fix, for `float`: PyYAML's stock float resolver carries
# the identical sexagesimal branch, so an unquoted colon-shaped decimal like
# `5:30.5` would misparse instead of staying a string. Narrowed the same way:
# sexagesimal branch dropped, every other branch (decimal, exponent,
# .inf/.nan) copied verbatim.
_YAML_1_2_FLOAT_RE = re.compile(
    r"""^(?:[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?
        |\.[0-9][0-9_]*(?:[eE][-+][0-9]+)?
        |[-+]?\.(?:inf|Inf|INF)
        |\.(?:nan|NaN|NAN))$""", re.X
)
_narrow_implicit_resolver(ComposeLoader, "tag:yaml.org,2002:float", _YAML_1_2_FLOAT_RE, "-+0123456789.")

# `bool` is deliberately NOT narrowed the same way, despite carrying the same
# YAML-1.1-vs-1.2 divergence in the abstract (PyYAML resolves yes/no/on/off;
# a strict YAML-1.2 reading wouldn't). In an untyped context (`environment:`
# values), an unquoted `TRUSTED: yes` DOES stay the literal string "yes",
# matching YAML 1.2 -- but in a schema-typed boolean field (`networks.<n>.internal`,
# `.external`), Compose's own decoder coerces legacy yes/no/on/off spellings
# to true/false for backwards compatibility, NOT treating them as strings. A
# single loader-level resolver cannot be right for both contexts at once, and
# every boolean this test suite actually reads out of ComposeLoader
# (`internal:`, `external:`) is the schema-typed kind -- so PyYAML's stock
# (YAML 1.1) bool resolver, which already agrees with that coercion, is the
# correct default to leave in place. See
# test_load_compose_reads_legacy_bool_spellings_as_booleans in test__compose.py.

# Glob-derived compose file lists ======================================================================================
E2E_COMPOSE_DIR = REPO_ROOT / "portal" / "tests" / "e2e"


def repo_relative(path: Path) -> str:
    return str(path.relative_to(REPO_ROOT))


def PRODUCTION_COMPOSE_FILES() -> list[Path]:
    # Two shapes: overlays match `compose*.yaml`; supplementary files follow `<name>.compose.yaml`, which that glob misses.
    files = sorted(set(REPO_ROOT.glob("compose*.yaml")) | set(REPO_ROOT.glob("*.compose.yaml")))
    assert files, "no production compose files found -- these guards would pass vacuously"
    return files


def E2E_COMPOSE_FILES() -> list[Path]:
    # rglob, not glob: matches test_e2e_image_isolation.py's e2e_compose_files(),
    # so both modules agree on what "an e2e compose file" is -- a file matching
    # one guard's definition but not the other's would be caught by exactly one.
    files = sorted(E2E_COMPOSE_DIR.rglob("*.compose.yaml"))
    assert files, f"no *.compose.yaml under {E2E_COMPOSE_DIR} -- these guards would pass vacuously"
    return files


def ALL_COMPOSE_FILES() -> list[Path]:
    return PRODUCTION_COMPOSE_FILES() + E2E_COMPOSE_FILES()


def load_compose(path: Path) -> dict:
    """Parse a Docker Compose YAML file into a plain dict.

    Does not perform Compose's multi-file merge semantics -- callers that need
    the effect of `docker compose -f a -f b config` should shell out to the
    Compose CLI instead.
    """
    return yaml.load(path.read_text(encoding="utf-8"), Loader=ComposeLoader) or {}


# Derived constants shared across compose-parsing tests ================================================================
@functools.lru_cache(maxsize=1)
def production_mta_submit_subnet() -> str:
    """Production's IPAM-pinned mta-submit subnet, read from compose.yaml.

    Derived, never hand-typed: any consumer's whole requirement is being a
    *different* subnet from whatever production currently pins, and a literal
    copy would keep comparing against a stale value after production moved.

    Lives in this docker-free, loader-only module rather than in
    portal/tests/e2e/_mta_helpers.py -- both test_compose_colocation.py (no
    Docker required, per its own docstring) and the e2e-scoped test_mta.py
    need it, and the base suite must not depend on an e2e/docker-orchestration
    module to stay Docker-free.

    A plain, lazily-memoized function rather than a module-level constant:
    this loader is imported by several unrelated compose-parsing test modules
    that only need `load_compose` (test_compose_edge.py, test_compose_gateway.py,
    test_build_revision.py, ...), and an eager call here would make every one
    of their test collections depend on compose.yaml's mta-submit block, not
    just the two modules that actually use this value.
    """
    # Tolerant of every partial shape, same pattern as test_compose_colocation.py's
    # _pinned_subnet_of -- a KeyError/IndexError here would surface as an
    # unworded traceback in whichever test happens to trigger the first call,
    # instead of a clear message.
    networks = load_compose(REPO_ROOT / "compose.yaml").get("networks") or {}
    net = networks.get("mta-submit")
    assert net is not None, "compose.yaml declares no networks.mta-submit"
    configs = (net.get("ipam") or {}).get("config") or []
    assert configs and configs[0].get("subnet"), "compose.yaml networks.mta-submit has no pinned ipam subnet"
    subnet = configs[0]["subnet"]
    assert isinstance(subnet, str), f"compose.yaml mta-submit subnet is {subnet!r}"
    return subnet


# Service environment and the real Compose CLI =========================================================================
@functools.cache
def load_verify_deploy() -> ModuleType:
    """`scripts/verify-deploy.py`, loaded once by path (it is host-side, stdlib-only, and not importable as a module).

    Registered in `sys.modules` before it executes: the script uses `from __future__ import annotations`, so
    dataclasses resolve every field annotation through `sys.modules[cls.__module__]`, and without the registration
    every dataclass in it raises AttributeError at import. Memoized so every caller shares one module (one
    `CollectError` class, one `Completed`).
    """
    spec = importlib.util.spec_from_file_location("verify_deploy", REPO_ROOT / "scripts" / "verify-deploy.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def service_environment(path: Path, service: str) -> dict[str, str | None]:
    """A service's `environment` as a dict, accepting both Compose forms.

    Parsing is `verify-deploy.py`'s `service_environment`, the one implementation: the mapping form is what
    this repo uses; the `- KEY=VALUE` list form is equally valid Compose; a bare `- KEY` entry (or a null mapping
    value) maps to None, since "value comes from the host" is not "malformed file". Values are strings or None.
    """
    env = ((load_compose(path).get("services") or {}).get(service) or {}).get("environment")
    assert env is None or isinstance(env, (dict, list)),         f"{repo_relative(path)}: service {service!r} environment is {type(env).__name__}"
    return load_verify_deploy().service_environment({"environment": env})


def run_compose_config(compose_args: list[str], cwd: Path, env: dict[str, str]) -> dict:
    """Shell out to the real Compose CLI's `config --format json` and return
    the parsed result.
    """
    proc = subprocess.run(
        ["docker", "compose", *compose_args, "config", "--format", "json"],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        # A hung child (Docker-context probe, credential helper) must fail with this subprocess named; keep below pyproject's `timeout = 30`.
        timeout=20,
    )
    assert proc.returncode == 0, f"`docker compose config` failed:\n{proc.stderr}"
    return json.loads(proc.stdout)


# Names no Compose-CLI test may inherit from the developer's own shell: every portal setting, plus the
# variables Compose itself reads. A test that cares about another name passes it as `scrub`.
_ALWAYS_SCRUBBED = frozenset({"COMPOSE_FILE", "COMPOSE_PROFILES", "COMPOSE_PROJECT_NAME", "GIT_REVISION"})


def compose_project(tmp_path: Path, files: Iterable[str], dotenv: Mapping[str, str]) -> Path:
    """Copy repo-root compose `files` and a fresh `.env` into `tmp_path`.

    Compose resolves `.env` against the project directory, so resolving the repo's own files would read
    the operator's real `.env`. The copies are byte-identical, so what is resolved is the shipped file.
    """
    for name in files:
        shutil.copy(REPO_ROOT / name, tmp_path / name)
    dotenv_lines = [f"{key}={value}\n" for key, value in dotenv.items()]
    (tmp_path / ".env").write_text("".join(dotenv_lines), encoding="utf-8")
    return tmp_path


def resolve_compose(
    project: Path,
    files: Iterable[str],
    shell: Mapping[str, str] | None = None,
    scrub: Iterable[str] = (),
) -> dict:
    """`docker compose -f <files> config` in `project`, with `shell` as the deploying shell.

    The environment is the caller's own minus every `Settings` field, `_ALWAYS_SCRUBBED` and `scrub`,
    so a value exported in the developer's shell cannot leak into what is asserted.
    """
    scrubbed = {field.upper() for field in Settings.model_fields} | _ALWAYS_SCRUBBED | set(scrub)
    env = {k: v for k, v in os.environ.items() if k not in scrubbed}
    env.update(shell or {})
    return run_compose_config([arg for name in files for arg in ("-f", name)], project, env)
