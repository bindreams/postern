#!/usr/bin/env python3
"""Assert the running stack is the stack this checkout describes (issue #195).

Runs on the *host*, not in a container, for three reasons:

  1. Desired state lives in `docker compose config`, which the portal cannot
     see -- it has the Docker API but not the compose files. Only the host can
     notice that a service which should exist does not.
  2. A check that ships inside the artifact it verifies is circular: a stale
     portal runs a stale check.
  3. A failed deploy often means the portal is not healthy, and the gate must
     still produce a diagnosis rather than an `exec` error.

Stdlib only: the deploy host is documented to have Docker Engine and Compose,
nothing else.

Two staleness modes, each with a different fix:

  * stale revision -- the image was never rebuilt from this checkout
    (`docker compose up -d --build` was skipped). This is issue #195's incident.
  * stale image ID -- the tag was rebuilt but the container was not recreated,
    OR something else on this host moved the tag (a manual build, a different
    checkout, a restored image).
  * unconverged tunnels -- the reconcile pass finished, but the ss-* containers
    are not the set the deployment's enabled connections call for. Only checked
    when the caller supplies `--expected-tunnels-from`: the answer lives in the
    portal's database, and asking the portal how the deploy went would cost this
    script the property in reason 3 above. scripts/deploy.sh supplies it, after
    blocking on a completed pass. The two observations are not simultaneous and
    nothing locks either of them -- see docs/operations/index.md for the
    no-mutation-during-a-deploy assumption that follows.

Plus a liveness check: a container's health status (from its Docker
HEALTHCHECK, when one is defined) must not be `unhealthy`. This is
point-in-time, not polled: `starting` (the status right after `up -d`, before
the first probe has run) passes, `unhealthy` fails.

Exit codes are three-valued and the distinction matters to callers:

  0 -- every check passed.
  1 -- a check FAILED: the deployment is stale.
  2 -- verify-deploy could not run (bad --repo or --project-dir, docker not on
       PATH, unparseable compose output, usage error). NOT a verdict about the
       deployment. Issue #196's deploy entrypoint must not read 2 as 1.

No failure path produces a traceback.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Literal, NamedTuple

# Types ================================================================================================================
Status = Literal["ok", "fail", "skip"]

# Label column width. Pinned by test_render_text_columns_align, whose fixture
# includes the longest label the tool emits:
# `tunnel ss-<24 hex>: image identity` is 50 characters.
_LABEL_W = 52


@dataclass(frozen=True)
class Check:
    """One row of output. A FAIL always carries a fix hint so the operator has
    somewhere to go; OK and SKIP rows leave it empty."""
    label: str
    status: Status
    detail: str = ""
    fix: str = ""


@dataclass
class Report:
    project: str
    revision: str
    checks: list[Check] = field(default_factory=list)
    # Overrides the computed 0/1 below. Exists solely for main()'s CollectError
    # path: that Report carries one failing Check (so the printed text/JSON
    # reads as a failure), but the process must exit 2, not 1 -- "could not
    # run" is not a verdict, and the JSON payload's exit_code field must agree
    # with the real process exit code or a caller parsing the JSON is misled.
    exit_code_override: int | None = None

    @property
    def failures(self) -> list[Check]:
        return [c for c in self.checks if c.status == "fail"]

    @property
    def exit_code(self) -> int:
        if self.exit_code_override is not None:
            return self.exit_code_override
        return 1 if self.failures else 0


class Completed(NamedTuple):
    """A finished subprocess. Errors are returned, not raised: `docker inspect`
    over a list of names exits non-zero when one is gone but still prints the
    ones that were found, and that partial output is exactly what we want."""
    returncode: int
    stdout: str
    stderr: str


Runner = Callable[[Sequence[str], "Path | None"], Completed]


class CollectError(RuntimeError):
    """A command we cannot proceed without failed (compose config / ps)."""


# Revision oracle ======================================================================================================
class RevisionError(RuntimeError):
    """`--repo` is not a usable git checkout."""


def git_revision(repo: Path) -> str:
    """The revision a build from `repo` would carry.

    Untracked files count as dirty: anything git does not track is not
    described by any commit, so the resulting image is not either. `-dirty` is
    a flag, not an identifier -- two different dirty trees produce the same
    string, which is why `evaluate` refuses to certify a dirty deployment
    unless the operator passes --allow-dirty.

    Raises RevisionError rather than CalledProcessError/FileNotFoundError, so
    a missing git or a non-checkout --repo surfaces as a message and not a
    stack dump -- issue #196's deploy entrypoint calls --print-revision first,
    and a traceback there would kill the deploy with no explanation.
    """

    def git(*args: str) -> str:
        try:
            # errors="replace": a git output byte sequence invalid for the
            # locale's encoding must not raise UnicodeDecodeError -- that would
            # violate "no failure path produces a traceback" the same way an
            # uncaught OSError would.
            proc = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, errors="replace")
        except OSError as exc:  # git not installed
            raise RevisionError(f"cannot run git: {exc}") from exc
        if proc.returncode != 0:
            raise RevisionError(f"git {' '.join(args)} failed in {repo}: {proc.stderr.strip()}")
        return proc.stdout.strip()

    head = git("rev-parse", "HEAD")
    return f"{head}-dirty" if git("status", "--porcelain") else head


# Observation ==========================================================================================================
# `with` yields the empty string for an absent label instead of erroring under
# missingkey=error. `.ID` (not `.Id`) is the typed field on an image: `.Id`
# forces a fallback to raw-JSON templating, which then blows up on any image
# whose config has no Labels map at all. `.State.Health` is a nil pointer when
# no HEALTHCHECK is defined; `{{if .State.Health}}` guards it the same way.
_CONTAINER_FMT = (
    '{{.Name}}\t'
    '{{with index .Config.Labels "com.docker.compose.service"}}{{.}}{{end}}\t'
    '{{.State.Status}}\t'
    '{{.State.ExitCode}}\t'
    '{{.HostConfig.RestartPolicy.Name}}\t'
    '{{.Image}}\t'
    '{{with index .Config.Labels "org.opencontainers.image.revision"}}{{.}}{{end}}\t'
    '{{if .State.Health}}{{.State.Health.Status}}{{end}}'
)
_IMAGE_FMT = ('{{.ID}}\t'
              '{{with index .Config.Labels "org.opencontainers.image.revision"}}{{.}}{{end}}')

MANAGED_FILTER = "label=postern.managed=true"
INSTANCE_LABEL = "postern.instance"
DEFAULT_SS_IMAGE = "local/shadowsocks-server"
# `docker compose run` leftovers carry the project AND service labels. Including
# them would shadow the real container in the service lookup, or be reported as
# an orphan.
ONEOFF_FILTER = "label=com.docker.compose.oneoff=False"


@dataclass(frozen=True)
class ServiceSpec:
    name: str
    image: str
    first_party: bool  # declares `build:`, so it should carry a revision label


@dataclass(frozen=True)
class ContainerState:
    service: str  # "" for containers outside the compose project (ss-*)
    name: str
    state: str
    exit_code: int
    restart_policy: str
    image_id: str
    revision: str  # "" when the image carries no revision label
    health: str  # "" when no HEALTHCHECK is configured for this container

    @property
    def completed_one_shot(self) -> bool:
        """A service that ran to completion and was not meant to stay up.

        The provisioner is exactly this in the default topology: with no
        DNS_PROVIDER it logs "nothing to publish" and exits 0, and compose.yaml
        gives it `restart: "no"` precisely so it stays exited. Reporting that
        as a failed deploy would red-flag a correct install.
        """
        return self.state == "exited" and self.exit_code == 0 and self.restart_policy in ("", "no")


@dataclass
class Observation:
    project: str
    services: tuple[ServiceSpec, ...]
    containers: tuple[ContainerState, ...]
    tag_ids: dict[str, str]  # image ref -> current ID; "" when the tag is gone
    tag_revisions: dict[str, str]
    ss_image: str
    ss_containers: tuple[ContainerState, ...]


def run_command(argv: Sequence[str], cwd: Path | None = None) -> Completed:
    try:
        # errors="replace": see the matching comment in git_revision.git().
        proc = subprocess.run(list(argv), cwd=cwd, capture_output=True, text=True, errors="replace")
    except OSError as exc:
        # A typo'd --project-dir, or `docker` missing from PATH. Same class as
        # RevisionError: a misconfiguration must read as a message, not a stack
        # dump, and must not be mistaken for "the deployment is stale".
        raise CollectError(f"cannot run {argv[0]}: {exc}") from exc
    return Completed(proc.returncode, proc.stdout, proc.stderr)


def _portal_env(config: dict) -> dict[str, str]:
    """The compose-resolved portal environment, keyed upper-case.

    `Settings` (pydantic-settings) has no `model_config` overriding the
    library default, which is case-INSENSITIVE: a `.env` entry spelled
    `shadowsocks_image=...` or `instance_id=...` is authoritative for the
    portal, and a case-sensitive `dict.get` here would miss it -- silently,
    in the passing direction, which is the one failure mode this script
    exists to eliminate.
    """
    raw = (config.get("services", {}).get("portal", {}) or {}).get("environment") or {}
    return {k.upper(): v for k, v in raw.items()}


def resolve_ss_image(config: dict, flag: str) -> str:
    """The tunnel image ref the portal will actually spawn.

    SHADOWSOCKS_IMAGE is a portal Settings field reaching the container through
    `env_file: .env`. It is NOT compose interpolation, so the host shell's
    environment has no bearing on it -- reading $SHADOWSOCKS_IMAGE here would
    invert the precedence and verify an image nothing uses.

    `docker compose config --format json` already resolves `env_file` into
    `services.<name>.environment` (and drops the `env_file` key), so the
    authoritative value is in the config we have already parsed. That is why
    there is no .env parser in this script.
    """
    if flag:
        return flag
    return _portal_env(config).get("SHADOWSOCKS_IMAGE") or DEFAULT_SS_IMAGE


def resolve_instance_id(config: dict, project: str) -> str:
    """The `postern.instance` label value `--tunnels` filters on.

    Mirrors `reconciler.resolve_instance_id`: an explicit INSTANCE_ID override
    (already folded into services.portal.environment by `docker compose
    config`, the same way SHADOWSOCKS_IMAGE is) wins; otherwise the compose
    project name IS the value the reconciler derives, because compose.yaml's
    `COMPOSE_PROJECT_NAME: ${COMPOSE_PROJECT_NAME:-}` passthrough feeds
    Settings.compose_project_name from the exact same project-name resolution
    `docker compose config`'s "name" already reports.

    Scoping tunnels this way keeps a host running more than one Postern
    deployment (production + an e2e run, two checkouts, ...) from reporting
    a DIFFERENT deployment's tunnels as this one's.
    """
    override = (_portal_env(config).get("INSTANCE_ID") or "").strip()
    return override or project


def _parse_containers(stdout: str) -> tuple[ContainerState, ...]:
    """Parse `_CONTAINER_FMT`'s tab-separated output.

    Both checks below raise CollectError rather than padding/truncating or
    defaulting silently: a label value an operator controls (GIT_REVISION,
    forwarded verbatim into org.opencontainers.image.revision) could in
    principle contain a tab or newline, which would shift every field after
    it. A field-count mismatch is exactly that shift; an unparseable exit
    code is the same failure surfacing one field over. Either one silently
    misreading `revision` or `health` -- or defaulting `exit_code` to 0, which
    `ContainerState.completed_one_shot` treats as "exited cleanly" -- is worse
    than a loud stop.
    """
    states: list[ContainerState] = []
    for line in stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != 8:
            raise CollectError(f"docker inspect produced {len(parts)} fields (expected 8) in line: {line!r}")
        name, service, state, exit_code, restart_policy, image_id, revision, health = parts
        if not exit_code.strip().lstrip("-").isdigit():
            raise CollectError(f"docker inspect produced a non-numeric exit code {exit_code!r} for {name!r}")
        states.append(
            ContainerState(
                service=service,
                name=name.lstrip("/"),
                state=state,
                exit_code=int(exit_code),
                restart_policy=restart_policy,
                image_id=image_id,
                revision=revision,
                health=health,
            )
        )
    return tuple(states)


def _inspect(run: Runner, names: Sequence[str]) -> tuple[ContainerState, ...]:
    """Inspect every name in one call.

    A non-zero exit means at least one name was gone -- but docker still prints
    the ones it found, and that partial output is the answer we want. Names
    that came back empty simply do not appear, which `evaluate` reports as a
    missing container. Pre-checking existence would only move the race.
    """
    if not names:
        return ()
    result = run(["docker", "inspect", "--type", "container", "--format", _CONTAINER_FMT, *names], None)
    return _parse_containers(result.stdout)


def _names(run: Runner, *filters: str) -> list[str]:
    argv = ["docker", "ps", "-a"]
    for docker_filter in filters:
        argv += ["--filter", docker_filter]
    result = run([*argv, "--format", "{{.Names}}"], None)
    if result.returncode != 0:
        # Unlike `docker inspect` (see `_inspect`'s docstring), a non-zero
        # `docker ps` has no useful partial output -- it means the daemon or
        # the filter expression is broken, not "some names were not found".
        # Reading it as "zero containers" would misreport a broken
        # environment as every service missing (exit 1), when it must be
        # exit 2: not a verdict about the deployment.
        raise CollectError(f"docker ps failed: {result.stderr.strip()}")
    return [n.strip() for n in result.stdout.splitlines() if n.strip()]


# A container name, not the token inside it: deliberately NOT `ss-[a-f0-9]{24}`.
# The token's width lives in three places already (nginx.conf's regex, cli.py's
# token_hex(12), reconciler.py's _container_name) and CLAUDE.md pins them to each
# other; a fourth copy here would drift silently. This only has to reject text
# that is not a container name at all.
_TUNNEL_NAME = re.compile(r"^ss-\S+$")


def read_expected_tunnels(path: str) -> frozenset[str]:
    """The tunnel container names the caller says should exist, one per line.

    `-` reads stdin, which is how scripts/deploy.sh passes them: a container
    name embeds its connection's path token, and argv is world-readable through
    `ps` on the deploy host while `docker ps` is not.

    Blank lines are ignored so an empty input is the empty set -- a real answer
    (a deployment with no enabled connections), distinct from not passing the
    flag at all. Anything else that is not a container name raises rather than
    being skipped: if the portal ever printed a warning on stdout, silently
    dropping it would be indistinguishable from a shorter expected set.
    """
    try:
        if path == "-":
            # sys.stdin is None with fd 0 closed (CPython sets it that way), not an
            # object that raises on .read() -- must be caught before dereferencing.
            if sys.stdin is None:
                raise CollectError("cannot read the expected tunnel list: stdin is closed")
            text = sys.stdin.read()
        else:
            text = Path(path).read_text(errors="replace")
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        # UnicodeDecodeError is not an OSError. The file branch cannot raise either
        # (errors="replace"), but sys.stdin decodes strictly and raises ValueError
        # on an already-closed stream -- "no failure path produces a traceback"
        # applies to both halves of this function.
        raise CollectError(f"cannot read the expected tunnel list: {exc}") from exc
    names = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if not _TUNNEL_NAME.match(line):
            raise CollectError(f"expected tunnel list contains something that is not a container name: {line!r}")
        names.add(line)
    return frozenset(names)


def collect(run: Runner, project_dir: Path, ss_image_flag: str = "", *, tunnels: bool) -> Observation:
    """Gather desired state (compose) and observed state (docker).

    Compose subprocesses run with cwd=project_dir: --project-directory sets the
    base for relative paths but does NOT control compose-file discovery, and
    -f would break COMPOSE_FILE overlay chains.
    """
    compose = ["docker", "compose"]

    config_result = run([*compose, "config", "--format", "json"], project_dir)
    if config_result.returncode != 0:
        raise CollectError(f"docker compose config failed: {config_result.stderr.strip()}")
    try:
        config = json.loads(config_result.stdout)
    except ValueError as exc:
        raise CollectError(f"docker compose config emitted unparseable JSON: {exc}") from exc

    # Refuse to verify nothing. A wrong --project-dir, or a COMPOSE_PROFILES
    # that gates every service off, would otherwise exit 0 having checked
    # nothing -- the same vacuous-pass failure the docs gates guard against.
    if not config.get("services"):
        raise CollectError(
            "compose resolved zero services -- wrong --project-dir, or every service is "
            "gated off by COMPOSE_PROFILES"
        )
    if not config.get("name"):
        raise CollectError("compose resolved no project name")
    missing_image = sorted(n for n, s in config["services"].items() if not s.get("image"))
    if missing_image:
        raise CollectError(f"services with no `image:` tag, so identity cannot be checked: {missing_image}")

    ss_image = resolve_ss_image(config, ss_image_flag)
    services = tuple(
        ServiceSpec(name=name, image=spec.get("image", ""), first_party="build" in spec)
        for name, spec in sorted(config["services"].items())
    )

    project = config["name"]
    # `docker ps` on the project label rather than `docker compose ps`: a
    # container whose service was deleted from compose.yaml still carries the
    # project label, so orphans stay visible.
    containers = _inspect(run, _names(run, f"label=com.docker.compose.project={project}", ONEOFF_FILTER))

    tag_ids: dict[str, str] = {}
    tag_revisions: dict[str, str] = {}
    for ref in sorted({s.image for s in services if s.image} | {ss_image}):
        result = run(["docker", "image", "inspect", ref, "--format", _IMAGE_FMT], None)
        if result.returncode != 0:
            tag_ids[ref], tag_revisions[ref] = "", ""
            continue
        image_id, revision = (result.stdout.strip().split("\t") + ["", ""])[:2]
        tag_ids[ref], tag_revisions[ref] = image_id, revision

    if tunnels:
        instance_id = resolve_instance_id(config, project)
        ss_containers = _inspect(run, _names(run, MANAGED_FILTER, f"label={INSTANCE_LABEL}={instance_id}"))
    else:
        ss_containers = ()
    # `docker inspect` is a separate call from `docker ps`; a concurrent
    # `docker compose up` can therefore be observed mid-flight. Run this after
    # `up -d` has returned (the runbook says so).

    return Observation(
        project=project,
        services=services,
        containers=containers,
        tag_ids=tag_ids,
        tag_revisions=tag_revisions,
        ss_image=ss_image,
        ss_containers=ss_containers,
    )


# Evaluation ===========================================================================================================
# Fix hints must be copy-pasteable and must actually fix the thing.
#
# `docker compose up -d --build` ALONE does not: with GIT_REVISION unset,
# `${GIT_REVISION:-}` resolves to empty, the rebuilt image is byte-identical,
# compose does not recreate, and the same check fails again. The export is not
# decoration.
#
# `VAR=x cmd --flag "$VAR"` does not work either -- the shell expands "$VAR"
# before the assignment takes effect, so the build arg arrives empty. Hence two
# statements, not a one-line prefix.
#
# The two statements must be `VAR=$(cmd) && export VAR`, NOT `export
# VAR=$(cmd)`: `export` is a declaration command and always returns 0
# regardless of the substitution's exit status (verified: `export
# FOO="$(exit 3)"; echo $?` prints 0 in both bash and zsh), so a failing
# --print-revision would be swallowed and the chained `&&` would proceed to
# rebuild yet another unstamped image -- the exact failure mode
# docs/operations/index.md's runbook calls out avoiding.
_EXPORT = 'GIT_REVISION="$(scripts/verify-deploy.py --print-revision)" && export GIT_REVISION'
_UP = f"{_EXPORT} && docker compose up -d --build"


def _ss_build(ref: str) -> str:
    """The build command for the tunnel image, tagged as whatever `ref` the
    portal actually resolved -- not hardcoded to the `local/shadowsocks-server`
    default. A deployment with a custom SHADOWSOCKS_IMAGE would otherwise get a
    fix hint that builds a different tag than the one the row says is missing,
    leaving the check failing on every re-run.
    """
    return f'{_EXPORT} && docker build -f shadowsocks/Dockerfile --build-arg GIT_REVISION="$GIT_REVISION" -t {ref} .'


_RECONCILE = "docker compose exec portal postern reconcile"
# Distinct from _RECONCILE: a set mismatch means the pass FINISHED without
# converging, so "trigger a pass" alone is not the whole fix -- the operator
# needs the blocking form. Fix hints must stay copy-pasteable (see the section
# comment below); the repeats-anyway guidance lives in the check details instead.
_RECONVERGE = "docker compose exec -T portal postern reconcile --wait"


def _short(revision: str) -> str:
    return revision[:12] if revision else "(none)"


def _check_identity(label: str, container: ContainerState, service: ServiceSpec, obs: Observation) -> Check:
    ref = service.image
    tag_id = obs.tag_ids.get(ref, "")
    fix = _UP if service.first_party else f"docker compose pull {container.service}".strip()
    if not tag_id:
        return Check(label, "fail", f"image tag {ref} is not present locally", fix)
    if container.image_id == tag_id:
        return Check(label, "ok", f"on {tag_id[:19]}")

    moved = f"container is on {container.image_id[:19]} but {ref} now points at {tag_id[:19]}"
    if not service.first_party:
        # Third-party images carry the UPSTREAM project's revision label
        # (docker-socket-proxy ships one), so the first-party diagnosis below
        # would read that SHA and blame a postern rebuild for a plain pull.
        return Check(
            label, "fail", f"{moved}: the tag moved (a pull or an upstream rebuild)",
            f"docker compose up -d {container.service}".strip()
        )

    tag_revision = obs.tag_revisions.get(ref, "")
    if not tag_revision:
        detail = (
            f"{moved}: the tag was rebuilt without provenance -- something other than a "
            "postern deploy moved it (a manual `docker build`, a different checkout, or a "
            "restored image)"
        )
    elif tag_revision == container.revision:
        detail = f"{moved}: same revision, so the tag was rebuilt rather than advanced"
    else:
        detail = f"{moved}: built, not recreated"
    return Check(label, "fail", detail, fix)


def _check_tunnel_set(obs: Observation, expected: frozenset[str] | None) -> list[Check]:
    """Compare the tunnel containers found against the set the caller supplied
    (see the module docstring for why the set is an argument).

    By name, never by cardinality: a pass that fails to create one container
    and fails to remove another has the right count and the wrong state, and
    the reconciler logs and swallows exactly those per-container failures.

    A concurrent mutation produces these same rows, so the detail names that
    possibility rather than asserting non-convergence as fact.
    """
    label = "tunnels: expected set"
    observed = {c.name for c in obs.ss_containers}
    if expected is None:
        return [
            Check(
                label, "skip", f"{len(observed)} found; not verified -- pass --expected-tunnels-from FILE "
                "(scripts/deploy.sh does) to make this a check"
            )
        ]
    missing = sorted(expected - observed)
    surplus = sorted(observed - expected)
    if not missing and not surplus:
        return [Check(label, "ok", f"all {len(expected)} present")]

    if not obs.tag_ids.get(obs.ss_image):
        # One row, not one per name -- and it covers surplus as well as missing.
        # reconcile() short-circuits its ENTIRE container branch when the tunnel
        # image is absent: it logs, returns, and neither creates nor removes
        # anything. So every row here is wrong for the identical reason, and
        # `postern reconcile` is a guaranteed no-op for all of them.
        return [
            Check(
                label, "fail", f"{len(missing)} missing, {len(surplus)} unexpected: image {obs.ss_image} is not "
                "present locally, so the reconciler neither created nor removed anything", _ss_build(obs.ss_image)
            )
        ]

    checks: list[Check] = []
    for name in missing:
        checks.append(
            Check(
                f"tunnel {name}: exists", "fail",
                "no container for this connection: the reconcile pass finished without converging, or the "
                "connection was added while this ran. If a fresh reconcile doesn't fix it, check `docker "
                "compose logs portal` -- a pre-instance-labelling legacy container squatting on this name "
                "is a standing cause the reconciler backs off on rather than removes (see "
                "docs/operations/index.md's post-upgrade migration)", _RECONVERGE
            )
        )
    for name in surplus:
        checks.append(
            Check(
                f"tunnel {name}: not expected", "fail",
                "no enabled connection for this container: the reconciler did not remove it, or the connection "
                "was disabled while this ran. If a fresh reconcile doesn't fix it, check `docker compose logs "
                "portal`", _RECONVERGE
            )
        )
    return checks


def evaluate(
    obs: Observation,
    expected_revision: str,
    *,
    allow_dirty: bool = False,
    tunnels: bool = False,
    expected_tunnels: frozenset[str] | None = None,
) -> Report:
    """Compare desired state against observed state. Pure.

    `expected_tunnels` is only consulted when `tunnels` is set; main() rejects
    the combination rather than silently discarding it.
    """
    checks: list[Check] = []

    # Checkout ---------------------------------------------------------------------------------------------------------
    if not expected_revision.endswith("-dirty"):
        checks.append(Check("checkout: clean", "ok", _short(expected_revision)))
    elif allow_dirty:
        checks.append(Check("checkout: clean", "skip", "dirty, acknowledged via --allow-dirty"))
    else:
        checks.append(
            Check(
                "checkout: clean", "fail", "the checkout has uncommitted or untracked files, so `-dirty` matching "
                "proves nothing: two different dirty trees produce the same string",
                "commit or stash, rebuild, and re-run; or pass --allow-dirty to acknowledge"
            )
        )

    by_service: dict[str, list[ContainerState]] = {}
    for container in obs.containers:
        if container.service:
            by_service.setdefault(container.service, []).append(container)
    declared = {s.name for s in obs.services}

    # Compose services -------------------------------------------------------------------------------------------------
    for service in obs.services:
        found = by_service.get(service.name, [])
        running_label = f"service {service.name}: running"
        if not found:
            checks.append(Check(running_label, "fail", "no container for this service", _UP))
            continue
        if len(found) > 1:
            # Never pick one arbitrarily: which container "is" the service
            # would then depend on docker's return order.
            checks.append(
                Check(
                    running_label, "fail",
                    f"{len(found)} containers claim this service ({', '.join(c.name for c in found)})",
                    "docker compose up -d --remove-orphans, or remove the stale container"
                )
            )
            continue
        container = found[0]
        if container.completed_one_shot:
            # A `restart: "no"` service that exited 0 finished its job. The
            # provisioner does this by design in the default topology.
            checks.append(Check(running_label, "skip", f"{container.name} ran to completion (exit 0, restart=no)"))
        elif container.state != "running":
            # No `continue`: an operator whose portal is restarting still needs
            # to know whether it is ALSO stale. The image rows below read the
            # container's recorded image and work regardless of its state.
            checks.append(
                Check(
                    running_label, "fail",
                    f"container {container.name} is {container.state} (exit {container.exit_code})", _UP
                )
            )
        else:
            checks.append(Check(running_label, "ok", container.name))

        checks.append(_check_identity(f"service {service.name}: image identity", container, service, obs))

        revision_label = f"service {service.name}: revision"
        if not service.first_party:
            checks.append(Check(revision_label, "skip", "third-party image, no postern revision"))
        elif not container.revision:
            checks.append(
                Check(
                    revision_label, "fail", "image carries no revision label: it was built without GIT_REVISION", _UP
                )
            )
        elif container.revision != expected_revision:
            checks.append(
                Check(
                    revision_label, "fail",
                    f"running {_short(container.revision)}, checkout is {_short(expected_revision)}", _UP
                )
            )
        else:
            checks.append(Check(revision_label, "ok", _short(container.revision)))

        # Health: point-in-time, not polled. `starting` (right after `up -d`,
        # before the first probe) passes; only `unhealthy` fails. A container
        # with no HEALTHCHECK reports "" and is skipped, not blamed.
        #
        # Gated on state == "running": Docker stops probing on exit and
        # freezes Health.Status at whatever the last probe said, so an exited
        # `restart: "no"` container (the provisioner, exactly the case
        # `completed_one_shot` above exists to not red-flag) can carry a
        # stale "unhealthy" from its last probe before it shut down cleanly,
        # or a stale "healthy" from before it crashed. Neither says anything
        # about a container that is not running right now.
        health_label = f"service {service.name}: health"
        if container.state != "running":
            checks.append(Check(health_label, "skip", "not running; health status is a frozen last-probe value"))
        elif not container.health:
            checks.append(Check(health_label, "skip", "no healthcheck configured"))
        elif container.health == "unhealthy":
            checks.append(
                Check(health_label, "fail", "container reports unhealthy", f"docker compose logs {container.service}")
            )
        else:
            checks.append(Check(health_label, "ok", container.health))

    # Orphans ----------------------------------------------------------------------------------------------------------
    for container in obs.containers:
        if container.service and container.service not in declared:
            # Two causes: the service was deleted from compose.yaml, or it was
            # gated off by COMPOSE_PROFILES (compose config omits those
            # entirely). Whether `--remove-orphans` clears the profile-gated
            # case depends on the compose version, so the hint names the
            # unambiguous fallback too.
            checks.append(
                Check(
                    f"orphan container {container.name}", "fail",
                    f"service {container.service} is not declared in this compose project "
                    "(deleted, or gated off by COMPOSE_PROFILES)",
                    f"docker compose up -d --remove-orphans, or docker rm -f {container.name}"
                )
            )

    # Tunnel image -----------------------------------------------------------------------------------------------------
    # Compose neither builds this image nor owns these containers; the
    # reconciler does. The image check has no race; the per-container checks do.
    ss_revision = obs.tag_revisions.get(obs.ss_image, "")
    ss_label = "shadowsocks image: revision"
    if not obs.tag_ids.get(obs.ss_image):
        checks.append(Check(ss_label, "fail", f"image {obs.ss_image} is not present locally", _ss_build(obs.ss_image)))
    elif not ss_revision:
        checks.append(
            Check(
                ss_label, "fail", "image carries no revision label: it was built without GIT_REVISION",
                _ss_build(obs.ss_image)
            )
        )
    elif ss_revision != expected_revision:
        checks.append(
            Check(
                ss_label, "fail", f"image is {_short(ss_revision)}, checkout is {_short(expected_revision)}",
                _ss_build(obs.ss_image)
            )
        )
    else:
        checks.append(Check(ss_label, "ok", _short(ss_revision)))

    # Tunnel containers ------------------------------------------------------------------------------------------------
    if not tunnels:
        checks.append(
            Check(
                "tunnels: image identity", "skip",
                "not checked; the reconciler recreates tunnels asynchronously after a "
                "portal restart. Run `postern reconcile`, then re-run with --tunnels"
            )
        )
    else:
        checks.extend(_check_tunnel_set(obs, expected_tunnels))
        if not obs.ss_containers:
            if expected_tunnels is None:
                # Without a caller-supplied set this tool cannot tell "no
                # connections are enabled" from "the pass finished without
                # converging" (see the module docstring).
                checks.append(
                    Check(
                        "tunnels: image identity", "skip", "no tunnel containers for this instance -- either no "
                        "connections are enabled, or the reconcile pass this check trusts has not converged yet"
                    )
                )
        else:
            ss_tag_id = obs.tag_ids.get(obs.ss_image, "")
            if not ss_tag_id:
                checks.append(
                    Check(
                        "tunnels: image identity", "fail", f"image {obs.ss_image} is not present locally",
                        _ss_build(obs.ss_image)
                    )
                )
            else:
                # Surplus containers are skipped here: `_check_tunnel_set` has
                # already condemned them as containers that should not exist,
                # and "tunnel X: running ok" underneath that reads as a passing
                # health check for the very thing the report is failing on.
                for tunnel in obs.ss_containers:
                    if expected_tunnels is not None and tunnel.name not in expected_tunnels:
                        continue
                    if tunnel.state != "running":
                        checks.append(Check(f"tunnel {tunnel.name}: running", "fail", f"is {tunnel.state}", _RECONCILE))
                        continue
                    checks.append(Check(f"tunnel {tunnel.name}: running", "ok", tunnel.state))
                    label = f"tunnel {tunnel.name}: image identity"
                    if tunnel.image_id == ss_tag_id:
                        checks.append(Check(label, "ok", f"on {ss_tag_id[:19]}"))
                    else:
                        checks.append(
                            Check(
                                label, "fail",
                                f"tunnel is on {tunnel.image_id[:19]}, {obs.ss_image} is {ss_tag_id[:19]}", _RECONCILE
                            )
                        )

    return Report(project=obs.project, revision=expected_revision, checks=checks)


# Rendering ============================================================================================================
def render_text(report: Report) -> str:
    lines = [f"project:  {report.project}", f"revision: {report.revision}", ""]
    markers: dict[Status, str] = {"ok": "[OK]  ", "fail": "[FAIL]", "skip": "[SKIP]"}
    for check in report.checks:
        lines.append(f"{markers[check.status]} {check.label.ljust(_LABEL_W)} {check.detail}")
        if check.fix:
            lines.append(f"{' ' * 7}{' ' * _LABEL_W} fix: {check.fix}")
    lines.append("")
    failed, total = len(report.failures), len(report.checks)
    lines.append(f"{failed} of {total} checks failed" if failed else f"All {total} checks passed.")
    return "\n".join(lines) + "\n"


def render_json(report: Report) -> str:
    return json.dumps(
        {
            "exit_code": report.exit_code,
            "project": report.project,
            "revision": report.revision,
            "checks": [asdict(c) for c in report.checks],
        },
        indent=2,
    )


# CLI ==================================================================================================================
# The script lives at <repo>/scripts/, so the repo root is one level up. In
# every documented deployment that is also the compose project directory, but
# the two are separate flags because they answer different questions.
REPO_ROOT = Path(__file__).resolve().parents[1]


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="verify-deploy.py",
        description="Assert every running container is on an image built from this checkout.",
    )
    parser.add_argument(
        "--print-revision",
        action="store_true",
        help="Print the revision a build from --repo would carry, and exit. Export this "
        "as GIT_REVISION before building so both halves agree.",
    )
    parser.add_argument("--json", dest="output_json", action="store_true", help="Emit structured JSON")
    parser.add_argument(
        "--project-dir",
        type=Path,
        default=REPO_ROOT,
        help="Compose project directory, holding compose.yaml and .env (default: this checkout)"
    )
    parser.add_argument(
        "--repo",
        type=Path,
        default=REPO_ROOT,
        help="Git checkout the images must have been built from (default: this checkout)"
    )
    parser.add_argument(
        "--expected-revision", default="", help="Revision to require (default: computed from git in --repo)"
    )
    parser.add_argument(
        "--shadowsocks-image",
        default="",
        help="Tunnel image ref (default: the portal's resolved SHADOWSOCKS_IMAGE, then "
        f"{DEFAULT_SS_IMAGE})"
    )
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="Acknowledge that the checkout is dirty and the match proves nothing"
    )
    parser.add_argument(
        "--tunnels",
        action="store_true",
        help="Also check every ss-* container belonging to this deployment. Run "
        "`postern reconcile` first: the reconciler recreates tunnels asynchronously "
        "after a portal restart. Pass --expected-tunnels-from to also assert exactly "
        "which ones should exist."
    )
    parser.add_argument(
        "--expected-tunnels-from",
        # None, not "": an explicitly-supplied empty value (`--expected-tunnels-from
        # ""`, or an unset variable in a wrapper) must NOT be read as "the flag was
        # not passed" -- that would silently downgrade the strictest check the tool
        # has to the weakest, with a green exit code. An empty value falls through to
        # read_expected_tunnels(""), which fails as an unreadable path: exit 2, loudly.
        default=None,
        metavar="FILE",
        help="File listing the ss-* container names this deployment should have, one per "
        "line (`-` reads stdin); `postern connection tunnels` produces it. Requires "
        "--tunnels. Without it, zero tunnels is reported as an honest SKIP, because it "
        "cannot be told apart from a deployment with no connections. Only sound if a "
        "reconcile pass has completed since the last restart -- scripts/deploy.sh "
        "guarantees that with `postern reconcile --wait`."
    )
    return parser.parse_args(list(argv))


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)

    if args.print_revision:
        try:
            print(git_revision(args.repo))
        except RevisionError as exc:
            print(f"verify-deploy: {exc}", file=sys.stderr)
            return 2
        return 0

    if args.expected_tunnels_from is not None and not args.tunnels:
        # 2, not 1 -- a usage error is not a verdict (see the flag's own comment
        # above for why an unset value is never read as "flag not passed").
        print("verify-deploy: --expected-tunnels-from requires --tunnels", file=sys.stderr)
        return 2

    try:
        expected = args.expected_revision or git_revision(args.repo)
    except RevisionError as exc:
        print(f"verify-deploy: {exc}", file=sys.stderr)
        return 2

    def _collect_error_report(check: Check) -> Report:
        # A broken environment is not a stale deployment. Exit 2 so issue #196's
        # deploy entrypoint can tell "verify-deploy is misconfigured" apart from
        # "the deploy did not take".
        return Report(
            project="",
            revision=expected,
            checks=[check],
            exit_code_override=2,  # a CollectError is "could not run", not "stale" -- keep JSON and $? in agreement
        )

    expected_tunnels = None
    if args.expected_tunnels_from is not None:
        try:
            expected_tunnels = read_expected_tunnels(args.expected_tunnels_from)
        except CollectError as exc:
            # Its own Check, not the compose one below: a bad --expected-tunnels-from
            # is not a bad --project-dir, and "run from the deployment's project
            # directory" is not a fix for it.
            print(f"verify-deploy: {exc}", file=sys.stderr)
            report = _collect_error_report(
                Check(
                    "expected tunnels: readable", "fail", str(exc),
                    "check the file/pipe named by --expected-tunnels-from, or the `postern connection tunnels` command that produced it"
                )
            )
            print(render_json(report) if args.output_json else render_text(report), end="")
            return report.exit_code

    try:
        observation = collect(run_command, args.project_dir, args.shadowsocks_image, tunnels=args.tunnels)
    except CollectError as exc:
        print(f"verify-deploy: {exc}", file=sys.stderr)
        report = _collect_error_report(
            Check(
                "compose: readable", "fail", str(exc),
                "run from the deployment's project directory, or pass --project-dir"
            )
        )
        print(render_json(report) if args.output_json else render_text(report), end="")
        return report.exit_code
    report = evaluate(
        observation,
        expected,
        allow_dirty=args.allow_dirty,
        tunnels=args.tunnels,
        expected_tunnels=expected_tunnels,
    )
    print(render_json(report) if args.output_json else render_text(report), end="")
    return report.exit_code


if __name__ == "__main__":
    sys.exit(main())
