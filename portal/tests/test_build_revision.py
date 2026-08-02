"""Build-provenance gates (issue #195).

Every first-party image carries the git revision it was built from, as the
standard `org.opencontainers.image.revision` OCI label stamped from a
`GIT_REVISION` build arg. `scripts/verify-deploy.py` reads that label back off
the running container's image to prove the deploy actually happened.

The ARG/LABEL pair is last in the final stage so a new revision invalidates
only the final layer.
"""
import subprocess
from pathlib import Path

from ._compose import load_compose

REPO_ROOT = Path(__file__).resolve().parents[2]

# Every image this repo builds and deploys. `portal/tests/` is excluded because
# `ssclient.Dockerfile` is e2e-only and never deployed; `external/` is vendored.
FIRST_PARTY_DOCKERFILES = (
    "portal/Dockerfile",
    "nginx/Dockerfile",
    "mta/Dockerfile",
    "provisioner/Dockerfile",
    "shadowsocks/Dockerfile",
)

ARG_LINE = 'ARG GIT_REVISION=""'
LABEL_LINE = 'LABEL org.opencontainers.image.revision="${GIT_REVISION}"'
ENV_LINE = 'ENV POSTERN_REVISION="${GIT_REVISION}"'


def _lines(rel: str) -> list[str]:
    return (REPO_ROOT / rel).read_text().splitlines()


def _discovered_dockerfiles() -> set[str]:
    """Every deployable Dockerfile, found rather than listed -- so ADDING one
    reds this gate and forces a decision instead of silently escaping it.

    `git ls-files`, not a filesystem walk: this repo's own workflow
    (CLAUDE.local.md) puts full nested checkouts -- each with its own
    portal/Dockerfile, nginx/Dockerfile, etc. -- under the gitignored
    `.tmp/claude/worktrees/`. A `Path.rglob` would find every one of those
    too and red this gate on any machine that follows that workflow.

    Matches the repo's naming convention (CLAUDE.md): a Dockerfile is named
    exactly `Dockerfile` or `<name>.Dockerfile`. `*Dockerfile*` alone would
    also match `portal/Dockerfile.dockerignore`, which is a BuildKit ignore
    file, not a Dockerfile.
    """
    result = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "ls-files", "--", "*Dockerfile*"],
        check=True,
        capture_output=True,
        text=True,
    )
    found = set()
    for rel in result.stdout.splitlines():
        rel = rel.strip()
        if not rel:
            continue
        name = rel.rsplit("/", 1)[-1]
        if not (name == "Dockerfile" or name.endswith(".Dockerfile")):
            continue
        if rel.startswith("external/") or rel.startswith("portal/tests/"):
            continue
        found.add(rel)
    return found


def test_the_first_party_dockerfile_list_is_complete():
    discovered = _discovered_dockerfiles()
    assert discovered, "found no Dockerfiles -- the gates below would pass vacuously"
    assert discovered == set(FIRST_PARTY_DOCKERFILES)


def test_every_first_party_dockerfile_declares_the_revision_arg():
    for rel in FIRST_PARTY_DOCKERFILES:
        assert ARG_LINE in _lines(rel), rel


def test_every_first_party_dockerfile_stamps_the_revision_label():
    for rel in FIRST_PARTY_DOCKERFILES:
        assert LABEL_LINE in _lines(rel), rel


def test_revision_stamp_lands_in_the_final_stage():
    """Guards the cache property: the stamp must come after the last FROM."""
    for rel in FIRST_PARTY_DOCKERFILES:
        lines = _lines(rel)
        last_from = max(i for i, ln in enumerate(lines) if ln.startswith("FROM "))
        assert ARG_LINE in lines and LABEL_LINE in lines, rel
        assert lines.index(ARG_LINE) > last_from, rel
        assert lines.index(LABEL_LINE) > last_from, rel


def test_portal_exports_the_revision_to_the_runtime_env():
    """`postern version` reads POSTERN_REVISION; the distroless runtime has no
    other way to learn it."""
    assert ENV_LINE in _lines("portal/Dockerfile")


def test_compose_forwards_the_revision_to_every_built_service():
    built = {n: s for n, s in load_compose(REPO_ROOT / "compose.yaml")["services"].items() if "build" in s}
    assert set(built) == {"nginx", "portal", "mta", "provisioner"}
    for name, svc in built.items():
        assert svc["build"]["args"]["GIT_REVISION"] == "${GIT_REVISION:-}", name


def test_overlays_declare_no_builds():
    """If an overlay ever adds a `build:` it needs the arg too -- fail here so
    the omission is not silent. Globbed, not listed: a NEW overlay file is
    exactly the omission this is meant to catch.

    Two glob shapes at repo root: the existing overlays are `compose.<name>.yaml`
    (matched by `compose*.yaml`); CLAUDE.md's general Compose-file convention is
    `<name>.compose.yaml` for a supplementary file, which `compose*.yaml` would
    NOT match. Glob both so a future root overlay following either convention
    is covered.
    """
    overlays = sorted((set(REPO_ROOT.glob("compose*.yaml")) | set(REPO_ROOT.glob("*.compose.yaml"))) -
                      {REPO_ROOT / "compose.yaml"})
    assert overlays, "found no compose overlays -- this gate would pass vacuously"
    for path in overlays:
        for name, svc in (load_compose(path).get("services") or {}).items():
            assert "build" not in svc, f"{path.name}:{name} builds but does not forward GIT_REVISION"
