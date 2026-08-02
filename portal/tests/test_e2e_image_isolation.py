"""Guard: every image the e2e stack builds or runs is named `local/<name>-test`,
never the unsuffixed production tag (see CLAUDE.md). Every path set below is
derived by glob with a non-empty assert, so a fifth e2e compose file or a new
production service can't silently evade these checks. No Docker required.
"""
from __future__ import annotations

import re
from pathlib import Path

from postern.settings import Settings

from ._compose import load_compose
# The e2e image-name constants live in _helpers.py (it's what _edge_helpers.py,
# test_tunnel.py, and test_mta_real.py actually import for their docker
# run/build calls); import rather than redefine so there is one source of
# truth to check the compose files against, not two that could drift.
from .e2e._helpers import E2E_NGINX_IMAGE, E2E_PROVISIONER_IMAGE, E2E_SHADOWSOCKS_IMAGE

# portal/tests/ -> portal/ -> repo root
REPO_ROOT = Path(__file__).resolve().parent.parent.parent

TEST_SUFFIX = "-test"
E2E_SOURCE_DIR = REPO_ROOT / "portal" / "tests" / "e2e"
CI_DIR = REPO_ROOT / ".github"
DOCS_DIR = REPO_ROOT / "docs"

# Any `local/<name>` reference, boundary-anchored so `/usr/local/bin/...` and
# `sslocal` -- both of which appear for real under portal/tests/e2e/ -- can
# never match.
_LOCAL_REF_RE = re.compile(r"(?<![\w/.-])(local/[\w-]+)")


def _is_e2e_owned(name: str) -> bool:
    return name.endswith(TEST_SUFFIX)


def _scan(paths: list[Path]) -> list[str]:
    """`path:line: names <ref>` for every `local/...` occurrence that is NOT
    e2e-owned (i.e. does not end in `-test`). Every hit, not one per distinct
    ref, so all violations surface in a single run."""
    problems = []
    for path in paths:
        text = path.read_text(encoding="utf-8")
        for match in _LOCAL_REF_RE.finditer(text):
            ref = match.group(1)
            if _is_e2e_owned(ref):
                continue
            line = text.count("\n", 0, match.start()) + 1
            problems.append(f"{path.relative_to(REPO_ROOT)}:{line}: names {ref!r}")
    return problems


def _files_under(root: Path) -> list[Path]:
    files = [p for p in sorted(root.rglob("*")) if p.is_file() and "__pycache__" not in p.parts]
    assert files, f"no files found under {root} -- this scan would pass vacuously"
    return files


def _services(path: Path) -> dict:
    data = load_compose(path)
    rel = path.relative_to(REPO_ROOT)
    assert "services" in data, f"{rel}: no top-level 'services' key"
    services = data["services"]
    assert isinstance(services, dict), f"{rel}: services: is not a mapping"
    return services


# Production image inventory ===========================================================================================
def production_images() -> set[str]:
    """Every image tag the production stack reads.

    Not a ban list -- the guards below ban every unsuffixed `local/` ref by
    construction. This exists as a tripwire: adding a production service
    changes this set and reds `test_production_image_inventory_is_complete`,
    prompting a human to check whether the e2e side needs a matching -test
    image. `local/shadowsocks-server` is in no compose file (the reconciler
    spawns it, taking the name from Settings), so it comes from the Settings
    default.
    """
    images: set[str] = set()
    composes = sorted(REPO_ROOT.glob("compose*.yaml"))
    assert composes, "no production compose files found -- the inventory would be empty"
    for path in composes:
        for name, svc in _services(path).items():
            image = (svc or {}).get("image")
            if isinstance(image, str) and image.startswith("local/"):
                images.add(image)
    default = Settings.model_fields["shadowsocks_image"].default
    assert isinstance(default, str) and default.startswith("local/"), (
        f"Settings.shadowsocks_image default is {default!r}; expected a local/ ref. "
        "If production moved off local/, update this guard deliberately."
    )
    images.add(default)
    return images


def test_production_image_inventory_is_complete():
    """Pins production_images()'s docstring-stated tripwire behavior."""
    assert production_images() == {
        "local/nginx",
        "local/postern-portal",
        "local/postern-mta",
        "local/postern-provisioner",
        "local/shadowsocks-server",
    }, (
        "The set of production image tags changed. Check whether the e2e side needs "
        "a matching -test image, then update this expected set."
    )


# E2e compose files ====================================================================================================
def e2e_compose_files() -> list[Path]:
    files = sorted(E2E_SOURCE_DIR.rglob("*.compose.yaml"))
    assert files, f"no *.compose.yaml under {E2E_SOURCE_DIR} -- these guards would pass vacuously"
    return files


def _e2e_compose_service_images() -> list[tuple[Path, str, str]]:
    """(compose file, service name, image) for every service in an e2e compose
    file that declares a `local/` image."""
    results = []
    for path in e2e_compose_files():
        for name, svc in _services(path).items():
            image = (svc or {}).get("image")
            if isinstance(image, str) and image.startswith("local/"):
                results.append((path, name, image))
    return results


def test_e2e_compose_images_use_test_suffix():
    """Every `local/` image an e2e compose file declares must be -test-suffixed
    -- covers portal, nginx, ssclient, mta, and provisioner across all four
    e2e compose files in one pass."""
    images = _e2e_compose_service_images()
    assert images, "no e2e compose service declares a local/ image -- this guard would pass vacuously"
    problems = [
        f"{path.relative_to(REPO_ROOT)}: service {name!r} declares {image!r}" for path, name, image in images
        if not _is_e2e_owned(image)
    ]
    assert not problems, (
        "E2e compose files must not claim any unsuffixed local/ image tag -- "
        f"append {TEST_SUFFIX} to the image name:\n" + "\n".join(f"  {p}" for p in problems)
    )


def test_e2e_portal_services_point_reconciler_at_e2e_shadowsocks_image():
    """Every e2e compose file that declares a `portal` service must pin
    SHADOWSOCKS_IMAGE in its own `portal.environment` block. `Settings.
    shadowsocks_image` defaults to the production tag, so an unpinned e2e
    portal would create/recreate `ss-*` containers from the production
    image instead of the e2e one."""
    files_with_portal = []
    problems = []
    for path in e2e_compose_files():
        svc = _services(path).get("portal")
        if svc is None:
            continue
        files_with_portal.append(path)
        env = svc.get("environment") or {}
        assert isinstance(env, dict), f"{path.relative_to(REPO_ROOT)}: portal.environment is not a mapping"
        value = env.get("SHADOWSOCKS_IMAGE")
        if value != E2E_SHADOWSOCKS_IMAGE:
            problems.append(f"{path.relative_to(REPO_ROOT)}: portal SHADOWSOCKS_IMAGE is {value!r}")
    assert files_with_portal, "no e2e compose file declares a portal service -- this guard would pass vacuously"
    assert not problems, (
        f"E2e portal services must set SHADOWSOCKS_IMAGE={E2E_SHADOWSOCKS_IMAGE!r}:\n" +
        "\n".join(f"  {p}" for p in problems)
    )


def test_e2e_compose_images_match_helpers_constants():
    """The nginx and provisioner images declared in the compose files must
    match `_helpers.py`'s `E2E_NGINX_IMAGE`/`E2E_PROVISIONER_IMAGE` -- the
    constants `_edge_helpers.py` and `test_mta_real.py` actually build their
    `docker run` calls from. A mismatch would only surface as "no such
    image" at e2e runtime otherwise."""
    expected = {"nginx": E2E_NGINX_IMAGE, "provisioner": E2E_PROVISIONER_IMAGE}
    checked = set()
    problems = []
    for path, name, image in _e2e_compose_service_images():
        if name not in expected:
            continue
        checked.add(name)
        if image != expected[name]:
            problems.append(
                f"{path.relative_to(REPO_ROOT)}: {name} image {image!r} != _helpers.py's {expected[name]!r}"
            )
    assert checked == set(expected), f"expected to find compose images for {set(expected)}, found {checked}"
    assert not problems, "\n".join(problems)


# Literal scan =========================================================================================================
def test_no_e2e_source_names_a_production_image():
    """Every file under portal/tests/e2e/, including compose file comments and
    the non-compose writers the structured guards above can't see: the runtime
    `docker build -t` in test_tunnel.py, the one-off `docker run`s in
    _edge_helpers.py and test_mta_real.py, and docstrings."""
    problems = _scan(_files_under(E2E_SOURCE_DIR))
    assert not problems, (
        "Nothing under portal/tests/e2e/ may name an unsuffixed local/ image -- "
        f"use the local/<name>{TEST_SUFFIX} constants in tests/e2e/_helpers.py:\n" +
        "\n".join(f"  {p}" for p in problems)
    )


def test_no_ci_workflow_names_a_production_image():
    """Whole-text scan of everything under .github/: a `run:` step, a bake
    `set:` override, or a job renamed off the `e2e` prefix would all evade a
    structure-aware check; none evades this one. No file in .github/ has a
    legitimate reason to name an unsuffixed production tag -- production
    images are built by hand on the deployment host, never in CI."""
    problems = _scan(_files_under(CI_DIR))
    assert not problems, (
        "No file under .github/ may name a production image tag:\n" + "\n".join(f"  {p}" for p in problems)
    )


def test_ci_builds_the_expected_test_tags():
    """The two explicit `docker/build-push-action` `tags:` values in
    test.yaml must be exactly the e2e images (not just -test-suffixed --
    equal to what _helpers.py and the reconciler actually expect)."""
    text = (CI_DIR / "workflows" / "test.yaml").read_text(encoding="utf-8")
    for expected in (f"tags: {E2E_SHADOWSOCKS_IMAGE}", f"tags: {E2E_PROVISIONER_IMAGE}"):
        assert expected in text, f".github/workflows/test.yaml missing {expected!r}"


# E2e documentation ====================================================================================================
# Pages that legitimately document PRODUCTION build/deploy commands and so
# correctly keep an unsuffixed local/ ref. An EXEMPT list, not an opt-IN one:
# every other page under docs/ is scanned by default.
_PRODUCTION_DOC_EXEMPTIONS = frozenset({
    DOCS_DIR / "getting-started.md",
    DOCS_DIR / "operations" / "index.md",
    DOCS_DIR / "development" / "architecture.md",
    DOCS_DIR / "deployment" / "configuration.md",
})


def test_e2e_documenting_pages_name_no_production_image():
    """Every doc page except the explicit production-instruction exemptions.
    An unsuffixed `local/` ref on a non-exempt page is an operator
    instruction to reintroduce the collision this module prevents."""
    pages = [p for p in sorted(DOCS_DIR.rglob("*.md")) if p not in _PRODUCTION_DOC_EXEMPTIONS]
    assert pages, f"no non-exempt page found under {DOCS_DIR} -- this scan would pass vacuously"
    problems = _scan(pages)
    assert not problems, (
        "Pages documenting e2e builds must not reference a production image tag:\n" +
        "\n".join(f"  {p}" for p in problems)
    )
