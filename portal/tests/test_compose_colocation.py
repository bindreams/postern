"""Regression tests for issue #198: an e2e compose stack must not claim any
host-namespace resource (a subnet, a host port, a named volume, a
container_name) that a co-located production Postern stack already claims --
except the one deliberate, allowlisted exception at _HOST_PORT_ALLOWLIST below.

A host can run production and an e2e stack at once (the maintainer's VPS is
exactly that host). The two host-port/subnet failure modes are not
symmetric: Docker's overlapping-subnet refusal only triggers against a
network that is already up, so it's ordering-dependent and can strand a
stack silently (see CLAUDE.md's default-address-pools note) -- pinned here
unconditionally, no exceptions. The kernel's double-bind refusal on a host
port is immediate and loud regardless of order, which is why exactly one
port collision is allowed to stand (see _HOST_PORT_ALLOWLIST's reason for
what "loud" means for that one entry, including which side actually fails).
These guards are glob-derived (`compose*.yaml` + `portal/tests/e2e/*.compose.yaml`),
so a new overlay or a new production compose file is covered automatically.
No Docker required.
"""
from __future__ import annotations

import ipaddress
import itertools
import re
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from ._compose import load_compose, production_mta_submit_subnet

# tests/ -> portal/ -> repo root
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SUBMIT_ALIAS = "mta-submit"

# Same glob-derived construction as test_e2e_image_isolation.py.
E2E_COMPOSE_DIR = REPO_ROOT / "portal" / "tests" / "e2e"


def _rel(path: Path) -> str:
    return str(path.relative_to(REPO_ROOT))


def PRODUCTION_COMPOSE_FILES() -> list[Path]:
    # Two glob shapes at repo root, same as test_build_revision.py's
    # test_overlays_declare_no_builds: the existing overlays match `compose*.yaml`,
    # but CLAUDE.md's general convention for a supplementary file is
    # `<name>.compose.yaml`, which `compose*.yaml` would NOT match.
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


def test_production_mta_submit_subnet_is_the_documented_literal():
    """Production's /29 is mta/entrypoint.py's MTA_SUBMIT_CIDR fallback, so
    moving it is a cross-repo change, not an edit. (CLAUDE.md's and testing.md's
    own prose copies of this literal are checked separately, in
    test_docs_quote_the_current_e2e_mta_submit_subnets_and_port.)

    Deliberately overlaps test_pinned_subnet_inventory_is_complete, which would
    also red on a change here: that one says "a pinned subnet moved, go look",
    this one names the one out-of-repo-tree place that has to move with it.
    The subnet <-> CIDR <-> mynetworks agreement is checked for this file and
    every overlay by test_every_compose_file_agrees_on_its_own_mynetworks_chain.
    """
    subnet = production_mta_submit_subnet()
    assert subnet == "172.30.42.0/29", f"unexpected production mta-submit subnet {subnet!r}"


# Submission chain (subnet <-> MTA_SUBMIT_CIDR <-> mynetworks) =========================================================
# Overlays that deliberately inherit half the submission config from a base file
# (a `mta-submit` network with no MTA_SUBMIT_CIDR, or the reverse). EXEMPT list,
# not an opt-in one: every other compose file must carry both halves, because
# load_compose does no Compose merge and a standalone file missing either half
# silently falls back to mta/entrypoint.py's default CIDR and breaks submission.
_PARTIAL_SUBMISSION_OVERLAYS: frozenset[Path] = frozenset()


def _service_environment(path: Path, service: str) -> dict[str, str | None]:
    """A service's `environment` as a dict, accepting both Compose forms.

    The mapping form is what this repo uses; the `- KEY=VALUE` list form is
    equally valid Compose and would otherwise crash every glob-derived guard in
    this module with an AttributeError the moment a new file used it. A bare
    `- KEY` entry (no `=`) is legal Compose too -- it passes the host's own
    environment value through -- and maps to None rather than raising, since
    "value comes from the host" is not "malformed file".
    """
    env = ((load_compose(path).get("services") or {}).get(service) or {}).get("environment")
    if env is None:
        return {}
    if isinstance(env, dict):
        return {str(k): (None if v is None else str(v)) for k, v in env.items()}
    assert isinstance(env, list), f"{_rel(path)}: service {service!r} environment is {type(env).__name__}"
    out: dict[str, str | None] = {}
    for item in env:
        key, sep, value = str(item).partition("=")
        out[key] = value if sep else None
    return out


# Compose coerces a YAML-*quoted* boolean through the same legacy spellings
# it accepts unquoted -- confirmed via `docker compose config`: `internal:
# "false"`/`"no"`/`"off"` (and the bare-bool half of `external:`) all resolve
# to false, `"true"` to true, with a deprecation warning for the legacy
# spellings. ComposeLoader deliberately leaves PyYAML's bool resolver
# un-narrowed (see _compose.py), so an UNQUOTED legacy spelling already
# reaches Python as `bool`; only a quoted one reaches here as `str` and needs
# this set to get the same reading Compose does. Shared by every schema-typed
# boolean field this module reads (`internal:` here, `external:`'s bare-bool
# form in _external_spec below) so the two can't drift out of step.
_LEGACY_BOOL_TRUE = frozenset({"true", "yes", "y", "on", "1"})
_LEGACY_BOOL_FALSE = frozenset({"false", "no", "n", "off", "0"})


def _as_compose_bool(value: object) -> bool | None:
    """Normalize a YAML-loaded scalar to the bool Compose itself would read
    it as, for a schema-typed boolean field. A `bool` (or `None`, meaning
    "absent") passes through unchanged. A `str` is resolved via
    `_LEGACY_BOOL_TRUE`/`_LEGACY_BOOL_FALSE` -- or rejected loudly if it's
    neither, since a string that reaches a boolean field but matches no
    recognized spelling is a malformed compose file, not a value to silently
    ignore. Any other type (a mapping, a list, ...) returns `None`: not a
    bool this function can produce, but also not this function's job to
    validate -- a caller with its own alternate shape for that type (e.g.
    `external:`'s mapping form) checks for it before calling this.
    """
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, str):
        lowered = value.lower()
        if lowered in _LEGACY_BOOL_TRUE:
            return True
        if lowered in _LEGACY_BOOL_FALSE:
            return False
        raise AssertionError(f"{value!r} is not a recognized Compose boolean spelling")
    return None


def _pinned_subnet_of(net: dict | None, *, where: str) -> str | None:
    """The single IPAM-pinned subnet of a network block, or None if it pins none.

    Tolerates every partial shape (`ipam:` absent, `config:` empty) rather than
    raising KeyError/IndexError -- an overlay that re-opens a network only to
    set `internal: true` is legal Compose, not a configuration error. Asserts
    at most one `config:` entry pins a subnet: `mynetworks` and opendkim's
    TrustedHosts are rendered from a single MTA_SUBMIT_CIDR value, so a second,
    silently-ignored subnet would leave part of the network outside both.
    """
    subnets = [
        entry["subnet"] for entry in (((net or {}).get("ipam") or {}).get("config") or [])
        if (entry or {}).get("subnet") is not None
    ]
    assert len(subnets) <= 1, f"{where}: {SUBMIT_ALIAS} network pins multiple subnets {subnets!r}, expected at most 1"
    return subnets[0] if subnets else None


def test_every_compose_file_agrees_on_its_own_mynetworks_chain():
    """The production file is not the only one that has to keep the chain
    intact -- each overlay renders its own main.cf. `mynetworks` AND opendkim's
    TrustedHosts are both rendered from MTA_SUBMIT_CIDR (mta/entrypoint.py), so
    a subnet that drifts from the CIDR either rejects submission with 554 5.7.1
    or lets mail leave unsigned. Checking the two fields *within* each file is
    what lets the overlays hold different values from production without anyone
    re-coupling them by hand.
    """
    checked = []
    for path in ALL_COMPOSE_FILES():
        rel = _check_submission_chain(path, exempt=_PARTIAL_SUBMISSION_OVERLAYS)
        if rel is not None:
            checked.append(rel)
    assert set(checked) == {
        "compose.yaml",
        "portal/tests/e2e/e2e-mta.compose.yaml",
        "portal/tests/e2e/e2e-mta-real.compose.yaml",
    }, f"unexpected set of submission-configuring compose files: {checked!r}"


def _check_submission_chain(path: Path, *, exempt: frozenset[Path]) -> str | None:
    """The per-file assertion body of test_every_compose_file_agrees_on_its_own_
    mynetworks_chain, split out so the `exempt` exemption path can be exercised
    with a synthetic path/exempt-set pair, not only the repo's real files.

    Returns the file's rel path if it participates in the chain (subnet AND
    cidr both present and checked), None if it has neither or is exempt.
    """
    rel = _rel(path)
    net = (load_compose(path).get("networks") or {}).get(SUBMIT_ALIAS)
    cidr = _service_environment(path, "mta").get("MTA_SUBMIT_CIDR")
    subnet = _pinned_subnet_of(net, where=rel)

    # Checked whenever the file declares the network at all, independent of
    # whether it also pins a subnet/CIDR (see the two tests below for why).
    if net is not None:
        internal = _as_compose_bool(net.get("internal"))
        if path not in exempt:
            assert internal is True, f"{rel}: {SUBMIT_ALIAS} network must be internal: true"
        else:
            assert internal is not False, (
                f"{rel}: {SUBMIT_ALIAS} network explicitly sets internal: false while exempt from the "
                f"subnet/CIDR agreement check -- an exempt file may omit internal (inheriting the base's "
                f"internal: true) but must never override it to false"
            )

    if subnet is None and cidr is None:
        return None
    if path in exempt:
        return None
    assert subnet is not None, (
        f"{rel}: sets MTA_SUBMIT_CIDR but pins no {SUBMIT_ALIAS} subnet. Docker would allocate the "
        f"network dynamically, outside mynetworks. If this file inherits the network from a base "
        f"file, add it to _PARTIAL_SUBMISSION_OVERLAYS."
    )
    assert cidr is not None, (
        f"{rel}: pins a {SUBMIT_ALIAS} subnet but sets no MTA_SUBMIT_CIDR, so mta falls back to "
        f"entrypoint.py's default and mynetworks won't match. If this file inherits the env from a "
        f"base file, add it to _PARTIAL_SUBMISSION_OVERLAYS."
    )
    assert cidr == subnet, (
        f"{rel}: MTA_SUBMIT_CIDR ({cidr!r}) != {SUBMIT_ALIAS} subnet ({subnet!r}). "
        "mynetworks and opendkim TrustedHosts are both rendered from MTA_SUBMIT_CIDR, "
        "so a mismatch silently breaks submission or DKIM signing."
    )
    return rel


def test_submission_chain_checks_internal_flag_even_without_a_pinned_subnet(monkeypatch):
    """A file that re-opens `mta-submit` to (say) accidentally drop `internal:
    true`, without itself pinning a subnet or MTA_SUBMIT_CIDR, must still fail
    -- the unauthenticated-relay hazard doesn't depend on the same file also
    owning the IPAM config. Synthetic: no real compose file does this today."""
    fake_path = REPO_ROOT / "portal" / "tests" / "e2e" / "_fake-internal-false-overlay.compose.yaml"
    fake_compose = {"networks": {SUBMIT_ALIAS: {"internal": False}}}
    monkeypatch.setattr(
        sys.modules[__name__],
        "load_compose",
        lambda path, _real=load_compose: fake_compose if path == fake_path else _real(path),
    )
    with pytest.raises(AssertionError, match="must be internal: true"):
        _check_submission_chain(fake_path, exempt=frozenset())


def test_submission_chain_normalizes_a_quoted_internal_boolean(monkeypatch):
    """A YAML-quoted `internal: "false"` reaches Python as the truthy string
    "false", not the bool False -- `is True`/`is not False` compares that
    never actually see would silently pass a network Compose itself reads as
    NOT internal. Routed through the same _as_compose_bool that normalizes
    `external:`'s quoted spellings, so both fields agree with Compose. Also
    checks the reverse: a quoted "true" must not fail the non-exempt branch."""
    fake_path = REPO_ROOT / "portal" / "tests" / "e2e" / "_fake-quoted-internal-false.compose.yaml"
    fake_compose = {"networks": {SUBMIT_ALIAS: {"internal": "false"}}}
    monkeypatch.setattr(
        sys.modules[__name__],
        "load_compose",
        lambda path, _real=load_compose: fake_compose if path == fake_path else _real(path),
    )
    with pytest.raises(AssertionError, match="must be internal: true"):
        _check_submission_chain(fake_path, exempt=frozenset())

    fake_compose["networks"][SUBMIT_ALIAS]["internal"] = "true"
    # No AssertionError: a quoted "true" is internal, same as the bool True.
    _check_submission_chain(fake_path, exempt=frozenset())


def test_submission_chain_exempt_overlay_may_not_set_internal_false(monkeypatch):
    """An exempt overlay (missing half of the subnet/CIDR pair) may legitimately
    omit `internal:` and inherit the base file's `internal: true` -- but if it
    actively sets `internal: false`, that must still fail. The exemption's
    purpose is narrowly "can't check subnet<->CIDR agreement in isolation",
    not "every check on this file is suspended"."""
    fake_path = REPO_ROOT / "portal" / "tests" / "e2e" / "_fake-exempt-internal-false.compose.yaml"
    fake_compose = {"networks": {SUBMIT_ALIAS: {"internal": False}}}
    monkeypatch.setattr(
        sys.modules[__name__],
        "load_compose",
        lambda path, _real=load_compose: fake_compose if path == fake_path else _real(path),
    )
    with pytest.raises(AssertionError, match="must never override it to false"):
        _check_submission_chain(fake_path, exempt=frozenset({fake_path}))


def test_partial_submission_overlay_exemption_skips_files_that_would_otherwise_fail(monkeypatch):
    """`_PARTIAL_SUBMISSION_OVERLAYS` has no current member (every real compose
    file today carries both halves), so the exemption branch it guards has no
    coverage from the real files. Exercised here with synthetic compose data
    -- a subnet pinned with no MTA_SUBMIT_CIDR, which fails the chain check on
    its own -- to prove the exemption actually suppresses that failure rather
    than happening to no-op."""
    fake_path = REPO_ROOT / "portal" / "tests" / "e2e" / "_fake-partial-overlay.compose.yaml"
    fake_compose = {"networks": {SUBMIT_ALIAS: {"internal": True, "ipam": {"config": [{"subnet": "10.0.0.0/29"}]}}}}
    monkeypatch.setattr(
        sys.modules[__name__],
        "load_compose",
        lambda path, _real=load_compose: fake_compose if path == fake_path else _real(path),
    )
    # Not exempt: the synthetic data really does fail the chain check.
    with pytest.raises(AssertionError, match="pins a mta-submit subnet but sets no MTA_SUBMIT_CIDR"):
        _check_submission_chain(fake_path, exempt=frozenset())
    # Exempt: the same failing data is skipped cleanly instead of raising.
    assert _check_submission_chain(fake_path, exempt=frozenset({fake_path})) is None


# Subnet inventory and disjointness ====================================================================================
def _pinned_subnets(path: Path) -> list[tuple[str, str | None, ipaddress.IPv4Network | ipaddress.IPv6Network]]:
    """(network key, EXPLICIT Docker network name or None, subnet) for every
    IPAM subnet a compose file pins.

    The name is deliberately None when the file declares no `name:` -- Compose
    then derives the runtime name from the project (`<project>_<key>`), so two
    unnamed declarations in two projects are two different networks that must
    not overlap. Defaulting the name to the compose key would make them look
    like one network and skip exactly the check this module exists for.
    """
    found = []
    for key, cfg in (load_compose(path).get("networks") or {}).items():
        cfg = cfg or {}
        for entry in ((cfg.get("ipam") or {}).get("config") or []):
            subnet = (entry or {}).get("subnet")
            if subnet is None:
                continue
            try:
                parsed = ipaddress.ip_network(subnet)
            except ValueError as e:
                raise AssertionError(f"{_rel(path)}: network {key!r} has malformed subnet {subnet!r}: {e}") from e
            found.append((key, cfg.get("name"), parsed))
    return found


def test_pinned_subnet_inventory_is_complete():
    """Tripwire, not a ban list: pinning a new subnet changes this set and reds
    this test, prompting a human to check it against everything else on the
    host. The disjointness guard below does the actual enforcement."""
    inventory = {(_rel(p), key, str(net)) for p in ALL_COMPOSE_FILES() for key, _, net in _pinned_subnets(p)}
    assert inventory == {
        ("compose.yaml", "mta-submit", "172.30.42.0/29"),
        ("portal/tests/e2e/e2e-mta.compose.yaml", "default", "10.234.45.0/24"),
        ("portal/tests/e2e/e2e-mta.compose.yaml", "mta-submit", "10.234.43.0/29"),
        ("portal/tests/e2e/e2e-mta-real.compose.yaml", "default", "10.234.46.0/24"),
        ("portal/tests/e2e/e2e-mta-real.compose.yaml", "mta-submit", "10.234.44.0/29"),
    }, f"the set of IPAM-pinned subnets changed: {sorted(inventory)!r}"


def test_unpinned_e2e_networks_are_exactly_the_documented_residual():
    """Every network any e2e compose file declares with NO ipam pin is
    outside every subnet guard above -- dynamically allocated from Docker's
    default pool, the residual gap CLAUDE.md's co-location bullet names
    explicitly (not something this issue's scope closes; most of these
    networks are declared by the shared base e2e.compose.yaml and
    e2e-edge.compose.yaml, used suite-wide and owned outside this issue).
    Tripwire, not enforcement: a NEW unpinned e2e network changes this set
    and reds the test, forcing a human to decide whether it needs a pin or
    just a doc update -- the one thing nothing else in this module catches.
    """
    unpinned = set()
    for path in E2E_COMPOSE_FILES():
        pinned_keys = {key for key, _, _ in _pinned_subnets(path)}
        for key in (load_compose(path).get("networks") or {}):
            if key not in pinned_keys:
                unpinned.add((_rel(path), key))
    assert unpinned == {
        ("portal/tests/e2e/e2e.compose.yaml", "default"),
        ("portal/tests/e2e/e2e.compose.yaml", "e2e-tunnel-entry"),
        ("portal/tests/e2e/e2e.compose.yaml", "e2e-shadowsocks"),
        ("portal/tests/e2e/e2e-edge.compose.yaml", "default"),
        ("portal/tests/e2e/e2e-edge.compose.yaml", "e2e-shadowsocks-edge"),
        ("portal/tests/e2e/e2e-mta.compose.yaml", "e2e-tunnel-entry"),
        ("portal/tests/e2e/e2e-mta.compose.yaml", "e2e-shadowsocks"),
        ("portal/tests/e2e/e2e-mta-real.compose.yaml", "e2e-tunnel-entry"),
        ("portal/tests/e2e/e2e-mta-real.compose.yaml", "e2e-shadowsocks"),
    }, f"the set of unpinned e2e networks changed: {sorted(unpinned)!r} -- update CLAUDE.md's residual-gap note"


_SubnetEntry = tuple[Path, str, "str | None", "ipaddress.IPv4Network | ipaddress.IPv6Network"]

# A default-form interpolation (${VAR:-default} or ${VAR-default}), matched
# anywhere in the string (not anchored) so _resolved_name can substitute more
# than one occurrence, e.g. a concatenated `${A:-x}${B:-y}` or a name with a
# literal prefix/suffix like `prefix-${V:-a}`. Deliberately excludes the
# required-value forms (${VAR:?msg}, ${VAR?msg}) and the bare ${VAR} form --
# neither has a value this module can predict without an env. The default
# group excludes `$`, `{`, and `}` on purpose, so a nested interpolation
# (`${A:-${B:-x}}`) can't be swallowed by one match's default group --
# _resolved_name re-scans to a fixed point instead, so the innermost
# interpolation resolves first (`${A:-${B:-x}}` -> `${A:-x}` -> `x`, matching
# Compose's own resolution of a nested default) rather than the whole
# expression being misread as unresolvable after a single pass.
_INTERPOLATED_DEFAULT_RE = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*:?-(?P<default>[^${}]*)\}")

# The alternate-value form (${VAR:+alt} or ${VAR+alt}): with VAR unset (the
# only environment this module predicts), Compose resolves this to the empty
# string regardless of what `alt` is -- `alt` only applies when VAR IS set.
# Verified with `docker compose config`: `shadowsocks${SUF:+-test}` with SUF
# unset renders `shadowsocks`. The alt text itself is discarded outright
# (not captured), since it plays no part in the all-unset resolution.
_INTERPOLATED_ALT_RE = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*:?\+[^${}]*\}")

# A placeholder no legal Compose name/interpolation can ever contain, swapped
# in for a `$$`-escaped literal dollar BEFORE interpolation-scanning begins
# (not after) -- so an escaped `$` immediately followed by a genuine `${...}`
# (e.g. `$${V:-x}`, which Compose reads as a literal "$" then the untouched
# literal text "{V:-x}") can never be misread as the `$` that opens that
# interpolation. Swapped back to a single literal `$` only once nothing `$`
# remains to interpolate.
_ESCAPED_DOLLAR_PLACEHOLDER = "\0"


def _resolved_name(name: str | None) -> str | None:
    """The literal Docker resource name a compose `name:` (or `container_name:`)
    field resolves to when every interpolation in it is left at its documented
    default -- e.g. `${SHADOWSOCKS_NETWORK:-shadowsocks}` resolves to
    `"shadowsocks"`, `prefix-${V:-a}` resolves to `"prefix-a"`, a nested
    `${A:-${B:-x}}` resolves to `"x"`, and `shadowsocks${SUF:+-test}` resolves
    to `"shadowsocks"` (SUF unset, so the alternate value never applies).

    A plain literal (no unescaped `$`) resolves to itself, with any `$$`
    escape collapsed to a literal `$` (Compose's own escaping rule). `None`,
    and any string where an unescaped `$` remains after resolving every
    `_INTERPOLATED_DEFAULT_RE`/`_INTERPOLATED_ALT_RE` match to a fixed point,
    resolve to `None` -- unresolvable, so must never be treated as equal to
    anything. That covers a bare `${VAR}` or `${VAR:?msg}` (neither matches
    either regex) and Compose's brace-less `$VAR` form (interpolation too,
    identical in meaning to `${VAR}`, with no default syntax of its own) --
    gating the literal fast path on `"${" not in name` would treat `$VAR` as
    the four-character literal string "$VAR" instead of recognizing it needs
    resolving.
    """
    if name is None:
        return None
    protected = name.replace("$$", _ESCAPED_DOLLAR_PLACEHOLDER)
    if "$" not in protected:
        return protected.replace(_ESCAPED_DOLLAR_PLACEHOLDER, "$")
    resolved = protected
    while True:
        # Each pass only ever shrinks or holds the string's length (neither
        # regex's substitution can reintroduce `$`, `{`, or `}`), so this
        # terminates without an iteration cap once no match changes anything.
        substituted = _INTERPOLATED_DEFAULT_RE.sub(lambda m: m.group("default"), resolved)
        substituted = _INTERPOLATED_ALT_RE.sub("", substituted)
        if substituted == resolved:
            break
        resolved = substituted
    return None if "$" in resolved else resolved.replace(_ESCAPED_DOLLAR_PLACEHOLDER, "$")


def _compose_family(path: Path) -> str:
    """"e2e" or "production", by directory. Scopes the "two files share one
    Docker network name" exemption in _find_subnet_overlaps to same-family
    pairs: a base file and its own overlay sharing a name is a normal Compose
    pattern, but a production file and an e2e file sharing a name is not a
    base/overlay relationship -- it is two different compose projects
    attaching to the exact same Docker network."""
    return "e2e" if path.is_relative_to(E2E_COMPOSE_DIR) else "production"


def _find_subnet_overlaps(entries: list[_SubnetEntry]) -> list[str]:
    """Problem strings for every pair of pinned-subnet entries that collide.

    Split out from the test so the "two files share one named Docker network"
    reconciliation branch (same name -> same subnet required, not a collision)
    can be exercised with synthetic entries, not only whatever the repo's real
    compose files happen to contain today.
    """
    problems = []
    for (pa, ka, na, sa), (pb, kb, nb, sb) in itertools.combinations(entries, 2):
        if (pa, ka) == (pb, kb):
            # Two `ipam.config` entries under the SAME file+network-key are
            # one network's own multi-pool list (e.g. two IPv4 CIDRs, valid
            # Compose/Docker), not two declarations to reconcile against each
            # other -- neither the same-name nor the overlap check applies.
            continue
        shown_a = f"{_rel(pa)} {ka} ({na or '<project-derived>'}) {sa}"
        shown_b = f"{_rel(pb)} {kb} ({nb or '<project-derived>'}) {sb}"
        # Two DIFFERENT purposes need two DIFFERENT notions of "same name",
        # not one shared boolean:
        #
        # - Flagging a cross-family pair (below) wants the INCLUSIVE
        #   resolved-name compare: production's `${SHADOWSOCKS_NETWORK:-
        #   shadowsocks}` against an e2e file spelling the resolved default
        #   `shadowsocks` literally is worth a red flag even though the two
        #   raw expressions differ -- a false positive here just prompts a
        #   human to look, while a false negative hides a live-network join.
        # - Suppressing the overlap check for a same-family pair (further
        #   below) is narrower, but not as narrow as raw-text identity: the
        #   same raw expression twice is provable regardless of whether it
        #   resolves to a literal (same env var, same compose invocation,
        #   so it resolves identically for every service). A literal on one
        #   side against an interpolation whose OWN default equals that
        #   literal (`foo` vs `${X:-foo}`) is provable too, at the
        #   documented default. Two DIFFERENT expressions that merely share
        #   a default (`${NET_A:-shared}` vs `${NET_B:-shared}`) are NOT --
        #   an operator can set one and leave the other, silently landing
        #   two DIFFERENT Docker networks on one subnet, so that pair falls
        #   through to the plain overlap check below instead of being
        #   exempted from it.
        ra, rb = _resolved_name(na), _resolved_name(nb)
        same_resolved_name = ra is not None and ra == rb
        # Raw-text identity is stronger evidence than a resolved match, not
        # weaker: two files reading the SAME (possibly unresolvable-to-this-
        # tool) expression share one env var in one compose invocation, so
        # whatever it resolves to, both land on the same runtime name --
        # unlike a resolved match, this holds even for two files that both
        # spell an unresolvable form (a bare `${VAR}`, no default).
        raw_identical = na is not None and na == nb
        literal_a = na is not None and ra == na
        literal_b = nb is not None and rb == nb
        provably_same_network = raw_identical or (same_resolved_name and (literal_a or literal_b))

        if (same_resolved_name or raw_identical) and _compose_family(pa) != _compose_family(pb):
            # Same resolved (or raw-identical) name across the production/e2e
            # boundary: not a legitimate base/overlay pair, but two different
            # compose projects attaching to the identical Docker network --
            # the e2e container joins production's network directly,
            # bypassing the whole point of pinning separate subnets.
            # Independent of address family: checked before the IP-version
            # skip below, since joining production's network doesn't require
            # the pinned subnets to match version or value. Checked before
            # `provably_same_network` too, so a cross-family raw-identical
            # pair reports as a collision rather than being silently
            # reconciled by the same logic that's correct for a same-family
            # base+overlay pair.
            problems.append(f"{shown_a} and {shown_b} declare the same Docker network name across production/e2e")
            continue

        if sa.version != sb.version:
            # A dual-stack network (enable_ipv6: true) legitimately pins one
            # IPv4 and one IPv6 config entry under the same name -- that is
            # not two conflicting subnets on one network, and the two
            # families can never overlap on the wire either way.
            continue

        if provably_same_network:
            # One Docker network declared by two files in the same family (a
            # base and its overlay), the same expression/literal both times.
            # Not a collision -- but the two must then pin the SAME subnet,
            # or whichever project creates the network first silently wins.
            if sa != sb:
                problems.append(f"{shown_a} and {shown_b} are the same Docker network with different subnets")
            continue

        if sa.overlaps(sb):
            problems.append(f"{shown_a} overlaps {shown_b}")
    return problems


def test_pinned_subnets_are_pairwise_disjoint():
    """Docker refuses to create a network overlapping an existing one, so two
    stacks pinning the same range cannot both be up. Compared as networks, not
    strings: a 172.30.42.0/24 that *contains* production's /29 is just as fatal
    as an exact duplicate and a string compare would miss it.

    Only sees IPAM-*pinned* subnets. A dynamically allocated network can still
    land on top of one of these; that is a daemon-level concern (see the
    default-address-pools note in CLAUDE.md), not something this can check.
    """
    prod_entries = [(p, key, name, net) for p in PRODUCTION_COMPOSE_FILES() for key, name, net in _pinned_subnets(p)]
    e2e_entries = [(p, key, name, net) for p in E2E_COMPOSE_FILES() for key, name, net in _pinned_subnets(p)]
    # Asserted separately: this guard's whole point is catching a
    # cross-family collision, so a combined `len(entries) >= 2` is satisfied
    # by two production (or two e2e) entries alone -- exercising only the
    # same-family branch and leaving the cross-family one unproven non-vacuous.
    assert prod_entries, "no production compose file pins a subnet -- this guard would pass vacuously"
    assert e2e_entries, "no e2e compose file pins a subnet -- this guard would pass vacuously"
    problems = _find_subnet_overlaps(prod_entries + e2e_entries)
    assert not problems, (
        "Compose files must not pin overlapping subnets -- a production stack and an e2e "
        "stack share one Docker daemon and one address space:\n" + "\n".join(f"  {p}" for p in problems)
    )


def test_find_subnet_overlaps_allows_a_shared_named_network_with_matching_subnets():
    """A base file and its overlay legitimately declare the same explicit
    network `name:` with the same subnet (e.g. a base + an overlay that only
    adds `internal: true`) -- not a collision, since it's one Docker network,
    not two. No real compose file in this repo shares a name this way today."""
    a = REPO_ROOT / "a.compose.yaml"
    b = REPO_ROOT / "b.compose.yaml"
    net = ipaddress.ip_network("10.99.0.0/29")
    entries: list[_SubnetEntry] = [(a, "mta-submit", "shared-net", net), (b, "mta-submit", "shared-net", net)]
    assert _find_subnet_overlaps(entries) == []


def test_find_subnet_overlaps_flags_a_shared_named_network_with_mismatched_subnets():
    """Same explicit network `name:` in two files but different subnets: not a
    Docker-level collision (Compose treats it as one network either way), but
    whichever project's `up` runs first silently decides the real subnet for
    both -- flagged so it isn't mistaken for the "same network, safe" case."""
    a = REPO_ROOT / "a.compose.yaml"
    b = REPO_ROOT / "b.compose.yaml"
    entries: list[_SubnetEntry] = [
        (a, "mta-submit", "shared-net", ipaddress.ip_network("10.99.0.0/29")),
        (b, "mta-submit", "shared-net", ipaddress.ip_network("10.99.0.8/29")),
    ]
    problems = _find_subnet_overlaps(entries)
    assert len(problems) == 1
    assert "same Docker network with different subnets" in problems[0]


def test_find_subnet_overlaps_flags_a_shared_name_across_production_and_e2e():
    """A production file and an e2e file sharing an explicit network name is
    not the legitimate base/overlay pattern (that only happens within one
    family) -- it means the e2e stack's container joins production's network
    directly, which is exactly what pinning separate subnets exists to
    prevent. Same subnet on both sides doesn't make this safe."""
    prod = REPO_ROOT / "compose.yaml"
    e2e = E2E_COMPOSE_DIR / "e2e-mta.compose.yaml"
    net = ipaddress.ip_network("10.99.0.0/29")
    entries: list[_SubnetEntry] = [
        (prod, "mta-submit", "shared-net", net),
        (e2e, "mta-submit", "shared-net", net),
    ]
    problems = _find_subnet_overlaps(entries)
    assert len(problems) == 1
    assert "same Docker network name across production/e2e" in problems[0]


def test_find_subnet_overlaps_flags_a_shared_name_across_families_even_with_different_ip_versions():
    """The cross-family same-name violation doesn't depend on the two pinned
    subnets sharing an address family -- e.g. production pins only IPv4 on a
    network while an e2e overlay pins only IPv6 on a network of the same
    name. The IP-version skip (for legitimate dual-stack networks) must not
    swallow this before the cross-family name check runs."""
    prod = REPO_ROOT / "compose.yaml"
    e2e = E2E_COMPOSE_DIR / "e2e-mta.compose.yaml"
    entries: list[_SubnetEntry] = [
        (prod, "mta-submit", "shared-net", ipaddress.ip_network("10.99.0.0/29")),
        (e2e, "mta-submit", "shared-net", ipaddress.ip_network("fd00:dead:beef::/64")),
    ]
    problems = _find_subnet_overlaps(entries)
    assert len(problems) == 1
    assert "same Docker network name across production/e2e" in problems[0]


def test_find_subnet_overlaps_treats_matching_interpolated_defaults_as_the_same_network():
    """Two same-family files spelling the identical `${VAR:-default}`
    expression, pinning the SAME subnet: resolved to the same literal name
    (see _resolved_name), so this is the legitimate one-network-pinned-twice
    base+overlay pattern, not a collision."""
    a = REPO_ROOT / "a.compose.yaml"
    b = REPO_ROOT / "b.compose.yaml"
    entries: list[_SubnetEntry] = [
        (a, "shadowsocks", "${SHADOWSOCKS_NETWORK:-shadowsocks}", ipaddress.ip_network("10.99.0.0/29")),
        (b, "shadowsocks", "${SHADOWSOCKS_NETWORK:-shadowsocks}", ipaddress.ip_network("10.99.0.0/29")),
    ]
    assert _find_subnet_overlaps(entries) == []


def test_find_subnet_overlaps_flags_mismatched_subnets_under_the_same_interpolated_default():
    """Same-family files resolving to the SAME network name but pinning
    DIFFERENT subnets: whichever project's `up` runs first silently decides
    the real subnet for both -- the same hazard
    test_find_subnet_overlaps_flags_a_shared_named_network_with_mismatched_subnets
    covers for a literal name, only reachable here once the interpolation is
    resolved before the name compare."""
    a = REPO_ROOT / "compose.yaml"
    b = REPO_ROOT / "compose.edge.yaml"
    entries: list[_SubnetEntry] = [
        (a, "n", "${NET:-x}", ipaddress.ip_network("10.99.0.0/29")),
        (b, "n", "${NET:-x}", ipaddress.ip_network("10.99.1.0/29")),
    ]
    problems = _find_subnet_overlaps(entries)
    assert len(problems) == 1
    assert "same Docker network with different subnets" in problems[0]


def test_find_subnet_overlaps_flags_same_family_different_expressions_sharing_a_default():
    """Two DIFFERENT interpolation expressions that merely share a default
    (${NET_A:-shared} vs ${NET_B:-shared}) are NOT provably one network, even
    same-family and even pinning the identical subnet -- only the all-unset
    environment makes them equal, and an operator could set one while leaving
    the other, landing two DIFFERENT Docker networks on the same range. Must
    still be flagged as an overlap, not silently treated as "same network,
    nothing to check" the way two IDENTICAL expressions legitimately are."""
    a = REPO_ROOT / "compose.yaml"
    b = REPO_ROOT / "compose.edge.yaml"
    entries: list[_SubnetEntry] = [
        (a, "x", "${NET_A:-shared}", ipaddress.ip_network("10.99.0.0/29")),
        (b, "y", "${NET_B:-shared}", ipaddress.ip_network("10.99.0.0/29")),
    ]
    problems = _find_subnet_overlaps(entries)
    assert len(problems) == 1
    assert "overlaps" in problems[0]


def test_find_subnet_overlaps_treats_a_same_family_literal_and_its_interpolated_default_as_the_same_network():
    """A same-family pair spelled differently but resolving to the same name
    -- one a plain literal, the other an interpolation whose OWN default
    equals that literal -- is the base/overlay pattern at its documented
    default, not two independently-settable names. Pinning the SAME subnet:
    reconciled as one network declared twice, not a collision."""
    a = E2E_COMPOSE_DIR / "e2e.compose.yaml"
    b = E2E_COMPOSE_DIR / "e2e-mta.compose.yaml"
    entries: list[_SubnetEntry] = [
        (a, "k", "${X:-foo}", ipaddress.ip_network("10.99.0.0/29")),
        (b, "k", "foo", ipaddress.ip_network("10.99.0.0/29")),
    ]
    assert _find_subnet_overlaps(entries) == []


def test_find_subnet_overlaps_flags_a_same_family_literal_and_its_interpolated_default_with_mismatched_subnets():
    """Same pair as above, but pinning DIFFERENT subnets: whichever project's
    `up` runs first silently decides the real subnet for both -- the same
    hazard as two identical raw expressions with mismatched subnets, only
    reachable here once resolution (not raw text) decides "same network"."""
    a = E2E_COMPOSE_DIR / "e2e.compose.yaml"
    b = E2E_COMPOSE_DIR / "e2e-mta.compose.yaml"
    entries: list[_SubnetEntry] = [
        (a, "k", "${X:-foo}", ipaddress.ip_network("10.99.0.0/29")),
        (b, "k", "foo", ipaddress.ip_network("10.99.1.0/29")),
    ]
    problems = _find_subnet_overlaps(entries)
    assert len(problems) == 1
    assert "same Docker network with different subnets" in problems[0]


def test_find_subnet_overlaps_flags_a_cross_family_interpolated_collision():
    """Cross-family same resolved name: production's shadowsocks network name
    is an interpolation, so an e2e file spelling its resolved default
    literally joins that exact live network even with a non-overlapping
    pinned subnet of its own -- invisible to a raw-text `${` skip, since only
    one side is interpolated."""
    prod = REPO_ROOT / "compose.yaml"
    e2e = E2E_COMPOSE_DIR / "e2e.compose.yaml"
    entries: list[_SubnetEntry] = [
        (prod, "shadowsocks", "${SHADOWSOCKS_NETWORK:-shadowsocks}", ipaddress.ip_network("10.1.0.0/24")),
        (e2e, "e2e-shadowsocks", "shadowsocks", ipaddress.ip_network("10.2.0.0/24")),
    ]
    problems = _find_subnet_overlaps(entries)
    assert len(problems) == 1
    assert "same Docker network name across production/e2e" in problems[0]


def test_find_subnet_overlaps_flags_the_identical_unresolvable_expression_across_families():
    """Two files spelling the IDENTICAL unresolvable expression (a bare
    `${VAR}`) share one env var, so whatever it resolves to, both land on the
    same runtime network -- stronger evidence than the resolved-literal case
    above, and must be flagged as a cross-family collision (not silently
    reconciled by the same-family "must pin the same subnet" logic, and not
    silently passed through to the plain overlap check either)."""
    prod = REPO_ROOT / "compose.yaml"
    e2e = E2E_COMPOSE_DIR / "e2e.compose.yaml"
    entries: list[_SubnetEntry] = [
        (prod, "shadowsocks", "${SOME_SHARED_VAR}", ipaddress.ip_network("10.1.0.0/24")),
        (e2e, "e2e-shadowsocks", "${SOME_SHARED_VAR}", ipaddress.ip_network("10.1.0.0/24")),
    ]
    problems = _find_subnet_overlaps(entries)
    assert len(problems) == 1
    assert "same Docker network name across production/e2e" in problems[0]


def test_find_subnet_overlaps_allows_a_dual_stack_network_same_name_different_family():
    """`enable_ipv6: true` lets one Docker network legitimately pin both an
    IPv4 and an IPv6 `ipam.config` entry -- two entries, same name, same
    family, deliberately different subnets. Must not be mistaken for the
    "same name, mismatched subnet" collision case."""
    a = REPO_ROOT / "a.compose.yaml"
    entries: list[_SubnetEntry] = [
        (a, "mta-submit", "dual-stack-net", ipaddress.ip_network("10.99.0.0/29")),
        (a, "mta-submit", "dual-stack-net", ipaddress.ip_network("fd00:dead:beef::/64")),
    ]
    assert _find_subnet_overlaps(entries) == []


def test_find_subnet_overlaps_allows_a_network_with_two_ipv4_pools():
    """A single Docker network can legitimately have more than one IPv4
    `ipam.config` entry (`docker network create --subnet A --subnet B`).
    Same file, same network key, two pools -- not two networks to compare,
    and must not be flagged as "same name, different subnets"."""
    a = REPO_ROOT / "a.compose.yaml"
    entries: list[_SubnetEntry] = [
        (a, "edge", "edge-net", ipaddress.ip_network("10.99.0.0/29")),
        (a, "edge", "edge-net", ipaddress.ip_network("10.99.1.0/29")),
    ]
    assert _find_subnet_overlaps(entries) == []


def _external_spec(cfg: dict) -> tuple[bool, str | None]:
    """Whether a `networks:`/`volumes:` entry is `external:`, and the name an
    object-form `external:` mapping supplies.

    Compose's `external:` accepts three shapes: absent or `false` (not
    external); `true` (external, runtime name is `name:` if set else the bare
    compose key); or a mapping (`external: {}` -- same naming rule as `true`
    -- or `external: {name: X}`, which overrides the runtime name).
    `bool(cfg.get("external"))` gets the mapping form wrong on both counts:
    `{}` is external but Python-falsy (`bool({}) is False`), and `{name: X}`'s
    override name is invisible to `cfg.get("name")` -- either shape would
    defeat the cross-family reuse guards below, which key entirely off this.
    A quoted boolean (`external: "false"`) reaches here as `str`, not `bool`
    -- routed through the shared `_as_compose_bool`, or a quoted `"false"`/
    `"no"` would be misread as external. Anything that is neither bool, str,
    nor mapping (an int, a list, ...) is not valid Compose for this field and
    is rejected loudly rather than silently treated as `true`.
    """
    ext = cfg.get("external")
    if ext is None or ext is False:
        return False, None
    if isinstance(ext, dict):
        return True, ext.get("name")
    if isinstance(ext, str):
        # _as_compose_bool's str branch always returns a bool or raises --
        # never None -- but narrow explicitly so this stays a plain `bool`
        # for the declared return type.
        resolved = _as_compose_bool(ext)
        assert resolved is not None
        return resolved, None
    if ext is True:
        return True, None
    raise AssertionError(f"external: {ext!r} is not a recognized bool, str, or mapping")


def _resolved_external_name(key: str, name: str | None, external: bool) -> str | None:
    """The runtime Docker resource name, given a (key, name, external) triple
    from _declared_network_names / _declared_volume_names.

    An external resource's runtime name is `name:` if set, else the bare key
    -- Compose attaches directly, no `<project>_` prefix -- so `external`
    with no `name:` still resolves to something comparable, unlike the
    non-external case where a missing `name:` means "project-derived, can't
    predict". Shared by networks and volumes: Compose's external-naming rule
    is identical for both.
    """
    if name is not None:
        return _resolved_name(name)
    return key if external else None


def _find_cross_family_name_reuse(
    entries: list[tuple[Path, str, str | None, bool]],
    *,
    resolve: Callable[[str, str | None, bool], str | None],
    noun: str,
    flag_external: bool,
) -> list[str]:
    """Cross-family reuse of a resolved Docker resource name.

    Shared shape behind the network/volume/container_name guards below: each
    entry is a (path, key, name, external) tuple -- one file's own
    declaration of one resource -- and what varies between the three
    resource kinds is only `resolve` (how a (key, name, external) triple
    becomes the runtime name to compare) and whether an e2e `external: true`
    is an unconditional violation on its own (`flag_external`), independent
    of any name match -- true for networks and volumes, which have an
    `external:` concept at all; irrelevant for container_name, which
    doesn't.

    A pair matches on EITHER of two grounds, not just the resolved value:
    resolving to the same non-None literal (the interpolation-vs-literal
    case), OR sharing the identical raw `name` text even when NEITHER side
    resolves (e.g. both `${SOME_VAR}`, a bare required-value form). The raw
    match is not weaker evidence -- it's stronger: two projects reading the
    SAME env var land on the same runtime name for any given environment,
    unresolvable to a literal by this static tool or not, so skipping it
    just because `resolve()` can't predict the value would exempt the exact
    collision this function exists to catch.
    """
    problems = []
    if flag_external:
        for path, key, _name, external in entries:
            if _compose_family(path) == "e2e" and external:
                problems.append(f"{_rel(path)}: {noun} {key!r} sets external: true")
    for (pa, ka, na, ea), (pb, kb, nb, eb) in itertools.combinations(entries, 2):
        ra, rb = resolve(ka, na, ea), resolve(kb, nb, eb)
        matches = (ra is not None and ra == rb) or (na is not None and na == nb)
        if not matches:
            continue
        if _compose_family(pa) == _compose_family(pb):
            continue
        shown = ra if ra is not None else na
        problems.append(
            f"{_rel(pa)} {noun} {ka!r} ({na!r}) and {_rel(pb)} {noun} {kb!r} ({nb!r}) both resolve to "
            f"{noun} {shown!r} across production/e2e"
        )
    return problems


def _declared_network_names(path: Path) -> list[tuple[str, str | None, bool]]:
    """(network key, explicit name, external) for every network a compose
    file declares -- independent of whether it pins a subnet. Unlike
    _pinned_subnets, an unpinned entry still shows up here: both a bare
    name reuse and `external: true` attach to another Docker network without
    ever touching Docker's IPAM allocator, so a subnet-only check can't see
    either. _PARTIAL_SUBMISSION_OVERLAYS exists specifically because a file
    can declare `mta-submit` with no `ipam:` at all -- the same shape.
    """
    found = []
    for key, cfg in (load_compose(path).get("networks") or {}).items():
        cfg = cfg or {}
        external, external_name = _external_spec(cfg)
        found.append((key, cfg.get("name") or external_name, external))
    return found


def _find_network_name_reuse(entries: list[tuple[Path, str, str | None, bool]]) -> list[str]:
    """Problem strings for cross-family Docker network name reuse (pinned or
    not) and any e2e network declared `external: true`. Split out for direct
    synthetic testing, same pattern as _find_subnet_overlaps."""
    return _find_cross_family_name_reuse(entries, resolve=_resolved_external_name, noun="network", flag_external=True)


def test_no_cross_family_network_name_reuse_or_external_network():
    """Subnet-independent sibling of test_pinned_subnets_are_pairwise_disjoint:
    that guard only ever sees IPAM-*pinned* entries, so an e2e file that
    declares production's exact network name with no `ipam:` block (or reaches
    it via `external: true`) is invisible to it. This one isn't."""
    prod_entries = [(p, key, name, ext) for p in PRODUCTION_COMPOSE_FILES()
                    for key, name, ext in _declared_network_names(p)]
    e2e_entries = [(p, key, name, ext) for p in E2E_COMPOSE_FILES() for key, name, ext in _declared_network_names(p)]
    # Asserted separately, not combined -- a cross-family check is vacuous
    # unless BOTH families contribute (same reasoning as the volume/container
    # guards below).
    assert prod_entries, "no production compose file declares a network -- this guard would pass vacuously"
    assert e2e_entries, "no e2e compose file declares a network -- this guard would pass vacuously"
    problems = _find_network_name_reuse(prod_entries + e2e_entries)
    assert not problems, (
        "An e2e compose file must not reuse production's Docker network name, pinned or not, "
        "and must not attach to an existing network via external: true:\n" + "\n".join(f"  {p}" for p in problems)
    )


def test_find_network_name_reuse_flags_unpinned_cross_family_name_collision():
    """The exact shape _find_subnet_overlaps cannot see: no ipam on either
    side, so it never reaches _pinned_subnets, but the two files still name
    the identical Docker network across the production/e2e boundary."""
    prod = REPO_ROOT / "compose.yaml"
    e2e = E2E_COMPOSE_DIR / "e2e-mta.compose.yaml"
    entries = [(prod, "mta-submit", "mta-submit", False), (e2e, "mta-submit", "mta-submit", False)]
    problems = _find_network_name_reuse(entries)
    assert len(problems) == 1
    assert "across production/e2e" in problems[0]


def test_find_network_name_reuse_flags_external_on_an_e2e_network():
    e2e = E2E_COMPOSE_DIR / "e2e-mta.compose.yaml"
    entries = [(e2e, "mta-submit", None, True)]
    problems = _find_network_name_reuse(entries)
    assert len(problems) == 1
    assert "external: true" in problems[0]


def test_find_network_name_reuse_flags_a_production_external_network_via_key_fallback():
    """The network-side counterpart of test_find_volume_name_reuse_flags_an_
    external_e2e_volume_via_key_fallback, on the PRODUCTION side: a production
    file reaching a pre-existing network via `external: true` alone (no
    `name:` override, which reads as redundant with the key) resolves via its
    bare key -- production's real network name -- so it's still caught by the
    ordinary cross-family compare, not just the unconditional e2e-external
    flag above, which only ever fires for the e2e side."""
    prod = REPO_ROOT / "compose.gateway.yaml"
    e2e = E2E_COMPOSE_DIR / "e2e-edge.compose.yaml"
    entries = [(prod, "gateway", None, True), (e2e, "e2e-gateway", "gateway", False)]
    problems = _find_network_name_reuse(entries)
    assert len(problems) == 1
    assert "across production/e2e" in problems[0]


def test_as_compose_bool_examples():
    assert _as_compose_bool(True) is True
    assert _as_compose_bool(False) is False
    assert _as_compose_bool(None) is None
    for spelling in ("true", "yes", "y", "on", "1", "TRUE", "Yes"):
        assert _as_compose_bool(spelling) is True
    for spelling in ("false", "no", "n", "off", "0", "FALSE", "No"):
        assert _as_compose_bool(spelling) is False
    with pytest.raises(AssertionError):
        _as_compose_bool("maybe")
    # Not this function's job to validate -- a caller with its own shape for
    # a non-bool/str/None type (e.g. _external_spec's mapping form) checks
    # for it first; this just declines to produce a bool for it.
    assert _as_compose_bool({}) is None
    assert _as_compose_bool([1, 2]) is None


def test_external_spec_examples():
    """Compose's three `external:` shapes, and the two Python gets wrong:
    `external: {}` is external (True) despite being a falsy dict, and a
    YAML-quoted `external: "false"`/`"no"` is NOT external despite being a
    truthy non-empty string."""
    assert _external_spec({}) == (False, None)
    assert _external_spec({"external": False}) == (False, None)
    assert _external_spec({"external": True}) == (True, None)
    assert _external_spec({"external": {}}) == (True, None)
    assert _external_spec({"external": {"name": "postern-mta-data"}}) == (True, "postern-mta-data")
    assert _external_spec({"external": "false"}) == (False, None)
    assert _external_spec({"external": "no"}) == (False, None)
    assert _external_spec({"external": "true"}) == (True, None)
    assert _external_spec({"external": "YES"}) == (True, None)
    with pytest.raises(AssertionError):
        _external_spec({"external": "maybe"})
    # A type that's neither bool, str, nor mapping is not valid Compose for
    # this field -- rejected loudly rather than silently treated as `true`.
    with pytest.raises(AssertionError):
        _external_spec({"external": 1})
    with pytest.raises(AssertionError):
        _external_spec({"external": [1, 2]})


def test_declared_network_names_reads_object_form_external(monkeypatch):
    """The bug _external_spec exists to fix, exercised through
    _declared_network_names: a `networks: {n: {external: {}}}` entry must
    report external=True, not the `bool({})`-is-False that would silently
    exempt it from _find_network_name_reuse's unconditional e2e-external
    flag."""
    fake_path = E2E_COMPOSE_DIR / "_fake-external-object-form.compose.yaml"
    fake_compose = {"networks": {"n": {"external": {}}}}
    monkeypatch.setattr(
        sys.modules[__name__],
        "load_compose",
        lambda path, _real=load_compose: fake_compose if path == fake_path else _real(path),
    )
    assert _declared_network_names(fake_path) == [("n", None, True)]


def test_find_network_name_reuse_flags_an_interpolated_default_against_a_literal():
    """Production's shadowsocks network name is `${SHADOWSOCKS_NETWORK:-shadowsocks}`
    (compose.yaml) -- with the documented default env (the variable unset), an
    e2e file that spells the resolved default `shadowsocks` literally joins
    that exact live network. A raw-text compare is blind to this because only
    one side is interpolated; resolving both sides first is what catches it."""
    prod = REPO_ROOT / "compose.yaml"
    e2e = E2E_COMPOSE_DIR / "e2e.compose.yaml"
    entries = [
        (prod, "shadowsocks", "${SHADOWSOCKS_NETWORK:-shadowsocks}", False),
        (e2e, "e2e-shadowsocks", "shadowsocks", False),
    ]
    problems = _find_network_name_reuse(entries)
    assert len(problems) == 1
    assert "across production/e2e" in problems[0]


def test_find_network_name_reuse_flags_two_interpolations_sharing_a_default():
    """Neither side has to be a bare literal -- two different variables that
    both default to the same value collide just as surely if both are left
    unset."""
    prod = REPO_ROOT / "compose.yaml"
    e2e = E2E_COMPOSE_DIR / "e2e.compose.yaml"
    entries = [
        (prod, "shadowsocks", "${SHADOWSOCKS_NETWORK:-shadowsocks}", False),
        (e2e, "e2e-shadowsocks", "${SOME_OTHER_VAR:-shadowsocks}", False),
    ]
    problems = _find_network_name_reuse(entries)
    assert len(problems) == 1
    assert "across production/e2e" in problems[0]


def test_find_network_name_reuse_flags_a_nested_interpolated_default_against_a_literal():
    """A nested default (`${A:-${B:-x}}`) is still fully determined with both
    vars unset -- Compose resolves it the same as a single-level default, so
    an e2e file spelling the resolved value literally must be caught exactly
    like the single-level case above, not silently exempted because the
    production side happens to nest two variables."""
    prod = REPO_ROOT / "compose.yaml"
    e2e = E2E_COMPOSE_DIR / "e2e.compose.yaml"
    entries = [
        (prod, "shadowsocks", "${SHADOWSOCKS_NETWORK:-${SHADOWSOCKS_NETWORK_DEFAULT:-shadowsocks}}", False),
        (e2e, "e2e-shadowsocks", "shadowsocks", False),
    ]
    problems = _find_network_name_reuse(entries)
    assert len(problems) == 1
    assert "across production/e2e" in problems[0]


def test_find_network_name_reuse_flags_an_alternate_value_default_against_a_literal():
    """`${VAR:+alt}` is fully determined at the all-unset default too (resolves
    to empty, since VAR unset means the alternate value never applies) -- an
    e2e file spelling that resolved value literally must be caught the same
    way as the `:-default` form above."""
    prod = REPO_ROOT / "compose.yaml"
    e2e = E2E_COMPOSE_DIR / "e2e.compose.yaml"
    entries = [
        (prod, "shadowsocks", "shadowsocks${SHADOWSOCKS_NETWORK_SUFFIX:+-x}", False),
        (e2e, "e2e-shadowsocks", "shadowsocks", False),
    ]
    problems = _find_network_name_reuse(entries)
    assert len(problems) == 1
    assert "across production/e2e" in problems[0]


def test_find_network_name_reuse_does_not_flag_an_unresolvable_interpolation():
    """A bare `${VAR}` (no default) and a required-value `${VAR:?msg}` both
    resolve to *something* only Compose can know at invocation time -- this
    module must not guess, or it would risk a false positive against an
    unrelated literal that happens to match the variable's eventual value."""
    prod = REPO_ROOT / "compose.yaml"
    e2e = E2E_COMPOSE_DIR / "e2e.compose.yaml"
    entries = [
        (prod, "shadowsocks", "${SHADOWSOCKS_NETWORK}", False),
        (e2e, "e2e-shadowsocks", "shadowsocks", False),
    ]
    assert _find_network_name_reuse(entries) == []
    entries = [
        (prod, "shadowsocks", "${SHADOWSOCKS_NETWORK:?must be set}", False),
        (e2e, "e2e-shadowsocks", "shadowsocks", False),
    ]
    assert _find_network_name_reuse(entries) == []


def test_find_network_name_reuse_flags_the_identical_unresolvable_expression_across_families():
    """Two files spelling the IDENTICAL unresolvable expression (a bare
    `${VAR}`, no default) are NOT exempt just because this module can't
    predict its value: they reference the same env var in one environment,
    so whatever VAR resolves to, both land on the same runtime name. That is
    stronger evidence than the interpolation-vs-literal case above, which
    IS flagged -- skipping the unresolvable case entirely would exempt the
    more certain collision and catch only the less certain one."""
    prod = REPO_ROOT / "compose.yaml"
    e2e = E2E_COMPOSE_DIR / "e2e.compose.yaml"
    entries = [
        (prod, "shadowsocks", "${SOME_SHARED_VAR}", False),
        (e2e, "e2e-shadowsocks", "${SOME_SHARED_VAR}", False),
    ]
    problems = _find_network_name_reuse(entries)
    assert len(problems) == 1
    assert "across production/e2e" in problems[0]


def test_resolved_name_examples():
    assert _resolved_name(None) is None
    assert _resolved_name("shadowsocks") == "shadowsocks"
    assert _resolved_name("${SHADOWSOCKS_NETWORK:-shadowsocks}") == "shadowsocks"
    assert _resolved_name("${SHADOWSOCKS_NETWORK-shadowsocks}") == "shadowsocks"
    assert _resolved_name("${SHADOWSOCKS_NETWORK}") is None
    assert _resolved_name("${SHADOWSOCKS_NETWORK:?must be set}") is None
    # A literal prefix/suffix around one interpolation, or more than one
    # interpolation concatenated, are each fully determined and resolve.
    assert _resolved_name("${V:-a}-b") == "a-b"
    assert _resolved_name("prefix-${V:-a}") == "prefix-a"
    assert _resolved_name("${NET:-shadow}${SUF:-socks}") == "shadowsocks"
    # A nested interpolation resolves too -- the inner `${B:-x}` substitutes
    # first, leaving `${A:-x}`, which the next fixed-point pass resolves to
    # `x`, matching Compose's own resolution of both vars unset.
    assert _resolved_name("${A:-${B:-x}}") == "x"
    # Compose's brace-less $VAR form is interpolation too (identical meaning
    # to ${VAR}) and has no default syntax of its own -- always unresolvable,
    # never the literal four-character string "$NET".
    assert _resolved_name("$NET") is None
    assert _resolved_name("prefix-$NET-suffix") is None
    # ${VAR:+alt} / ${VAR+alt}: with VAR unset, the alternate value never
    # applies -- resolves to empty, same as Compose's own rendering.
    assert _resolved_name("shadowsocks${SUF:+-test}") == "shadowsocks"
    assert _resolved_name("shadowsocks${SUF+-test}") == "shadowsocks"
    # `$$` is Compose's own escape for a literal `$` -- collapsed in the
    # output, not left doubled, so a name using it resolves to what Compose
    # actually renders rather than to raw, still-escaped source text.
    assert _resolved_name("prefix-$${A}") == "prefix-${A}"
    assert _resolved_name("just-a-dollar-$$") == "just-a-dollar-$"


# Host ports ===========================================================================================================
def parse_published_ports(entries: list, *, where: str) -> list[tuple[str | None, int, int, str]]:
    """(host_ip, host_port, container_port, protocol) for each entry of one
    service's `ports:` list.

    Handles Compose's short string form (`[[IP:]HOST:]CONTAINER[/PROTO]`) and
    the long mapping form. Every other form -- a bare container port, an
    `IP::CONTAINER` ephemeral publish, a port range, a bracketed IPv6 host IP,
    an ephemeral `0` host port -- is rejected loudly rather than skipped or
    mis-parsed. All of them DO publish something on the host, so silently
    dropping one would make the guards below pass vacuously on exactly the
    entry they exist to catch. `protocol` defaults to `"tcp"` (Compose's own
    default) and is kept alongside the port because TCP and UDP occupy
    independent port namespaces -- two entries with the same number but
    different protocol do not actually collide. `container_port` is carried
    through (not just the host side) so a caller that documents the full
    `HOST:CONTAINER` mapping -- see
    test_docs_quote_the_current_e2e_mta_submit_subnets_and_port -- derives
    both halves from the compose file instead of assuming they match.

    Given an explicit `where` label so it can be unit-tested on synthetic
    entries; the repo's own compose files exercise only the two supported
    forms.
    """
    valid_protocols = {"tcp", "udp", "sctp"}
    found = []
    for entry in entries:
        if isinstance(entry, dict):
            published = entry.get("published")
            assert published is not None, f"{where}: long-form ports entry {entry!r} has no `published`; " \
                                          "Docker picks an ephemeral host port -- extend this parser"
            target = entry.get("target")
            assert target is not None, f"{where}: long-form ports entry {entry!r} has no `target`; extend this parser"
            host_ip, spec, container_spec = entry.get("host_ip"), str(published), str(target)
            protocol = str(entry.get("protocol") or "tcp").lower()
        else:
            spec, sep, proto_suffix = str(entry).partition("/")
            protocol = proto_suffix.lower() if sep else "tcp"
            assert "[" not in spec, f"{where}: bracketed IPv6 host IP in {entry!r}; extend this parser"
            parts = spec.split(":")
            assert len(parts) in (2, 3), (
                f"{where}: ports entry {entry!r} is not `HOST:CONTAINER` or `IP:HOST:CONTAINER`. "
                "A bare container port publishes on an ephemeral 0.0.0.0 host port -- extend this parser"
            )
            host_ip, spec, container_spec = (None, parts[0], parts[1]) if len(parts) == 2 else \
                (parts[0], parts[1], parts[2])
        # Case-normalized before this check. Verified against `docker compose
        # config`: Compose itself lowercases the short form's "TCP" suffix,
        # but passes a long-form `protocol: TCP` through unchanged -- so this
        # parser lowercases both, or a long-form "TCP" could look disjoint
        # from a short-form "tcp" on the same port to a caller comparing them.
        assert protocol in valid_protocols, (
            f"{where}: ports entry {entry!r} has protocol {protocol!r}, expected one of {sorted(valid_protocols)}"
        )
        assert spec.isdigit(), (
            f"{where}: ports entry {entry!r} has host port {spec!r}, not a plain number. "
            "Ranges and empty (ephemeral) host ports both land here -- extend this parser"
        )
        assert container_spec.isdigit(
        ), (f"{where}: ports entry {entry!r} has container port {container_spec!r}, not a plain number.")
        port = int(spec)
        assert port != 0, (
            f"{where}: ports entry {entry!r} has host port 0, Compose's other spelling of an ephemeral "
            "publish -- extend this parser"
        )
        found.append((host_ip, port, int(container_spec), protocol))
    return found


def _published_host_ports(path: Path) -> list[tuple[str, str | None, int, int, str]]:
    """(service, host_ip, host_port, container_port, protocol) for every port
    a compose file publishes."""
    found = []
    for service, cfg in (load_compose(path).get("services") or {}).items():
        cfg = cfg or {}
        # `network_mode: host` claims every host port directly, with no
        # `ports:` entry to parse -- invisible to every guard below it.
        assert cfg.get("network_mode") != "host", (
            f"{_rel(path)}: service {service!r} sets network_mode: host, which claims the entire host port "
            "namespace and is invisible to the port-collision/loopback guards -- extend this module"
        )
        # `ports: !reset []` (compose.gateway.yaml) loads as None via ComposeLoader.
        entries = cfg.get("ports") or []
        for host_ip, port, container_port, protocol in parse_published_ports(
            entries, where=f"{_rel(path)} service {service!r}"
        ):
            found.append((service, host_ip, port, container_port, protocol))
    return found


def test_published_host_ports_rejects_network_mode_host(monkeypatch):
    """`network_mode: host` is Compose's other way to claim host ports --
    bypassing `ports:` entirely, so parse_published_ports never sees it.
    Tested directly against a synthetic path/compose pair rather than a real
    file: no compose file in this repo uses network_mode today."""
    fake_path = REPO_ROOT / "portal" / "tests" / "e2e" / "_fake-network-mode-host.compose.yaml"
    fake_compose = {"services": {"mta": {"network_mode": "host"}}}
    monkeypatch.setattr(
        sys.modules[__name__],
        "load_compose",
        lambda path, _real=load_compose: fake_compose if path == fake_path else _real(path),
    )
    with pytest.raises(AssertionError, match="network_mode: host"):
        _published_host_ports(fake_path)


def _is_loopback(host_ip: str | None) -> bool:
    """Whether a `ports:` host IP is a loopback address. None (Compose's own
    default is `0.0.0.0`) and a malformed value are both not loopback."""
    if host_ip is None:
        return False
    try:
        return ipaddress.ip_address(host_ip).is_loopback
    except ValueError:
        return False


def test_parse_published_ports_accepts_both_supported_forms():
    """The two forms the repo actually uses, on synthetic input -- the guards
    below only ever see whatever the compose files happen to contain today."""
    assert parse_published_ports(["80:80/tcp"], where="t") == [(None, 80, 80, "tcp")]
    assert parse_published_ports(["127.0.0.1:8443:443/tcp"], where="t") == [("127.0.0.1", 8443, 443, "tcp")]
    assert parse_published_ports(["53:53/udp"], where="t") == [(None, 53, 53, "udp")]
    assert parse_published_ports([{"host_ip": "127.0.0.1", "published": 2525, "target": 25}], where="t") == \
        [("127.0.0.1", 2525, 25, "tcp")]
    assert parse_published_ports([{"published": 53, "target": 53, "protocol": "udp"}], where="t") == \
        [(None, 53, 53, "udp")]


def test_parse_published_ports_normalizes_protocol_case():
    """See parse_published_ports's own inline comment on the protocol-case
    assert for why."""
    assert parse_published_ports(["25:25/TCP"], where="t") == [(None, 25, 25, "tcp")]
    assert parse_published_ports([{"published": 25, "target": 25, "protocol": "TCP"}], where="t") == \
        [(None, 25, 25, "tcp")]


@pytest.mark.parametrize(
    "entry",
    [
        "3000",  # bare container port: ephemeral host port on 0.0.0.0
        "127.0.0.1::25",  # ephemeral host port, bound to an interface
        "8000-8010:8000-8010",  # range
        "[::1]:25:25",  # bracketed IPv6 host IP
        "0:25",  # ephemeral host port, spelled as 0
        "25:25/sctpx",  # unrecognized protocol
        {"target": 25},  # long form, no `published`
        {"published": 25},  # long form, no `target`
        {"published": 25, "target": 25, "protocol": "sctpx"},  # long form, unrecognized protocol
        {"published": 0, "target": 25},  # long form, ephemeral host port spelled as 0
    ]
)
def test_parse_published_ports_rejects_unsupported_forms(entry):
    """Tested directly rather than through a compose file, so every rejection
    branch stays covered no matter what the repo's files contain."""
    with pytest.raises(AssertionError):
        parse_published_ports([entry], where="t")


# A deliberate, allowlisted exception to "every e2e host port is loopback and
# disjoint from production's" -- both guards below consult this same mapping,
# so the exception (and its reason) is recorded once, not duplicated across
# two independent skip conditions that could drift apart.
_HOST_PORT_ALLOWLIST: dict[tuple[str, str, int, str], str] = {
    ("portal/tests/e2e/e2e-mta-real.compose.yaml", "mta", 25, "tcp"): (
        "Real sender-callout / MX-based delivery needs this container reachable "
        "at its own DNS-advertised address; loopback or a different port would "
        "defeat that. See CLAUDE.md's co-location invariant for the full "
        "rationale (including which side loses on collision) and issue #223 for "
        "a fully hermetic replacement."
    ),
}


def _host_port_key(path: Path, service: str, port: int, protocol: str) -> tuple[str, str, int, str]:
    return (_rel(path), service, port, protocol)


def test_e2e_publishes_no_host_port_production_publishes():
    """Two processes cannot bind the same (host port, protocol). Binding
    loopback is not a way out: production publishes on 0.0.0.0, which already
    owns 127.0.0.1 on that port. So the e2e (port, protocol) pair must be
    disjoint from production's, independently of the interface, with the one
    documented exception in _HOST_PORT_ALLOWLIST. TCP and UDP are compared
    separately -- they occupy independent kernel port namespaces, so the same
    number on different protocols does not collide."""
    production = {(port, proto)
                  for path in PRODUCTION_COMPOSE_FILES()
                  for _, _, port, _, proto in _published_host_ports(path)}
    e2e = [(path, svc, port, proto) for path in E2E_COMPOSE_FILES()
           for svc, _, port, _, proto in _published_host_ports(path)]
    assert production, "no production compose file publishes a host port -- this guard would pass vacuously"
    assert e2e, "no e2e compose file publishes a host port -- this guard would pass vacuously"
    problems = [
        f"{_rel(path)}: service {svc!r} publishes host port {port}/{proto}" for path, svc, port, proto in e2e
        if (port, proto) in production and _host_port_key(path, svc, port, proto) not in _HOST_PORT_ALLOWLIST
    ]
    assert not problems, (
        f"E2e compose files must not publish a host port production publishes ({sorted(production)}) -- "
        "the two stacks share one host and the second bind fails, unless allowlisted in "
        "_HOST_PORT_ALLOWLIST with a written reason:\n" + "\n".join(f"  {p}" for p in problems)
    )


def test_e2e_published_host_ports_bind_loopback():
    """Every e2e host port is a fixture channel, never a service -- except the
    one entry in _HOST_PORT_ALLOWLIST, which is a deliberate exception to this
    rule, not a bug in it. Binding 0.0.0.0 on a VPS (which is exactly where
    e2e-mta-real runs) exposes a test service to the internet and reserves the
    port on every interface, so a non-loopback bind must be explained, not
    just present. Checked as an actual loopback address, not the literal
    string "127.0.0.1", so a (currently hypothetical) IPv6 `::1` publish is
    judged correctly instead of being flagged alongside a real 0.0.0.0
    exposure."""
    problems = []
    for path in E2E_COMPOSE_FILES():
        for service, host_ip, port, _, protocol in _published_host_ports(path):
            if _is_loopback(host_ip):
                continue
            if _host_port_key(path, service, port, protocol) in _HOST_PORT_ALLOWLIST:
                continue
            where = host_ip or "0.0.0.0 (all interfaces)"
            problems.append(f"{_rel(path)}: service {service!r} publishes host port {port}/{protocol} on {where}")
    assert not problems, (
        "E2e compose files must publish host ports on a loopback address only, unless allowlisted in "
        "_HOST_PORT_ALLOWLIST with a written reason:\n" + "\n".join(f"  {p}" for p in problems)
    )


def test_host_port_allowlist_entries_still_exist():
    """Tripwire: an allowlist entry for a port that no longer exists would
    silently exempt nothing -- or worse, silently apply to an unrelated
    future service/port that happened to reuse the same tuple."""
    published = {
        _host_port_key(path, svc, port, proto)
        for path in E2E_COMPOSE_FILES()
        for svc, _, port, _, proto in _published_host_ports(path)
    }
    for key in _HOST_PORT_ALLOWLIST:
        assert key in published, f"_HOST_PORT_ALLOWLIST entry {key!r} no longer matches any e2e compose publish"


def test_is_loopback_accepts_ipv6_and_rejects_bare_and_malformed():
    assert _is_loopback("127.0.0.1") is True
    assert _is_loopback("::1") is True
    assert _is_loopback(None) is False
    assert _is_loopback("0.0.0.0") is False
    assert _is_loopback("not-an-ip") is False


# Named volumes and container names ====================================================================================
# Host-wide like subnets and host ports, but on neither of those two axes: a
# named volume and a container_name are claimed by whichever project's `up`
# creates them first, with no IPAM allocator or kernel bind to refuse the
# second claimant -- an e2e stack that copies a volume block or a
# container_name literal without renaming it silently attaches to (or fails
# to start next to) production's real resource. postern-mta-data holds the
# DKIM private key and state.json.
def _declared_volume_names(path: Path) -> list[tuple[str, str | None, bool]]:
    """(volume key, explicit name, external) for every top-level named
    volume a compose file declares.

    `name:` is not defaulted to the key for the non-external case -- Compose
    derives the runtime name from `<project>_<key>` when absent, so two files
    using the same key with no `name:` are two different volumes (same
    convention as _pinned_subnets' network name). `external: true` is a
    DIFFERENT naming rule, not a variant of the above: Compose does not apply
    the project prefix to an external resource, so `external` is returned
    alongside the raw name/key rather than folded into a single resolved
    string here -- see _resolved_external_name, which is the one place that
    combines them.
    """
    found = []
    for key, cfg in (load_compose(path).get("volumes") or {}).items():
        cfg = cfg or {}
        external, external_name = _external_spec(cfg)
        found.append((key, cfg.get("name") or external_name, external))
    return found


def _declared_container_names(path: Path) -> list[tuple[str, str]]:
    """(service key, `container_name:`) for every service that sets one. A
    service with no `container_name:` gets a Compose-generated, project-scoped
    name and is invisible here on purpose -- there's nothing to collide."""
    found = []
    for service, cfg in (load_compose(path).get("services") or {}).items():
        name = (cfg or {}).get("container_name")
        if name is not None:
            found.append((service, str(name)))
    return found


def _find_volume_name_reuse(entries: list[tuple[Path, str, str | None, bool]]) -> list[str]:
    """Problem strings for cross-family Docker volume name reuse (pinned or
    not) and any e2e volume declared `external: true`."""
    return _find_cross_family_name_reuse(entries, resolve=_resolved_external_name, noun="volume", flag_external=True)


def _find_container_name_reuse(entries: list[tuple[Path, str, str]]) -> list[str]:
    """Problem strings for cross-family container_name reuse. `entries` is a
    3-tuple (unlike the network/volume 4-tuple) -- container_name has no
    `external:`-shaped alternate naming rule to track, so there's nothing to
    pad it with beyond a constant False before delegating to the shared
    cross-family compare."""
    padded = [(path, key, name, False) for path, key, name in entries]
    return _find_cross_family_name_reuse(
        padded, resolve=lambda key, name, external: _resolved_name(name), noun="container_name", flag_external=False
    )


def test_no_cross_family_volume_name_reuse():
    prod_entries = [(p, key, name, ext) for p in PRODUCTION_COMPOSE_FILES()
                    for key, name, ext in _declared_volume_names(p)]
    e2e_entries = [(p, key, name, ext) for p in E2E_COMPOSE_FILES() for key, name, ext in _declared_volume_names(p)]
    # Asserted separately, not as one combined `assert entries`: a
    # cross-family check is vacuous unless BOTH families contribute, and a
    # non-empty combined list is satisfied by either side alone (e.g. if a
    # future e2e overlay stopped declaring any top-level volumes, the guard
    # would report success on exactly the change that removed its coverage).
    assert prod_entries, "no production compose file declares a volume -- this guard would pass vacuously"
    assert e2e_entries, "no e2e compose file declares a volume -- this guard would pass vacuously"
    problems = _find_volume_name_reuse(prod_entries + e2e_entries)
    assert not problems, (
        "An e2e compose file must not reuse a production Docker volume name -- the e2e provisioner "
        "would read and rotate production's real DKIM state:\n" + "\n".join(f"  {p}" for p in problems)
    )


def test_no_cross_family_container_name_reuse():
    prod_entries = [(p, svc, name) for p in PRODUCTION_COMPOSE_FILES() for svc, name in _declared_container_names(p)]
    e2e_entries = [(p, svc, name) for p in E2E_COMPOSE_FILES() for svc, name in _declared_container_names(p)]
    assert prod_entries, "no production compose file sets a container_name -- this guard would pass vacuously"
    assert e2e_entries, "no e2e compose file sets a container_name -- this guard would pass vacuously"
    problems = _find_container_name_reuse(prod_entries + e2e_entries)
    assert not problems, (
        "An e2e compose file must not reuse a production container_name -- the second `docker run` "
        "for that name fails on collision:\n" + "\n".join(f"  {p}" for p in problems)
    )


def test_find_volume_name_reuse_flags_a_collision():
    prod = REPO_ROOT / "compose.yaml"
    e2e = E2E_COMPOSE_DIR / "e2e-mta.compose.yaml"
    entries = [(prod, "postern-mta-data", "postern-mta-data", False),
               (e2e, "postern-mta-data", "postern-mta-data", False)]
    problems = _find_volume_name_reuse(entries)
    assert len(problems) == 1
    assert "across production/e2e" in problems[0]


def test_find_volume_name_reuse_flags_an_interpolated_default_against_a_literal():
    """The volume-side counterpart of test_find_network_name_reuse_flags_an_
    interpolated_default_against_a_literal: a production `${VAR:-default}`
    volume name against an e2e file spelling the resolved default literally,
    routed through the same _resolved_external_name every other volume guard
    test uses via a plain string -- unexercised for interpolation until now."""
    prod = REPO_ROOT / "compose.yaml"
    e2e = E2E_COMPOSE_DIR / "e2e-mta.compose.yaml"
    entries = [
        (prod, "mta-data", "${MTA_DATA_VOLUME:-postern-mta-data}", False),
        (e2e, "mta-data", "postern-mta-data", False),
    ]
    problems = _find_volume_name_reuse(entries)
    assert len(problems) == 1
    assert "across production/e2e" in problems[0]


def test_find_volume_name_reuse_flags_an_external_e2e_volume_regardless_of_name():
    """The shape _find_network_name_reuse already handles for networks:
    `external: true` bypasses the `<project>_<key>` prefix entirely, so the
    runtime name is the bare key -- here, literally production's real volume
    name -- with no `name:` override needed to reach it."""
    e2e = E2E_COMPOSE_DIR / "e2e-mta.compose.yaml"
    entries = [(e2e, "postern-mta-data", None, True)]
    problems = _find_volume_name_reuse(entries)
    assert len(problems) == 1
    assert "external: true" in problems[0]


def test_find_volume_name_reuse_flags_an_external_e2e_volume_via_key_fallback():
    """An external volume with no `name:` resolves via its bare key (see
    _resolved_external_name), not None -- so it's still caught by the ordinary
    cross-family compare too, independent of the unconditional external flag
    above."""
    prod = REPO_ROOT / "compose.yaml"
    e2e = E2E_COMPOSE_DIR / "e2e-mta.compose.yaml"
    entries = [(prod, "postern-mta-data", "postern-mta-data", False), (e2e, "postern-mta-data", None, True)]
    problems = _find_volume_name_reuse(entries)
    assert len(problems) == 2  # the unconditional external:true flag, AND the name-collision flag


def test_declared_volume_names_reads_object_form_external(monkeypatch):
    """The volume-side counterpart of test_declared_network_names_reads_
    object_form_external: `volumes: {postern-mta-data: {external: {}}}`
    must report external=True, not the `bool({})`-is-False that would
    silently exempt it from _find_volume_name_reuse's unconditional
    e2e-external flag -- exactly the shape that hands the e2e provisioner
    production's real DKIM volume with no `name:` override needed at all."""
    fake_path = E2E_COMPOSE_DIR / "_fake-external-object-form.compose.yaml"
    fake_compose = {"volumes": {"postern-mta-data": {"external": {}}}}
    monkeypatch.setattr(
        sys.modules[__name__],
        "load_compose",
        lambda path, _real=load_compose: fake_compose if path == fake_path else _real(path),
    )
    assert _declared_volume_names(fake_path) == [("postern-mta-data", None, True)]


def test_find_container_name_reuse_flags_a_collision():
    prod = REPO_ROOT / "compose.yaml"
    e2e = E2E_COMPOSE_DIR / "e2e-mta.compose.yaml"
    entries = [(prod, "mta", "mta"), (e2e, "mta", "mta")]
    problems = _find_container_name_reuse(entries)
    assert len(problems) == 1
    assert "across production/e2e" in problems[0]


def test_find_container_name_reuse_flags_an_interpolated_default_against_a_literal():
    """The container_name-side counterpart of the same interpolation case:
    `container_name:` supports the identical `${VAR:-default}` syntax, routed
    through _find_container_name_reuse's own lambda (not
    _resolved_external_name -- container_name has no `external:` concept),
    which was otherwise only ever exercised with plain literals."""
    prod = REPO_ROOT / "compose.yaml"
    e2e = E2E_COMPOSE_DIR / "e2e-mta.compose.yaml"
    entries = [(prod, "mta", "${MTA_CONTAINER_NAME:-mta}"), (e2e, "mta", "mta")]
    problems = _find_container_name_reuse(entries)
    assert len(problems) == 1
    assert "across production/e2e" in problems[0]


def test_find_volume_and_container_name_reuse_allow_same_family_reuse():
    """A base file and its own overlay sharing a volume/container name is the
    normal Compose base+overlay pattern, not a collision."""
    a = REPO_ROOT / "portal" / "tests" / "e2e" / "e2e.compose.yaml"
    b = REPO_ROOT / "portal" / "tests" / "e2e" / "e2e-mta.compose.yaml"
    volume_entries = [(a, "postern-e2e-data", "postern-e2e-data", False),
                      (b, "postern-e2e-data", "postern-e2e-data", False)]
    assert _find_volume_name_reuse(volume_entries) == []
    container_entries = [(a, "portal", "e2e-portal"), (b, "portal", "e2e-portal")]
    assert _find_container_name_reuse(container_entries) == []


def test_find_volume_and_container_name_reuse_allow_distinct_names():
    prod = REPO_ROOT / "compose.yaml"
    e2e = E2E_COMPOSE_DIR / "e2e-mta.compose.yaml"
    volume_entries = [(prod, "postern-mta-data", "postern-mta-data", False),
                      (e2e, "postern-mta-data", "postern-e2e-mta-dkim-data", False)]
    assert _find_volume_name_reuse(volume_entries) == []
    container_entries = [(prod, "mta", "mta"), (e2e, "mta", "postern-e2e-mta-mta")]
    assert _find_container_name_reuse(container_entries) == []


# Documentation literals ===============================================================================================
def _subnet_of(path: Path, key: str) -> str:
    """The single pinned subnet for network `key` in `path` -- generalizes
    the old mta-submit-only helper so the same lookup covers the two
    overlays' `default` networks too (also quoted by value in CLAUDE.md's
    co-location bullet, not just mta-submit's)."""
    for found_key, _, net in _pinned_subnets(path):
        if found_key == key:
            return str(net)
    raise AssertionError(f"{_rel(path)}: no {key!r} subnet pinned")


def test_docs_quote_the_current_e2e_mta_submit_subnets_and_port():
    """CLAUDE.md's co-location bullet and docs/development/testing.md both
    quote production's and the e2e overlays' mta-submit subnets, plus the
    real-mode host port, in prose; CLAUDE.md additionally quotes the two
    overlays' `default`-network subnets by value. Nothing else pins those
    numbers against the compose files -- CLAUDE.md sits outside
    test_docs.py's MUST_KEEP_CODE scan (DOCS_DIR is docs/ only). Without
    this, `test_pinned_subnet_inventory_is_complete` and
    `test_production_mta_submit_subnet_is_the_documented_literal` would
    force a future subnet move to update the *tests*, but the prose in
    these two files could still go stale silently."""
    production_subnet = production_mta_submit_subnet()
    e2e_mta_subnet = _subnet_of(E2E_COMPOSE_DIR / "e2e-mta.compose.yaml", SUBMIT_ALIAS)
    e2e_mta_real_subnet = _subnet_of(E2E_COMPOSE_DIR / "e2e-mta-real.compose.yaml", SUBMIT_ALIAS)
    e2e_mta_default_subnet = _subnet_of(E2E_COMPOSE_DIR / "e2e-mta.compose.yaml", "default")
    e2e_mta_real_default_subnet = _subnet_of(E2E_COMPOSE_DIR / "e2e-mta-real.compose.yaml", "default")
    # host_ip is part of the documented literal too, not just the port -- a
    # hardcoded "25:25/tcp" here would let the overlay's actual publish spec
    # (e.g. a re-added host_ip, or a protocol change) drift from the docs
    # while this guard stayed green. container_port is read from the compose
    # file too, not assumed equal to the host port -- a hardcoded
    # f"{port}:{port}" would keep asserting "25:25/tcp" even if the overlay's
    # container side ever changed (e.g. "25:2525/tcp"), silently fabricating
    # the very literal this test exists to keep honest.
    mta_ports = [(host_ip, port, container_port, protocol) for svc, host_ip, port, container_port, protocol in
                 _published_host_ports(E2E_COMPOSE_DIR / "e2e-mta-real.compose.yaml") if svc == "mta"]
    assert mta_ports == [(None, 25, 25, "tcp")], f"e2e-mta-real.compose.yaml mta host ports changed: {mta_ports!r}"
    _, real_mode_port, real_mode_container_port, real_mode_protocol = mta_ports[0]
    real_mode_port_literal = f"{real_mode_port}:{real_mode_container_port}/{real_mode_protocol}"

    claude_md = (REPO_ROOT / "CLAUDE.md").read_text(encoding="utf-8")
    testing_md = (REPO_ROOT / "docs" / "development" / "testing.md").read_text(encoding="utf-8")
    for literal in (production_subnet, e2e_mta_subnet, e2e_mta_real_subnet, real_mode_port_literal):
        assert literal in claude_md, f"CLAUDE.md no longer quotes {literal!r} -- update its co-location bullet"
        assert literal in testing_md, f"docs/development/testing.md no longer quotes {literal!r}"
    # The two overlays' `default`-network subnets are quoted in CLAUDE.md's
    # co-location bullet only -- testing.md's shorter paragraph doesn't name
    # them, so they're checked against CLAUDE.md alone.
    for literal in (e2e_mta_default_subnet, e2e_mta_real_default_subnet):
        assert literal in claude_md, f"CLAUDE.md no longer quotes {literal!r} -- update its co-location bullet"
