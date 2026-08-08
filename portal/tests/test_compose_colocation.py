"""Regression tests for issue #198: an e2e compose stack must not claim any
host-namespace resource (a subnet, a host port) that a co-located production
Postern stack already claims.

A host can run production and an e2e stack at once (the maintainer's VPS is
exactly that host). Docker refuses overlapping subnets and the kernel refuses
a second bind of the same host port, so an e2e stack that claims production's
subnet or port doesn't degrade -- `compose up` fails outright, or worse, the
e2e stack wins the race and production's mta can't restart. These guards are
glob-derived (`compose*.yaml` + `portal/tests/e2e/*.compose.yaml`), so a new
overlay or a new production compose file is covered automatically. No Docker
required.
"""
from __future__ import annotations

import ipaddress
import itertools
import sys
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
        if path not in exempt:
            assert net.get("internal") is True, f"{rel}: {SUBMIT_ALIAS} network must be internal: true"
        else:
            assert net.get("internal") is not False, (
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
        ("portal/tests/e2e/e2e-mta-real.compose.yaml", "mta-submit", "10.234.44.0/29"),
    }, f"the set of IPAM-pinned subnets changed: {sorted(inventory)!r}"


_SubnetEntry = tuple[Path, str, "str | None", "ipaddress.IPv4Network | ipaddress.IPv6Network"]


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
        shown_a = f"{_rel(pa)} {ka} ({na or '<project-derived>'}) {sa}"
        shown_b = f"{_rel(pb)} {kb} ({nb or '<project-derived>'}) {sb}"
        # An interpolated name (`${VAR:-default}`) is not provably the same
        # runtime network just because two files spell the identical
        # expression -- Compose interpolates per invocation, and a
        # project-specific override could resolve them differently. Treated
        # as unknown (falls through to the version/overlap checks below)
        # rather than assumed equal.
        same_explicit_name = na is not None and nb is not None and na == nb and "${" not in na and "${" not in nb

        if same_explicit_name and _compose_family(pa) != _compose_family(pb):
            # Same explicit name across the production/e2e boundary: not a
            # legitimate base/overlay pair, but two different compose
            # projects attaching to the identical Docker network -- the e2e
            # container joins production's network directly, bypassing the
            # whole point of pinning separate subnets. Independent of address
            # family: checked before the IP-version skip below, since joining
            # production's network doesn't require the pinned subnets to
            # match version or value.
            problems.append(f"{shown_a} and {shown_b} declare the same Docker network name across production/e2e")
            continue

        if sa.version != sb.version:
            # A dual-stack network (enable_ipv6: true) legitimately pins one
            # IPv4 and one IPv6 config entry under the same name -- that is
            # not two conflicting subnets on one network, and the two
            # families can never overlap on the wire either way.
            continue

        if same_explicit_name:
            # One Docker network declared by two files in the same family (a
            # base and its overlay). Not a collision -- but the two must then
            # pin the SAME subnet, or whichever project creates the network
            # first silently wins.
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
    entries = [(p, key, name, net) for p in ALL_COMPOSE_FILES() for key, name, net in _pinned_subnets(p)]
    assert len(entries) >= 2, "fewer than two pinned subnets -- this guard would pass vacuously"
    problems = _find_subnet_overlaps(entries)
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


def test_find_subnet_overlaps_does_not_trust_interpolated_names_as_equal():
    """Two files spelling the identical `${VAR:-default}` expression are not
    provably the same runtime network, so the "same name -> safe" shortcut
    must not apply -- this falls through to the plain overlap check, which
    flags identical subnets like any other pair this function cannot prove
    is the same network."""
    a = REPO_ROOT / "a.compose.yaml"
    b = REPO_ROOT / "b.compose.yaml"
    entries: list[_SubnetEntry] = [
        (a, "shadowsocks", "${SHADOWSOCKS_NETWORK:-shadowsocks}", ipaddress.ip_network("10.99.0.0/29")),
        (b, "shadowsocks", "${SHADOWSOCKS_NETWORK:-shadowsocks}", ipaddress.ip_network("10.99.0.0/29")),
    ]
    problems = _find_subnet_overlaps(entries)
    assert len(problems) == 1
    assert "overlaps" in problems[0]


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


# Host ports ===========================================================================================================
def parse_published_ports(entries: list, *, where: str) -> list[tuple[str | None, int, str]]:
    """(host_ip, host_port, protocol) for each entry of one service's `ports:` list.

    Handles Compose's short string form (`[[IP:]HOST:]CONTAINER[/PROTO]`) and
    the long mapping form. Every other form -- a bare container port, an
    `IP::CONTAINER` ephemeral publish, a port range, a bracketed IPv6 host IP,
    an ephemeral `0` host port -- is rejected loudly rather than skipped or
    mis-parsed. All of them DO publish something on the host, so silently
    dropping one would make the guards below pass vacuously on exactly the
    entry they exist to catch. `protocol` defaults to `"tcp"` (Compose's own
    default) and is kept alongside the port because TCP and UDP occupy
    independent port namespaces -- two entries with the same number but
    different protocol do not actually collide.

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
            host_ip, spec = entry.get("host_ip"), str(published)
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
            host_ip, spec = (None, parts[0]) if len(parts) == 2 else (parts[0], parts[1])
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
        port = int(spec)
        assert port != 0, (
            f"{where}: ports entry {entry!r} has host port 0, Compose's other spelling of an ephemeral "
            "publish -- extend this parser"
        )
        found.append((host_ip, port, protocol))
    return found


def _published_host_ports(path: Path) -> list[tuple[str, str | None, int, str]]:
    """(service, host_ip, host_port, protocol) for every port a compose file publishes."""
    found = []
    for service, cfg in (load_compose(path).get("services") or {}).items():
        # `ports: !reset []` (compose.gateway.yaml) loads as None via ComposeLoader.
        entries = (cfg or {}).get("ports") or []
        for host_ip, port, protocol in parse_published_ports(entries, where=f"{_rel(path)} service {service!r}"):
            found.append((service, host_ip, port, protocol))
    return found


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
    assert parse_published_ports(["80:80/tcp"], where="t") == [(None, 80, "tcp")]
    assert parse_published_ports(["127.0.0.1:8443:443/tcp"], where="t") == [("127.0.0.1", 8443, "tcp")]
    assert parse_published_ports(["53:53/udp"], where="t") == [(None, 53, "udp")]
    assert parse_published_ports([{"host_ip": "127.0.0.1", "published": 2525, "target": 25}], where="t") == \
        [("127.0.0.1", 2525, "tcp")]
    assert parse_published_ports([{"published": 53, "target": 53, "protocol": "udp"}], where="t") == \
        [(None, 53, "udp")]


def test_parse_published_ports_normalizes_protocol_case():
    """Verified against `docker compose config`: Compose lowercases an
    uppercase short-form protocol suffix ("TCP" -> "tcp") but passes a
    long-form `protocol:` value through as-is. This parser lowercases both
    forms, or a long-form "TCP" would look disjoint from a short-form "tcp"
    on the same port to the collision guard, even though Compose treats them
    as the same bind."""
    assert parse_published_ports(["25:25/TCP"], where="t") == [(None, 25, "tcp")]
    assert parse_published_ports([{"published": 25, "target": 25, "protocol": "TCP"}], where="t") == \
        [(None, 25, "tcp")]


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
        {"published": 25, "target": 25, "protocol": "sctpx"},  # long form, unrecognized protocol
        {"published": 0, "target": 25},  # long form, ephemeral host port spelled as 0
    ]
)
def test_parse_published_ports_rejects_unsupported_forms(entry):
    """Each of these publishes something on the host that the parser cannot
    represent. Rejecting loudly is the point: a silent skip would exempt the
    entry from the collision and loopback guards, which is the failure this
    module exists to prevent. Tested directly rather than through a compose
    file, so the branches stay covered no matter what the repo's files contain.
    """
    with pytest.raises(AssertionError):
        parse_published_ports([entry], where="t")


def test_e2e_publishes_no_host_port_production_publishes():
    """Two processes cannot bind the same (host port, protocol). Binding
    loopback is not a way out: production publishes on 0.0.0.0, which already
    owns 127.0.0.1 on that port. So the e2e (port, protocol) pair must be
    disjoint from production's, independently of the interface. TCP and UDP
    are compared separately -- they occupy independent kernel port namespaces,
    so the same number on different protocols does not collide."""
    production = {(port, proto)
                  for path in PRODUCTION_COMPOSE_FILES()
                  for _, _, port, proto in _published_host_ports(path)}
    e2e = [(path, svc, port, proto) for path in E2E_COMPOSE_FILES()
           for svc, _, port, proto in _published_host_ports(path)]
    assert production, "no production compose file publishes a host port -- this guard would pass vacuously"
    assert e2e, "no e2e compose file publishes a host port -- this guard would pass vacuously"
    problems = [
        f"{_rel(path)}: service {svc!r} publishes host port {port}/{proto}" for path, svc, port, proto in e2e
        if (port, proto) in production
    ]
    assert not problems, (
        f"E2e compose files must not publish a host port production publishes ({sorted(production)}) -- "
        "the two stacks share one host and the second bind fails:\n" + "\n".join(f"  {p}" for p in problems)
    )


def test_e2e_published_host_ports_bind_loopback():
    """Every e2e host port is a fixture channel, never a service. Binding
    0.0.0.0 on a VPS (which is exactly where e2e-mta-real runs) exposes a test
    MTA with a test DKIM key to the internet, and reserves the port on every
    interface for a stack that only ever needs it from localhost. Checked as
    an actual loopback address, not the literal string "127.0.0.1", so a
    (currently hypothetical) IPv6 `::1` publish is judged correctly instead of
    being flagged alongside a real 0.0.0.0 exposure."""
    problems = []
    for path in E2E_COMPOSE_FILES():
        for service, host_ip, port, protocol in _published_host_ports(path):
            if not _is_loopback(host_ip):
                where = host_ip or "0.0.0.0 (all interfaces)"
                problems.append(f"{_rel(path)}: service {service!r} publishes host port {port}/{protocol} on {where}")
    assert not problems, (
        "E2e compose files must publish host ports on a loopback address only:\n" +
        "\n".join(f"  {p}" for p in problems)
    )


def test_is_loopback_accepts_ipv6_and_rejects_bare_and_malformed():
    assert _is_loopback("127.0.0.1") is True
    assert _is_loopback("::1") is True
    assert _is_loopback(None) is False
    assert _is_loopback("0.0.0.0") is False
    assert _is_loopback("not-an-ip") is False


# Documentation literals ===============================================================================================
def _mta_submit_subnet(path: Path) -> str:
    for key, _, net in _pinned_subnets(path):
        if key == SUBMIT_ALIAS:
            return str(net)
    raise AssertionError(f"{_rel(path)}: no {SUBMIT_ALIAS} subnet pinned")


def test_docs_quote_the_current_e2e_mta_submit_subnets_and_port():
    """CLAUDE.md's co-location bullet and docs/development/testing.md both
    quote production's and the e2e overlays' subnets, plus the real-mode host
    port, in prose. Nothing else pins those numbers against the compose
    files -- CLAUDE.md sits outside test_docs.py's MUST_KEEP_CODE scan
    (DOCS_DIR is docs/ only). Without this, `test_pinned_subnet_inventory_
    is_complete` and `test_production_mta_submit_subnet_is_the_documented_
    literal` would force a future subnet move to update the *tests*, but the
    prose in these two files could still go stale silently."""
    production_subnet = production_mta_submit_subnet()
    e2e_mta_subnet = _mta_submit_subnet(E2E_COMPOSE_DIR / "e2e-mta.compose.yaml")
    e2e_mta_real_subnet = _mta_submit_subnet(E2E_COMPOSE_DIR / "e2e-mta-real.compose.yaml")
    # host_ip is part of the documented literal too, not just the port -- a
    # hardcoded "127.0.0.1" here would let the overlay's actual publish IP
    # drift from the docs while this guard stayed green.
    mta_ports = [(host_ip, port)
                 for svc, host_ip, port, _ in _published_host_ports(E2E_COMPOSE_DIR / "e2e-mta-real.compose.yaml")
                 if svc == "mta"]
    assert mta_ports == [("127.0.0.1", 2525)], f"e2e-mta-real.compose.yaml mta host ports changed: {mta_ports!r}"
    real_mode_port_literal = f"{mta_ports[0][0]}:{mta_ports[0][1]}"

    claude_md = (REPO_ROOT / "CLAUDE.md").read_text(encoding="utf-8")
    testing_md = (REPO_ROOT / "docs" / "development" / "testing.md").read_text(encoding="utf-8")
    for literal in (production_subnet, e2e_mta_subnet, e2e_mta_real_subnet, real_mode_port_literal):
        assert literal in claude_md, f"CLAUDE.md no longer quotes {literal!r} -- update its co-location bullet"
        assert literal in testing_md, f"docs/development/testing.md no longer quotes {literal!r}"
