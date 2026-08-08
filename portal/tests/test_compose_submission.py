"""Regression tests for issue #151: built-in-MTA submission must route through
the `mta-submit` network alias, not the bare (multi-homed) `mta` name.

A multi-homed `mta`/`postern-mta` service name resolves to its default-network
IP under Docker's embedded DNS, putting the portal's submission source outside
Postfix's mynetworks (the internal /29) -> Postfix rejects with 554 5.7.1.
The fix: the mta service carries a network-scoped alias `mta-submit` on the
mta-submit network and SMTP_HOST points at that alias. These tests pin that
config across the production compose file and the maintainer overlays so it
cannot silently drift back to the bare name. No Docker required.
"""
from __future__ import annotations

import ipaddress
import itertools
from pathlib import Path

import pytest

from ._compose import load_compose
from .e2e._mta_helpers import PRODUCTION_MTA_SUBMIT_SUBNET

# tests/ -> portal/ -> repo root
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SUBMIT_ALIAS = "mta-submit"


def _load_compose(relpath: str) -> dict:
    return load_compose(REPO_ROOT / relpath)


def _mta_submit_aliases(compose: dict) -> list[str]:
    """Aliases declared for the mta service on the mta-submit network.

    Returns [] for the short list form (`networks: [a, b]`), where no alias can
    be expressed -- that is the unfixed shape this test must reject.
    """
    networks = compose["services"]["mta"]["networks"]
    if isinstance(networks, list):
        return []
    cfg = networks.get(SUBMIT_ALIAS) or {}
    return list(cfg.get("aliases", []))


def _env_value(relpath: str, key: str) -> str | None:
    for raw in (REPO_ROOT / relpath).read_text().splitlines():
        line = raw.strip()
        if line.startswith(f"{key}="):
            return line.split("=", 1)[1]
    return None


# Compose inventory ====================================================================================================
# Glob-derived, never a hand-maintained list: a fifth e2e overlay or a new
# production compose file is covered by every guard below the moment it lands
# (same construction as test_e2e_image_isolation.py).
E2E_COMPOSE_DIR = REPO_ROOT / "portal" / "tests" / "e2e"


def _rel(path: Path) -> str:
    return str(path.relative_to(REPO_ROOT))


def PRODUCTION_COMPOSE_FILES() -> list[Path]:
    files = sorted(REPO_ROOT.glob("compose*.yaml"))
    assert files, "no production compose files found -- these guards would pass vacuously"
    return files


def E2E_COMPOSE_FILES() -> list[Path]:
    files = sorted(E2E_COMPOSE_DIR.glob("*.compose.yaml"))
    assert files, f"no *.compose.yaml under {E2E_COMPOSE_DIR} -- these guards would pass vacuously"
    return files


def ALL_COMPOSE_FILES() -> list[Path]:
    return PRODUCTION_COMPOSE_FILES() + E2E_COMPOSE_FILES()


# Production ===========================================================================================================
def test_production_mta_carries_mta_submit_alias():
    aliases = _mta_submit_aliases(_load_compose("compose.yaml"))
    assert SUBMIT_ALIAS in aliases, (
        "compose.yaml mta service must declare aliases:[mta-submit] on the "
        "mta-submit network (issue #151) so SMTP_HOST=mta-submit resolves to the "
        "internal /29 IP inside Postfix mynetworks; got aliases=%r" % aliases
    )


def test_example_env_smtp_host_is_mta_submit_alias():
    value = _env_value("example.env", "SMTP_HOST")
    assert value == SUBMIT_ALIAS, (
        f"example.env SMTP_HOST must be {SUBMIT_ALIAS!r} (issue #151), got {value!r}: "
        "the bare 'mta' name resolves to the default network and fails mynetworks."
    )


def test_production_mta_submit_subnet_is_the_documented_literal():
    """Production's /29 is quoted in CLAUDE.md and is mta/entrypoint.py's
    MTA_SUBMIT_CIDR fallback, so moving it is a cross-repo change, not an edit.

    Deliberately overlaps test_pinned_subnet_inventory_is_complete, which would
    also red on a change here: that one says "a pinned subnet moved, go look",
    this one names the two out-of-repo-tree places that have to move with it.
    The subnet <-> CIDR <-> mynetworks agreement is checked for this file and
    every overlay by test_every_compose_file_agrees_on_its_own_mynetworks_chain.
    """
    assert PRODUCTION_MTA_SUBMIT_SUBNET == "172.30.42.0/29", (
        f"unexpected production mta-submit subnet {PRODUCTION_MTA_SUBMIT_SUBNET!r}"
    )


# Overlays =============================================================================================================
def test_e2e_mta_overlay_uses_submit_alias():
    """The hermetic CI overlay (e2e_mta) already aliases mta and points the
    portal at it. Pinned here so a refactor that drops it fails fast in the unit
    job, not only in the slower Docker e2e_mta job."""
    compose = _load_compose("portal/tests/e2e/e2e-mta.compose.yaml")
    assert SUBMIT_ALIAS in _mta_submit_aliases(compose)
    assert compose["services"]["portal"]["environment"]["SMTP_HOST"] == SUBMIT_ALIAS


def test_e2e_mta_real_overlay_mirrors_production():
    """The maintainer real-delivery overlay (e2e_mta_outbound; VPS-only, never
    in CI) must mirror production or it hits the same #151 bug on modern Docker."""
    compose = _load_compose("portal/tests/e2e/e2e-mta-real.compose.yaml")
    assert SUBMIT_ALIAS in _mta_submit_aliases(compose)
    assert compose["services"]["portal"]["environment"]["SMTP_HOST"] == SUBMIT_ALIAS


# Co-location with a production stack ==================================================================================
# A host can run production and an e2e stack at once (the maintainer's VPS is
# exactly that host). Docker refuses overlapping subnets and the kernel refuses
# a second bind of the same host port, so an e2e stack that claims production's
# subnet or port doesn't degrade -- `compose up` fails outright, or worse, the
# e2e stack wins the race and production's mta can't restart.

# Overlays that deliberately inherit half the submission config from a base file
# (a `mta-submit` network with no MTA_SUBMIT_CIDR, or the reverse). EXEMPT list,
# not an opt-in one: every other compose file must carry both halves, because
# load_compose does no Compose merge and a standalone file missing either half
# silently falls back to mta/entrypoint.py's default CIDR and breaks submission.
_PARTIAL_SUBMISSION_OVERLAYS: frozenset[Path] = frozenset()


def _service_environment(path: Path, service: str) -> dict[str, str]:
    """A service's `environment` as a dict, accepting both Compose forms.

    The mapping form is what this repo uses; the `- KEY=VALUE` list form is
    equally valid Compose and would otherwise crash every glob-derived guard in
    this module with an AttributeError the moment a new file used it.
    """
    env = ((load_compose(path).get("services") or {}).get(service) or {}).get("environment")
    if env is None:
        return {}
    if isinstance(env, dict):
        return {str(k): str(v) for k, v in env.items()}
    assert isinstance(env, list), f"{_rel(path)}: service {service!r} environment is {type(env).__name__}"
    out = {}
    for item in env:
        key, sep, value = str(item).partition("=")
        assert sep, f"{_rel(path)}: service {service!r} environment entry {item!r} has no '='"
        out[key] = value
    return out


def _pinned_subnet_of(net: dict | None) -> str | None:
    """The first IPAM-pinned subnet of a network block, or None if it pins none.

    Tolerates every partial shape (`ipam:` absent, `config:` empty) rather than
    raising KeyError/IndexError -- an overlay that re-opens a network only to
    set `internal: true` is legal Compose, not a configuration error.
    """
    for entry in (((net or {}).get("ipam") or {}).get("config") or []):
        subnet = (entry or {}).get("subnet")
        if subnet is not None:
            return subnet
    return None


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
        rel = _rel(path)
        net = (load_compose(path).get("networks") or {}).get(SUBMIT_ALIAS)
        cidr = _service_environment(path, "mta").get("MTA_SUBMIT_CIDR")
        subnet = _pinned_subnet_of(net)
        if subnet is None and cidr is None:
            continue
        if path in _PARTIAL_SUBMISSION_OVERLAYS:
            continue
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
        # subnet is not None (just asserted) only when _pinned_subnet_of found a
        # config entry on `net`, so `net` itself can't be None here -- spelled
        # out for ty, which can't see that cross-function invariant.
        assert net is not None
        assert net.get("internal") is True, f"{rel}: {SUBMIT_ALIAS} network must be internal: true"
        assert cidr == subnet, (
            f"{rel}: MTA_SUBMIT_CIDR ({cidr!r}) != {SUBMIT_ALIAS} subnet ({subnet!r}). "
            "mynetworks and opendkim TrustedHosts are both rendered from MTA_SUBMIT_CIDR, "
            "so a mismatch silently breaks submission or DKIM signing."
        )
        checked.append(rel)
    assert set(checked) == {
        "compose.yaml",
        "portal/tests/e2e/e2e-mta.compose.yaml",
        "portal/tests/e2e/e2e-mta-real.compose.yaml",
    }, f"unexpected set of submission-configuring compose files: {checked!r}"


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
        ("portal/tests/e2e/e2e-mta.compose.yaml", "default", "172.30.99.0/24"),
        ("portal/tests/e2e/e2e-mta.compose.yaml", "mta-submit", "10.234.43.0/29"),
        ("portal/tests/e2e/e2e-mta-real.compose.yaml", "mta-submit", "10.234.44.0/29"),
    }, f"the set of IPAM-pinned subnets changed: {sorted(inventory)!r}"


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
    problems = []
    for (pa, ka, na, sa), (pb, kb, nb, sb) in itertools.combinations(entries, 2):
        shown_a = f"{_rel(pa)} {ka} ({na or '<project-derived>'}) {sa}"
        shown_b = f"{_rel(pb)} {kb} ({nb or '<project-derived>'}) {sb}"
        if na is not None and na == nb:
            # One Docker network declared by two files (a base and its overlay).
            # Not a collision -- but the two must then pin the SAME subnet, or
            # whichever project creates the network first silently wins.
            if sa != sb:
                problems.append(f"{shown_a} and {shown_b} are the same Docker network with different subnets")
            continue
        if sa.overlaps(sb):
            problems.append(f"{shown_a} overlaps {shown_b}")
    assert not problems, (
        "Compose files must not pin overlapping subnets -- a production stack and an e2e "
        "stack share one Docker daemon and one address space:\n" + "\n".join(f"  {p}" for p in problems)
    )


def parse_published_ports(entries: list, *, where: str) -> list[tuple[str | None, int]]:
    """(host_ip, host_port) for each entry of one service's `ports:` list.

    Handles Compose's short string form (`[[IP:]HOST:]CONTAINER[/PROTO]`) and
    the long mapping form. Every other form -- a bare container port, an
    `IP::CONTAINER` ephemeral publish, a port range, a bracketed IPv6 host IP --
    is rejected loudly rather than skipped or mis-parsed. All of them DO publish
    something on the host, so silently dropping one would make the guards below
    pass vacuously on exactly the entry they exist to catch.

    Split out from `_published_host_ports` and given an explicit `where` label so
    it can be unit-tested on synthetic entries; the repo's own compose files
    exercise only the two supported forms.
    """
    found = []
    for entry in entries:
        if isinstance(entry, dict):
            published = entry.get("published")
            assert published is not None, f"{where}: long-form ports entry {entry!r} has no `published`; " \
                                          "Docker picks an ephemeral host port -- extend this parser"
            host_ip, spec = entry.get("host_ip"), str(published)
        else:
            spec = str(entry).split("/", 1)[0]
            assert "[" not in spec, f"{where}: bracketed IPv6 host IP in {entry!r}; extend this parser"
            parts = spec.split(":")
            assert len(parts) in (2, 3), (
                f"{where}: ports entry {entry!r} is not `HOST:CONTAINER` or `IP:HOST:CONTAINER`. "
                "A bare container port publishes on an ephemeral 0.0.0.0 host port -- extend this parser"
            )
            host_ip, spec = (None, parts[0]) if len(parts) == 2 else (parts[0], parts[1])
        assert spec.isdigit(), (
            f"{where}: ports entry {entry!r} has host port {spec!r}, not a plain number. "
            "Ranges and empty (ephemeral) host ports both land here -- extend this parser"
        )
        found.append((host_ip, int(spec)))
    return found


def _published_host_ports(path: Path) -> list[tuple[str, str | None, int]]:
    """(service, host_ip, host_port) for every port a compose file publishes."""
    found = []
    for service, cfg in (load_compose(path).get("services") or {}).items():
        # `ports: !reset []` (compose.gateway.yaml) loads as None via ComposeLoader.
        entries = (cfg or {}).get("ports") or []
        for host_ip, port in parse_published_ports(entries, where=f"{_rel(path)} service {service!r}"):
            found.append((service, host_ip, port))
    return found


def test_parse_published_ports_accepts_both_supported_forms():
    """The two forms the repo actually uses, on synthetic input -- the guards
    below only ever see whatever the compose files happen to contain today."""
    assert parse_published_ports(["80:80/tcp"], where="t") == [(None, 80)]
    assert parse_published_ports(["127.0.0.1:8443:443/tcp"], where="t") == [("127.0.0.1", 8443)]
    assert parse_published_ports([{"host_ip": "127.0.0.1", "published": 2525, "target": 25}], where="t") == \
        [("127.0.0.1", 2525)]


@pytest.mark.parametrize(
    "entry",
    [
        "3000",  # bare container port: ephemeral host port on 0.0.0.0
        "127.0.0.1::25",  # ephemeral host port, bound to an interface
        "8000-8010:8000-8010",  # range
        "[::1]:25:25",  # bracketed IPv6 host IP
        {"target": 25},  # long form, no `published`
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
    """Two processes cannot bind the same host port. Binding loopback is not a
    way out: production publishes on 0.0.0.0, which already owns 127.0.0.1 on
    that port. So the e2e port *numbers* must be disjoint from production's,
    independently of the interface."""
    production = {port for path in PRODUCTION_COMPOSE_FILES() for _, _, port in _published_host_ports(path)}
    e2e = [(path, svc, port) for path in E2E_COMPOSE_FILES() for svc, _, port in _published_host_ports(path)]
    assert production, "no production compose file publishes a host port -- this guard would pass vacuously"
    assert e2e, "no e2e compose file publishes a host port -- this guard would pass vacuously"
    problems = [
        f"{_rel(path)}: service {svc!r} publishes host port {port}" for path, svc, port in e2e if port in production
    ]
    assert not problems, (
        f"E2e compose files must not publish a host port production publishes ({sorted(production)}) -- "
        "the two stacks share one host and the second bind fails:\n" + "\n".join(f"  {p}" for p in problems)
    )


def test_e2e_published_host_ports_bind_loopback():
    """Every e2e host port is a fixture channel, never a service. Binding
    0.0.0.0 on a VPS (which is exactly where e2e-mta-real runs) exposes a test
    MTA with a test DKIM key to the internet, and reserves the port on every
    interface for a stack that only ever needs it from localhost."""
    problems = []
    for path in E2E_COMPOSE_FILES():
        for service, host_ip, port in _published_host_ports(path):
            if host_ip != "127.0.0.1":
                where = host_ip or "0.0.0.0 (all interfaces)"
                problems.append(f"{_rel(path)}: service {service!r} publishes host port {port} on {where}")
    assert not problems, (
        "E2e compose files must publish host ports on 127.0.0.1 only:\n" + "\n".join(f"  {p}" for p in problems)
    )
