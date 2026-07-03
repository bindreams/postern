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

from pathlib import Path

import yaml

# tests/ -> portal/ -> repo root
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SUBMIT_ALIAS = "mta-submit"


def _load_compose(relpath: str) -> dict:
    return yaml.safe_load((REPO_ROOT / relpath).read_text())


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


def test_mta_submit_network_pins_the_mynetworks_chain():
    """The alias only lands the portal *inside* mynetworks if the whole chain
    agrees: the mta-submit network is internal, uses the /29, AND MTA_SUBMIT_CIDR
    (which renders Postfix's `mynetworks`) equals that subnet. A subnet that
    drifts from the CIDR keeps the alias resolving but silently fails submission,
    so pin all three together (cf. the path-token chain pinned elsewhere)."""
    compose = _load_compose("compose.yaml")
    net = compose["networks"]["mta-submit"]
    assert net.get("internal") is True, "mta-submit network must be internal: true"
    subnet = net["ipam"]["config"][0]["subnet"]
    assert subnet == "172.30.42.0/29", f"unexpected mta-submit subnet {subnet!r}"
    cidr = compose["services"]["mta"]["environment"]["MTA_SUBMIT_CIDR"]
    assert cidr == subnet, (
        f"MTA_SUBMIT_CIDR ({cidr!r}) must equal the mta-submit subnet ({subnet!r}); "
        "mynetworks is derived from MTA_SUBMIT_CIDR, so a mismatch breaks submission."
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
