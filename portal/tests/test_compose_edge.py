"""Structure tests for the Cloudflare/generic edge compose foundation (issue #155).

The provisioner is the sole writer of the CF edge IP-range allowlists on the
`postern-edge` named volume; nginx mounts it read-only and render.sh globs the
*.conf files into both :443 server blocks. These tests pin that wiring -- the
volume, the nginx EDGE_* env, the provisioner `with-edge` profile, and the
`compose.edge.yaml` restart-policy flip -- so it cannot silently drift. No
Docker required (pure PyYAML)."""
from __future__ import annotations

from pathlib import Path

import yaml

# tests/ -> portal/ -> repo root
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
EDGE_VOLUME = "postern-edge"
EDGE_TARGET = "/var/lib/postern-edge"


def _load_compose(relpath: str) -> dict:
    return yaml.safe_load((REPO_ROOT / relpath).read_text())


def _named_mount(service: dict, volume_name: str) -> tuple[str, str] | None:
    """Return (target, mode) for `volume_name` mounted on `service`, else None.

    Handles the short string form (`name:target[:mode]`) and the long mapping
    form (`{type: volume, source, target, read_only}`). `mode` is 'ro' or 'rw'."""
    for entry in service.get("volumes", []):
        if isinstance(entry, str):
            parts = entry.split(":")
            if parts[0] == volume_name:
                target = parts[1] if len(parts) > 1 else ""
                mode = parts[2] if len(parts) > 2 else "rw"
                return target, mode
        elif isinstance(entry, dict) and entry.get("source") == volume_name:
            return entry.get("target", ""), ("ro" if entry.get("read_only") else "rw")
    return None


# Base compose.yaml ====================================================================================================
def test_edge_volume_declared_in_base():
    volumes = _load_compose("compose.yaml")["volumes"]
    assert EDGE_VOLUME in volumes, "compose.yaml must declare the postern-edge named volume"
    assert volumes[EDGE_VOLUME]["name"] == EDGE_VOLUME


def test_nginx_mounts_edge_volume_readonly():
    nginx = _load_compose("compose.yaml")["services"]["nginx"]
    mount = _named_mount(nginx, EDGE_VOLUME)
    assert mount == (EDGE_TARGET, "ro"), (f"nginx must mount {EDGE_VOLUME} read-only at {EDGE_TARGET}; got {mount!r}")


def test_provisioner_mounts_edge_volume_readwrite():
    prov = _load_compose("compose.yaml")["services"]["provisioner"]
    mount = _named_mount(prov, EDGE_VOLUME)
    assert mount is not None and mount[0] == EDGE_TARGET and mount[1] == "rw", (
        f"provisioner must mount {EDGE_VOLUME} read-write at {EDGE_TARGET}; got {mount!r}"
    )


def test_provisioner_is_sole_edge_writer():
    """Only the provisioner may hold postern-edge rw; every other mounter is ro.
    A second rw mounter would break the sole-writer invariant."""
    services = _load_compose("compose.yaml")["services"]
    writers = set()
    for name, svc in services.items():
        mount = _named_mount(svc, EDGE_VOLUME)
        if mount is not None and mount[1] == "rw":
            writers.add(name)
    assert writers == {"provisioner"}, f"expected provisioner as sole rw edge writer, got {writers!r}"


def test_nginx_has_edge_env():
    env = _load_compose("compose.yaml")["services"]["nginx"]["environment"]
    assert env.get("EDGE_PROFILE") == "${EDGE_PROFILE:-none}"
    assert env.get("EDGE_CF_AUTHENTICATED_ORIGIN_PULL") == "${EDGE_CF_AUTHENTICATED_ORIGIN_PULL:-true}"


def test_provisioner_has_with_edge_profile():
    profiles = _load_compose("compose.yaml")["services"]["provisioner"]["profiles"]
    assert "with-edge" in profiles, f"provisioner must join the with-edge profile; got {profiles!r}"


# compose.edge.yaml overlay ============================================================================================
def test_edge_overlay_flips_provisioner_restart():
    prov = _load_compose("compose.edge.yaml")["services"]["provisioner"]
    assert prov["restart"] == "unless-stopped", (
        "compose.edge.yaml must switch the provisioner to restart: unless-stopped -- "
        "the edge reconciler is a long-lived loop and base restart:'no' would not "
        "restart it after a crash (cf. compose.cert.yaml)."
    )


def test_edge_overlay_preserves_activation_profiles():
    """The overlay restates the full profile set so with-edge survives compose
    merge regardless of overlay order. Keep in sync with compose.yaml."""
    base = set(_load_compose("compose.yaml")["services"]["provisioner"]["profiles"])
    overlay = set(_load_compose("compose.edge.yaml")["services"]["provisioner"]["profiles"])
    assert "with-edge" in overlay
    assert overlay == base, f"overlay profiles {overlay!r} must equal base {base!r}"
