"""Map Postern's libdns-style provider env vars to Lego's CLI env vars.

Postern's existing DKIM rotation uses libdns-style env var names (e.g.
``CLOUDFLARE_API_TOKEN``); Lego occasionally uses different names for the
same provider (e.g. ``CLOUDFLARE_DNS_API_TOKEN``). This module is a pure
function: given the operator's env, produce Lego's env + ``--dns`` slug.

The ``pebble`` provider is for the e2e test environment only; it routes
through Lego's ``--dns exec`` mode + a small bash hook script that POSTs
to pebble-challtestsrv's HTTP API.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass


@dataclass
class LegoConfig:
    dns_slug: str  # value for `lego --dns <slug>`
    env: dict[str, str]  # additional env vars Lego needs (set in addition to inherited env)


# Provider env-var translations ========================================================================================
# Each entry: postern_name -> (dns_slug, fn_to_translate_env). The fn returns
# {} if the libdns-side credentials are missing -- we want Lego to surface
# its own clearer "missing credential" error rather than us pre-empting it.
def _cloudflare(env: dict[str, str]) -> dict[str, str]:
    token = env.get("CLOUDFLARE_API_TOKEN", "")
    return {"CLOUDFLARE_DNS_API_TOKEN": token} if token else {}


def _route53(env: dict[str, str]) -> dict[str, str]:
    # Lego reads the same AWS_* vars natively; pass them through unchanged.
    out: dict[str, str] = {}
    for k in ("AWS_REGION", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
        if k in env:
            out[k] = env[k]
    return out


def _gandi(env: dict[str, str]) -> dict[str, str]:
    token = env.get("GANDI_API_TOKEN", "")
    return {"GANDIV5_PERSONAL_ACCESS_TOKEN": token} if token else {}


def _digitalocean(env: dict[str, str]) -> dict[str, str]:
    token = env.get("DO_AUTH_TOKEN", "")
    return {"DO_AUTH_TOKEN": token} if token else {}


def _ovh(env: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for k in ("OVH_ENDPOINT", "OVH_APPLICATION_KEY", "OVH_APPLICATION_SECRET", "OVH_CONSUMER_KEY"):
        if k in env:
            out[k] = env[k]
    return out


def _hetzner(env: dict[str, str]) -> dict[str, str]:
    token = env.get("HETZNER_API_TOKEN", "")
    return {"HETZNER_API_KEY": token} if token else {}


def _linode(env: dict[str, str]) -> dict[str, str]:
    token = env.get("LINODE_TOKEN", "")
    return {"LINODE_TOKEN": token} if token else {}


def _namecheap(env: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for k in ("NAMECHEAP_API_KEY", "NAMECHEAP_API_USER", "NAMECHEAP_CLIENT_IP"):
        if k in env:
            out[k] = env[k]
    return out


def _pebble(env: dict[str, str]) -> dict[str, str]:
    # Lego's `--dns exec` reads the script path from EXEC_PATH.
    return {"EXEC_PATH": env.get("LEGO_EXEC_PATH", "/usr/local/bin/lego-pebble-hook.sh")}


_PROVIDERS: dict[str, tuple[str, Callable[[dict[str, str]], dict[str, str]]]] = {
    "cloudflare": ("cloudflare", _cloudflare),
    "route53": ("route53", _route53),
    "gandi": ("gandiv5", _gandi),
    "digitalocean": ("digitalocean", _digitalocean),
    "ovh": ("ovh", _ovh),
    "hetzner": ("hetzner", _hetzner),
    "linode": ("linodev4", _linode),
    "namecheap": ("namecheap", _namecheap),
    "pebble": ("exec", _pebble),
}


def supported_providers() -> list[str]:
    """Names accepted in DNS_PROVIDER. Excludes the ``pebble`` test sentinel."""
    return [p for p in _PROVIDERS if p != "pebble"]


def lego_config(provider: str, env: dict[str, str]) -> LegoConfig:
    """Translate a Postern provider name + env to a Lego invocation config.

    Raises ValueError on an unknown provider. Does NOT validate that
    credentials are present -- Lego's own error message is clearer than
    anything we could produce here.
    """
    key = provider.strip().lower()
    if key not in _PROVIDERS:
        raise ValueError(f"unknown DNS_PROVIDER {provider!r} (supported: {', '.join(supported_providers())})")
    slug, fn = _PROVIDERS[key]
    return LegoConfig(dns_slug=slug, env=fn(env))
