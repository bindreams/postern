"""Structure test for the reference gateway passthrough router (compose.gateway.yaml).

postern-nginx's :443 socket has proxy_protocol on (from the portal vhost), so every
:443 connection -- including the mta-sts vhost -- must arrive with a PROXY header.
The postern Traefik router prepends PROXY-v2; any SNI it does NOT claim falls through
to the gateway's catch-all HostSNI(*) router (no PROXY header) and nginx drops it.
This test pins the router's HostSNI set to the public server_name vhosts nginx serves,
so adding an nginx vhost without updating the router fails CI instead of silently
reintroducing the drop. No Docker required."""
from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


class _ComposeLoader(yaml.SafeLoader):
    """SafeLoader that tolerates Docker Compose's `!reset` merge tag. Only
    compose.gateway.yaml uses it (on `ports`, which this test never inspects);
    plain yaml.safe_load raises on the unknown tag. Subclassed so the constructor
    stays local -- it does not mutate the shared yaml.SafeLoader."""


_ComposeLoader.add_constructor("!reset", lambda loader, node: None)


def _nginx_public_snis() -> set[str]:
    """Public :443 server_name vhosts nginx serves, keyed by the ${DOMAIN} placeholder.
    Only names containing ${DOMAIN} count -- the default_server (server_name `_`) and
    the localhost health vhost are internal and never routed to by SNI."""
    files = [REPO_ROOT / "nginx/etc/nginx.conf.tmpl", *sorted(REPO_ROOT.glob("nginx/etc/conf.d/*.conf.tmpl"))]
    snis: set[str] = set()
    for f in files:
        for m in re.finditer(r"server_name\s+([^;]+);", f.read_text()):
            snis.update(name for name in m.group(1).split() if "${DOMAIN}" in name)
    return snis


def _router_hostsni_set() -> set[str]:
    """The SNIs the router claims, one per `HostSNI(`x`)` matcher. Traefik's HostSNI
    takes a SINGLE value, so multiple SNIs must be OR-combined -- `HostSNI(`a`) ||
    HostSNI(`b`)`, never `HostSNI(`a`, `b`)` (a Traefik parse error that silently
    drops the whole router). Matching each matcher individually enforces that form:
    the comma variant yields zero matches and fails the caller."""
    compose = yaml.load((REPO_ROOT / "compose.gateway.yaml").read_text(), Loader=_ComposeLoader)
    rule = compose["services"]["nginx"]["labels"]["traefik.tcp.routers.postern.rule"]
    snis = set(re.findall(r"HostSNI\(`([^`]+)`\)", rule))
    assert snis, f"router must use one-value HostSNI(`x`) matchers (OR-combined with ||); got {rule!r}"
    return snis


def test_gateway_router_claims_exactly_the_nginx_vhosts():
    nginx_snis = _nginx_public_snis()
    assert nginx_snis, "parsed no ${DOMAIN} server_name vhosts from nginx templates -- parser drift?"
    assert "mta-sts.${DOMAIN}" in nginx_snis  # guard the parser actually sees the mta-sts vhost
    assert _router_hostsni_set() == nginx_snis, (
        "the gateway router's HostSNI set must exactly match nginx's public :443 vhosts; "
        "add any new server_name vhost to compose.gateway.yaml's router rule too"
    )
