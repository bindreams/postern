"""Enable-gate + tick dispatcher for the provisioner's combined loop.

Pure, importable logic extracted out of `provisioner/entrypoint.py` (which is
not importable in the portal test env because it pulls in `postern_mta`). The
entrypoint builds the per-subsystem tick callables and hands them here; this
module decides which run.

`edge_enabled` means the *Cloudflare* edge profile specifically. The generic
edge profile is realized entirely in nginx (realip from an operator-provided
header) and involves no provisioner action -- no CF IP-range fetch, no proxied
DNS -- so it deliberately does not flip any flag here.

`mta_deployed` is an EXPLICIT input, not inferred from DNS_PROVIDER. The
built-in MTA runs under the `with-mta` compose profile; a Cloudflare edge
deployment also sets `DNS_PROVIDER=cloudflare` but need not deploy the MTA. So
"DNS provider configured" is NOT "MTA deployed" -- conflating them would make an
edge-only deployment publish mail/mta-sts records for a domain with no mail
server. The caller derives `mta_deployed` from `COMPOSE_PROFILES` (see
`mta_deployed_from_profiles`); compose injects `COMPOSE_PROFILES` into the
provisioner so the value can't drift from the active profile set.
"""
from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass

# Fixed dispatch order so logs across ticks stay deterministic.
_TICK_ORDER = ("dkim", "cert", "dns", "mta_records", "edge")

# COMPOSE_PROFILES is comma-separated per the compose spec; we also tolerate
# whitespace separators so a hand-edited value still parses.
_PROFILE_SEP = re.compile(r"[,\s]+")


@dataclass(frozen=True)
class Enablement:
    """Which provisioner subsystems run this deployment."""
    dkim_enabled: bool  # DKIM key rotation state machine (MTA deployed AND a DNS provider)
    cert_enabled: bool  # ACME cert renewal state machine (CERT_RENEWAL=true)
    mta_enabled: bool  # MX/SPF/DMARC/MTA-STS/TLS-RPT/TLSA + mail/mta-sts A/AAAA publisher
    dns_enabled: bool  # apex/wildcard/mail/mta-sts A/AAAA + CAA publisher
    edge_enabled: bool  # Cloudflare edge: IP-range refresh + proxied apex/mta-sts


def mta_deployed_from_profiles(compose_profiles: str) -> bool:
    """True iff the `with-mta` profile is present in a COMPOSE_PROFILES string.

    Exact-token match (case-insensitive), so a profile whose name merely
    contains `with-mta` (e.g. `with-mta-experimental`) does not count."""
    tokens = {t.lower() for t in _PROFILE_SEP.split(compose_profiles or "") if t}
    return "with-mta" in tokens


def compute_enablement(*, dns_provider: str, cert_renewal: bool, edge_profile: str, mta_deployed: bool) -> Enablement:
    """Derive the enablement matrix from raw env values (case/space-insensitive)."""
    provider = (dns_provider or "none").strip().lower()
    profile = (edge_profile or "none").strip().lower()

    have_provider = provider != "none"
    edge = profile == "cloudflare"
    cert = bool(cert_renewal)
    # DKIM rotation and the MTA records publisher are both MTA subsystems: they
    # need the MTA deployed AND a provider to publish through (postern-dns exits
    # non-zero under DNS_PROVIDER=none). Same gate for both.
    mta = have_provider and mta_deployed
    dkim = mta
    # The A/AAAA/CAA publisher needs a usable provider AND at least one consumer:
    # cert issuance (apex+wildcard+CAA), a CF edge profile (proxied apex), or the
    # MTA's mail host (mail A). Without a provider, postern-dns fails -- so never
    # enable the publisher then.
    dns = have_provider and (cert or edge or mta)

    return Enablement(
        dkim_enabled=dkim,
        cert_enabled=cert,
        mta_enabled=mta,
        dns_enabled=dns,
        edge_enabled=edge,
    )


def run_enabled_ticks(enablement: Enablement, ticks: Mapping[str, Callable[[], None]]) -> None:
    """Invoke each subsystem's tick callable exactly when its flag is set, in a
    fixed order. Pure dispatch: all env/state access lives inside the callables."""
    flags = {
        "dkim": enablement.dkim_enabled,
        "cert": enablement.cert_enabled,
        "dns": enablement.dns_enabled,
        "mta_records": enablement.mta_enabled,
        "edge": enablement.edge_enabled,
    }
    for name in _TICK_ORDER:
        if flags[name]:
            ticks[name]()
