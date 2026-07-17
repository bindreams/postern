"""Front-side ECH verification: does the apex HTTPS record carry an ech= SvcParam?

Shared by `postern ech verify`/`show` (portal CLI) and the provisioner's zone-ECH
reconciler (a non-gating serving check). Queries the apex HTTPS record (type 65)
over DoH -- so the lookup itself is encrypted -- and inspects the ech SvcParam
(SvcParamKey 5). Credential-free: needs no Cloudflare token. Requires the
dnspython[doh] backend (h2/httpcore/httpx); see portal/pyproject.toml.
"""
from __future__ import annotations

import logging
from typing import Literal

import dns.message
import dns.name
import dns.query
import dns.rdatatype

logger = logging.getLogger(__name__)

EchFrontStatus = Literal["present", "absent", "inconclusive"]

# SvcParamKey for the ECH config (RFC 9460 / SVCB-ECH): key 5.
_ECH_PARAM_KEY = 5


# Public API ===========================================================================================================
def check_apex_ech(domain: str, doh_url: str, *, timeout: float = 5.0) -> EchFrontStatus:
    """Report whether the apex HTTPS record serves an ech= SvcParam. Never raises.

    - "present": an HTTPS record exists and carries a non-empty ech param.
    - "absent": an HTTPS record resolved but has no ech param (front not serving ECH).
    - "inconclusive": no HTTPS record yet (propagation), DoH unreachable, or any
      query/parse error. Callers treat this as "unknown", never as a confirmed failure.
    """
    # One try covers BOTH the query and the SvcParam parse loop: a dnspython
    # version whose HTTPS rdata shape differs from _has_ech_param's assumption
    # must degrade to "inconclusive", not propagate (contract: never raises).
    try:
        rrs = _query_https_rrs(domain, doh_url, timeout)
        if rrs is None:
            return "inconclusive"
        for rr in rrs:
            if _has_ech_param(rr):
                return "present"
        return "absent"
    except dns.query.NoDOH as e:
        # A LOST DoH backend (h2/httpcore dropped) makes every check inconclusive --
        # a systemic regression, not an ordinary blip. Log loudly so it is visible.
        logger.error(
            "ech: DoH backend unavailable (%s) -- install the dnspython[doh] extra; ECH checks are degraded", e
        )
        return "inconclusive"
    except Exception as e:  # ordinary DoH transport/timeout, or a parse-shape surprise.
        logger.debug("ech: DoH check for %s failed: %s", domain, e)
        return "inconclusive"


# Internal =============================================================================================================
def _query_https_rrs(domain: str, doh_url: str, timeout: float):
    """Return the HTTPS records for `domain` fetched over DoH, or None if none
    resolved. Raises on transport/timeout/parse errors (caller maps to inconclusive)."""
    name = dns.name.from_text(domain)
    q = dns.message.make_query(name, dns.rdatatype.HTTPS)
    resp = dns.query.https(q, doh_url, timeout=timeout)
    rrs = [rr for rrset in resp.answer if rrset.rdtype == dns.rdatatype.HTTPS for rr in rrset]
    return rrs or None


def _has_ech_param(rr) -> bool:
    """True if the HTTPS record's SvcParams include a non-empty ech (key 5).

    dnspython keys `rr.params` by the numeric SvcParamKey (its int-enum compares
    equal to 5); the ech value object carries the wire bytes on `.ech`. An empty
    `ech=""` param is "absent" per the spec, so an empty `.ech` is not present.

    Direct attribute access (`.params`/`.ech`) is DELIBERATE: a dnspython shape
    change that renamed either raises AttributeError, which check_apex_ech's outer
    try/except maps to "inconclusive" rather than a false confirmed "absent". A
    getattr-with-default would swallow that and mis-report absence. The
    params-keyed-by-5 and ech-bytes assumptions are pinned by the real-rdata test."""
    val = rr.params.get(_ECH_PARAM_KEY)
    if val is None:
        return False
    return bool(val.ech)
