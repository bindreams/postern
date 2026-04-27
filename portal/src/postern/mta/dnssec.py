"""DNSSEC AD-bit verification.

Two consumers:
- The mta container's entrypoint, which uses the local Unbound on 127.0.0.1.
- The portal CLI (`postern mta dnssec-status`), which has no local Unbound.
  The portal uses external validating resolvers (1.1.1.1, 9.9.9.9, 8.8.8.8)
  with explicit DO/AD flag checking, and requires consensus across at least two.
"""

from __future__ import annotations

import logging
import time
from typing import Literal

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.resolver

logger = logging.getLogger(__name__)

PUBLIC_VALIDATING_RESOLVERS = ("1.1.1.1", "9.9.9.9", "8.8.8.8")

_TRUE_STRINGS = frozenset({"true", "1", "yes", "on"})
_FALSE_STRINGS = frozenset({"false", "0", "no", "off"})
_AUTO_STRINGS = frozenset({"auto", ""})


# Public API ===========================================================================================================
def check(domain: str, *, resolvers: tuple[str, ...] = PUBLIC_VALIDATING_RESOLVERS) -> list[str]:
    """Return failure messages, [] on pass.

    Queries the SOA for ``domain`` against multiple validating resolvers and
    requires at least two of them to set the AD bit. Single-resolver consensus
    is too easy to spoof (e.g., a hostile transit operator MITMing one of them).
    """
    results: list[tuple[str, bool, str | None]] = []
    for ip in resolvers:
        ok, err = _query_with_ad(domain, ip)
        results.append((ip, ok, err))

    ad_count = sum(1 for _, ok, _ in results if ok)
    if ad_count >= 2:
        return []

    failures = [
        f"DNSSEC {domain}: insufficient consensus across validating resolvers "
        f"(AD bit set on {ad_count} of {len(resolvers)})."
    ]
    for ip, ok, err in results:
        if ok:
            failures.append(f"  {ip}: AD bit set")
        elif err is not None:
            failures.append(f"  {ip}: {err}")
        else:
            failures.append(f"  {ip}: AD bit NOT set (zone unsigned, or resolver not validating)")
    return failures


def parse_setting(raw: object) -> bool | Literal["auto"]:
    """Normalize an env-var or programmatic input to ``bool | "auto"``.

    Accepts bool, str (case-insensitive: true/false/1/0/yes/no/on/off/auto/empty),
    or None (-> "auto"). Raises ``ValueError`` on anything else.
    """
    if isinstance(raw, bool):
        return raw
    if raw is None:
        return "auto"
    if isinstance(raw, str):
        normalized = raw.strip().lower()
        if normalized in _TRUE_STRINGS:
            return True
        if normalized in _FALSE_STRINGS:
            return False
        if normalized in _AUTO_STRINGS:
            return "auto"
        raise ValueError(f"invalid MTA_REQUIRE_DNSSEC value {raw!r}; expected one of: auto, true, false")
    raise ValueError(f"invalid MTA_REQUIRE_DNSSEC type {type(raw).__name__}; expected bool, str, or None")


def resolve_required(
    setting: bool | Literal["auto"],
    domain: str,
    *,
    resolver: dns.resolver.Resolver | None = None,
    deadline_s: float = 30.0,
    poll_interval_s: float = 0.5,
) -> bool:
    """Resolve the tri-state MTA_REQUIRE_DNSSEC setting to a concrete bool.

    - ``True`` / ``False``: pass through (no DNS calls).
    - ``"auto"`` + ``resolver`` given (validating local Unbound): poll SOA AD bit
      until a definitive answer or ``deadline_s`` elapses; ``True`` iff AD set.
    - ``"auto"`` + ``resolver=None``: use :func:`check` public consensus;
      ``True`` iff ``check()`` returns no failures.

    On indeterminate / errored probes returns ``False`` with a logged warning.
    The runtime DANE validation done by Unbound on outbound mail is unaffected
    by this return value -- this only gates the *startup safety check*.
    """
    if setting is True or setting is False:
        return setting
    if resolver is not None:
        return _resolve_local(domain, resolver, deadline_s=deadline_s, poll_interval_s=poll_interval_s)
    return _resolve_external(domain)


# Internal =============================================================================================================
def _query_with_ad(domain: str, resolver_ip: str, *, timeout: float = 5.0) -> tuple[bool, str | None]:
    name = dns.name.from_text(domain)
    q = dns.message.make_query(name, dns.rdatatype.SOA, want_dnssec=True)
    q.flags |= dns.flags.AD
    try:
        resp = dns.query.udp(q, resolver_ip, timeout=timeout)
    except dns.exception.Timeout:
        return (False, "timeout")
    except dns.exception.DNSException as e:
        return (False, f"query error ({e})")
    return (bool(resp.flags & dns.flags.AD), None)


def _resolve_local(
    domain: str,
    resolver: dns.resolver.Resolver,
    *,
    deadline_s: float,
    poll_interval_s: float,
) -> bool:
    """Auto-detect via a single validating resolver, retrying on transient errors.

    Unbound may answer SERVFAIL on the very first SOA query if its trust chain
    is still warming. We retry until we either get a definitive AD-set or
    AD-unset answer, or the deadline elapses.
    """
    deadline = time.monotonic() + deadline_s
    last_error: dns.exception.DNSException | None = None
    while True:
        try:
            ans = resolver.resolve(domain, "SOA")
        except dns.exception.DNSException as e:
            last_error = e
            if time.monotonic() >= deadline:
                logger.warning(
                    "DNSSEC auto-detect: SOA lookup for %s failed (%s). Not enforcing this run.",
                    domain,
                    last_error,
                )
                return False
            time.sleep(poll_interval_s)
            continue
        if ans.response.flags & dns.flags.AD:
            logger.info(
                "DNSSEC auto-detect: %s is signed (AD bit set on local Unbound). Enforcing.",
                domain,
            )
            return True
        logger.warning(
            "DNSSEC auto-detect: %s is unsigned (AD bit not set). Not enforcing -- "
            "this is fine for unsigned domains, but consider enabling DNSSEC at your "
            "registrar for tamper-evident DKIM/MTA-STS.",
            domain,
        )
        return False


def _resolve_external(domain: str) -> bool:
    """Auto-detect via the public-resolver consensus check."""
    failures = check(domain)
    if not failures:
        logger.info(
            "DNSSEC auto-detect: %s is signed (consensus across %d public validators). Enforcing.",
            domain,
            len(PUBLIC_VALIDATING_RESOLVERS),
        )
        return True
    detail = "\n".join(failures)
    logger.warning("DNSSEC auto-detect: insufficient consensus. Not enforcing.\n%s", detail)
    return False
