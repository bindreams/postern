"""DNSSEC AD-bit verification.

Two consumers:
- The mta container's entrypoint, which uses the local Unbound on 127.0.0.1.
- The portal CLI (`postern mta dnssec-status`), which has no local Unbound.
  The portal uses external validating resolvers (1.1.1.1, 9.9.9.9, 8.8.8.8)
  with explicit DO/AD flag checking, and requires consensus across at least two.
"""

from __future__ import annotations

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdatatype

PUBLIC_VALIDATING_RESOLVERS = ("1.1.1.1", "9.9.9.9", "8.8.8.8")


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
