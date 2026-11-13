"""Front-side ECH verification: does the apex HTTPS record carry an ech= SvcParam?

Used by `postern ech verify`/`show` and `postern connection add --ech always` (portal
CLI only; the provisioner does not run it and its image ships no DoH backend). Queries
the apex HTTPS record (type 65) over DoH -- so the lookup itself is encrypted -- and
inspects the ech SvcParam (SvcParamKey 5). Credential-free: needs no Cloudflare token.
Requires the dnspython[doh] backend (h2/httpcore2/httpx2); see portal/pyproject.toml.
"""
from __future__ import annotations

import logging
import struct
from typing import Literal

import dns.exception
import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdatatype
from dns.rdtypes.svcbbase import ECHParam, ParamKey

logger = logging.getLogger(__name__)

EchFrontStatus = Literal["present", "absent", "inconclusive"]

_ECH_PARAM_KEY = int(ParamKey.ECH)


class _Unreadable(ValueError):
    """The DNS wire does not have the shape the generic walk expects."""


# Public API ===========================================================================================================
def check_apex_ech(domain: str, doh_url: str, *, timeout: float = 5.0) -> EchFrontStatus:
    """Report whether the apex HTTPS record serves an ech= SvcParam. Never raises.

    - "present": an HTTPS record carries a usable ech param.
    - "absent": an HTTPS record resolved but none carries a usable ech config: no ech
      param, or an empty / malformed one. dnspython >= 2.9 rejects a whole reply over
      such a param (or over any other bad SvcParam), so that case is classified from
      the raw reply instead (`_classify_unparsed`). The front is not serving ECH.
    - "inconclusive": no HTTPS record yet (propagation), DoH unreachable, or a reply that
      is unreadable (not a DNS message, truncated) or bad outside its HTTPS records.
      Callers treat this as "unknown", never as a confirmed failure.
    """
    # One try covers the exchange, the parse and the SvcParam loop: a dnspython
    # version whose HTTPS rdata shape differs from _has_ech_param's assumption
    # must degrade to "inconclusive", not propagate (contract: never raises).
    try:
        wire = _fetch_wire(domain, doh_url, timeout)
        try:
            rrs = _parse_https_rrs(wire)
        except dns.exception.DNSException as e:
            logger.debug("ech: %s reply rejected by dnspython (%s); classifying from the raw reply", domain, e)
            return _classify_unparsed(wire)
        if not rrs:
            return "inconclusive"
        return "present" if any(_has_ech_param(rr) for rr in rrs) else "absent"
    except dns.query.NoDOH as e:
        # A LOST DoH backend (h2/httpcore2 dropped) makes every check inconclusive --
        # a systemic regression, not an ordinary blip. Log loudly so it is visible.
        logger.error(
            "ech: DoH backend unavailable (%s) -- install the dnspython[doh] extra; ECH checks are degraded", e
        )
        return "inconclusive"
    except Exception as e:  # ordinary DoH transport/timeout, or a parse-shape surprise.
        logger.debug("ech: DoH check for %s failed: %s", domain, e)
        return "inconclusive"


# Internal =============================================================================================================
def _fetch_wire(domain: str, doh_url: str, timeout: float) -> bytes:
    """POST the apex HTTPS query to `doh_url` (RFC 8484) and return the reply wire.

    Raises on transport errors, a non-2xx status, or a body that is not a reply to
    this query (caller maps to inconclusive). The wire is returned unparsed so a
    reply dnspython refuses can still be read generically."""
    if not dns.query.have_doh:
        raise dns.query.NoDOH
    import httpx2
    query = dns.message.make_query(dns.name.from_text(domain), dns.rdatatype.HTTPS)
    with httpx2.Client(http2=True) as client:
        response = client.post(
            doh_url,
            headers={"accept": "application/dns-message", "content-type": "application/dns-message"},
            content=query.to_wire(),
            timeout=timeout,
        )
    if not 200 <= response.status_code <= 299:
        raise ValueError(f"{doh_url} responded with status code {response.status_code}")
    wire = response.content
    if len(wire) < 12 or wire[:2] != struct.pack("!H", query.id) or not wire[2] & 0x80:
        raise ValueError("not a DNS reply to the query")
    return wire


def _parse_https_rrs(wire: bytes) -> list:
    """The HTTPS records in the reply's answer section. Raises DNSException if
    dnspython rejects any part of the reply."""
    resp = dns.message.from_wire(wire)
    return [rr for rrset in resp.answer if rrset.rdtype == dns.rdatatype.HTTPS for rr in rrset]


def _has_ech_param(rr) -> bool:
    """True if the HTTPS record's SvcParams include an ech (key 5).

    dnspython keys `rr.params` by the numeric SvcParamKey (its int-enum compares
    equal to 5). dnspython >= 2.9 refuses to parse an empty or malformed ech, so a
    parsed record that has the key carries a usable one.

    Direct attribute access (`.params`) is DELIBERATE: a dnspython shape change that
    renamed it raises AttributeError, which check_apex_ech's outer try/except maps to
    "inconclusive" rather than a false confirmed "absent". A getattr-with-default
    would swallow that and mis-report absence. The params-keyed-by-5 assumption is
    pinned by the real-rdata test."""
    return _ECH_PARAM_KEY in rr.params


# Generic reply classification -----------------------------------------------------------------------------------------
def _classify_unparsed(wire: bytes) -> EchFrontStatus:
    """Classify a reply dnspython refused to parse, from its raw bytes.

    Walks the message with RFC 1035 framing only, then reads each answer HTTPS record's
    SvcParams directly:
    - "present" if any record carries a usable ech (e.g. beside an unrelated bad param);
    - "inconclusive" if the framing is broken anywhere (not a DNS message, truncated) or
      a record's SvcParams cannot be walked to look for ech;
    - "absent" only if dnspython rejects at least one HTTPS record on its own, which
      pins the failure on SvcParam content, and no record has a usable ech. A reply
      that is bad elsewhere (say a malformed A record) explains nothing about ech."""
    try:
        spans = _answer_https_spans(wire)
        failure_is_in_an_https_record = False
        unwalkable = False
        for offset, length in spans:
            try:
                dns.rdata.from_wire(dns.rdataclass.IN, dns.rdatatype.HTTPS, wire, offset, length)
            except dns.exception.DNSException:
                failure_is_in_an_https_record = True
            try:
                value = _raw_ech_value(wire, offset, length)
            except _Unreadable:
                unwalkable = True
                continue
            if value is not None and _is_usable_ech(value):
                return "present"
        if unwalkable or not failure_is_in_an_https_record:
            return "inconclusive"
        return "absent"
    except _Unreadable:
        return "inconclusive"


def _skip_name(wire: bytes, pos: int) -> int:
    """Offset just past the (possibly compressed) domain name at `pos`."""
    while True:
        if pos >= len(wire):
            raise _Unreadable("name runs past the message")
        label = wire[pos]
        if label == 0:
            return pos + 1
        if label & 0xC0 == 0xC0:
            if pos + 2 > len(wire):
                raise _Unreadable("compression pointer runs past the message")
            return pos + 2
        if label & 0xC0:
            raise _Unreadable("reserved label type")
        pos += 1 + label


def _answer_https_spans(wire: bytes) -> list[tuple[int, int]]:
    """(rdata offset, rdata length) of each HTTPS record in the answer section, after
    checking the framing of every record in every section."""
    if len(wire) < 12:
        raise _Unreadable("shorter than a DNS header")
    questions, answers, authority, additional = struct.unpack_from("!4H", wire, 4)
    pos = 12
    for _ in range(questions):
        pos = _skip_name(wire, pos) + 4
        if pos > len(wire):
            raise _Unreadable("question runs past the message")
    spans = []
    for index in range(answers + authority + additional):
        pos = _skip_name(wire, pos)
        if pos + 10 > len(wire):
            raise _Unreadable("record header runs past the message")
        rrtype, _rdclass, _ttl, length = struct.unpack_from("!HHIH", wire, pos)
        pos += 10
        if pos + length > len(wire):
            raise _Unreadable("rdata runs past the message")
        if index < answers and rrtype == dns.rdatatype.HTTPS:
            spans.append((pos, length))
        pos += length
    return spans


def _raw_ech_value(wire: bytes, offset: int, length: int) -> bytes | None:
    """The value of SvcParamKey 5 in the HTTPS rdata at wire[offset:offset+length], or
    None if it has none. Raises _Unreadable if the SvcParams do not frame cleanly."""
    end = offset + length
    pos = offset + 2  # SvcPriority
    pos = _skip_name(wire, pos)  # TargetName
    value = None
    while pos < end:
        if pos + 4 > end:
            raise _Unreadable("SvcParam header runs past the record")
        key, size = struct.unpack_from("!HH", wire, pos)
        pos += 4
        if pos + size > end:
            raise _Unreadable("SvcParam value runs past the record")
        if key == _ECH_PARAM_KEY:
            value = wire[pos:pos + size]
        pos += size
    if pos != end:
        raise _Unreadable("TargetName runs past the record")
    return value


def _is_usable_ech(value: bytes) -> bool:
    """True if `value` is an ECHConfigList dnspython itself would accept."""
    try:
        ECHParam(value)
    except ValueError:
        return False
    return True
