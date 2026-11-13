"""Front-side ECH verification: does the apex HTTPS record carry an ech= SvcParam?

Used by `postern ech verify`/`show` and `postern connection add --ech always` (portal
CLI only; the provisioner does not run it and its image ships no DoH backend). Queries
the apex HTTPS record (type 65) over DoH -- so the lookup itself is encrypted -- and
inspects the ech SvcParam (SvcParamKey 5). Credential-free: needs no Cloudflare token.
Requires the dnspython[doh] backend (h2/httpcore2/httpx2); see portal/pyproject.toml.
"""
from __future__ import annotations

import logging
import urllib.parse
from typing import Literal

import dns.exception
import dns.inet
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.wire
from dns.rdtypes.svcbbase import ParamKey

logger = logging.getLogger(__name__)

EchFrontStatus = Literal["present", "absent", "inconclusive"]

_ECH_PARAM_KEY = int(ParamKey.ECH)


# Public API ===========================================================================================================
def check_apex_ech(domain: str, doh_url: str, *, timeout: float = 5.0) -> EchFrontStatus:
    """Report whether the apex HTTPS record serves an ech= SvcParam. Never raises.

    - "present": an HTTPS record carries a usable ech param.
    - "absent": an HTTPS record resolved but none carries a usable ech config: no ech
      param, or an empty / malformed one. dnspython >= 2.9 rejects a whole reply over
      such a param (or over any other bad SvcParam), so that case is classified from
      the raw reply instead (`_classify_unparsed`).
    - "inconclusive": no HTTPS record yet (propagation), DoH unreachable, or a reply that
      does not answer this query, is unreadable (not a DNS message, truncated) or is bad
      outside its HTTPS records. Callers treat this as "unknown", never as a confirmed
      failure.
    """
    # One try covers the exchange, the parse and the SvcParam loop: a dnspython
    # version whose HTTPS rdata shape differs from _has_ech_param's assumption
    # must degrade to "inconclusive", not propagate (contract: never raises).
    try:
        query = dns.message.make_query(dns.name.from_text(domain), dns.rdatatype.HTTPS)
        bodies: list[bytes] = []
        try:
            reply = _query_doh(query, doh_url, timeout, bodies)
        except dns.query.BadResponse as e:
            logger.warning("ech: %s: reply does not answer our query (%s); inconclusive", domain, e)
            return "inconclusive"
        except dns.exception.DNSException as e:
            if not bodies:  # not a parse failure: the exchange itself failed
                raise
            logger.debug("ech: %s reply rejected by dnspython (%s); classifying from the raw reply", domain, e)
            return _classify_unparsed(query, bodies[-1])
        rrs = _https_rrs(reply)
        if not rrs:
            logger.debug("ech: %s: reply has no HTTPS records (rcode=%s); inconclusive", domain, reply.rcode())
            return "inconclusive"
        return "present" if any(_has_ech_param(rr) for rr in rrs) else "absent"
    except (dns.query.NoDOH, _DohUnavailable) as e:
        # A LOST DoH backend (h2/httpcore2 dropped) or a changed dnspython transport makes
        # every check inconclusive -- a systemic regression, not an ordinary blip. Log loudly.
        logger.error(
            "ech: DoH backend unavailable (%s) -- install the dnspython[doh] extra; ECH checks are degraded", e
        )
        return "inconclusive"
    except Exception as e:  # ordinary DoH transport/timeout, or a parse-shape surprise.
        logger.warning("ech: DoH check for %s failed, result inconclusive: %r", domain, e)
        return "inconclusive"


# Internal =============================================================================================================
class _DohUnavailable(Exception):
    """dnspython's DoH transport cannot be built (a private class that changed or vanished)."""


def _query_doh(query: dns.message.Message, doh_url: str, timeout: float, bodies: list[bytes]) -> dns.message.Message:
    """Send `query` with dns.query.https over dnspython's own transport (so its
    resolver/bootstrap apply), with trust_env=False on transport and client so
    SSL_CERT_FILE/SSL_CERT_DIR and HTTP(S)_PROXY are ignored. A response hook appends
    each raw body to `bodies` so a reply dnspython refuses to parse can still be read."""
    if not dns.query.have_doh:
        raise dns.query.NoDOH
    import httpx2

    def keep_body(response: httpx2.Response) -> None:
        response.read()
        bodies.append(response.content)

    host = urllib.parse.urlparse(doh_url).hostname
    bootstrap_address = host if host and dns.inet.is_address(host) else None
    try:
        transport = dns.query._HTTPTransport(
            http1=True, http2=True, trust_env=False, bootstrap_address=bootstrap_address
        )
    except (AttributeError, TypeError) as e:
        raise _DohUnavailable(f"dnspython's DoH transport cannot be built: {e!r}") from e
    with httpx2.Client(
        http1=True, http2=True, transport=transport, trust_env=False, event_hooks={"response": [keep_body]}
    ) as session:
        return dns.query.https(query, doh_url, timeout=timeout, session=session)


def _https_rrs(message: dns.message.Message) -> list:
    """The HTTPS records in the reply's answer section."""
    return [rr for rrset in message.answer if rrset.rdtype == dns.rdatatype.HTTPS for rr in rrset]


def _has_ech_param(rr) -> bool:
    """True if the HTTPS record's SvcParams include an ech (key 5).

    dnspython keys `rr.params` by the numeric SvcParamKey (its int-enum compares
    equal to 5). A parsed record that has the key carries a usable ech (dnspython
    rejects empty/malformed ones at parse time).

    Direct attribute access (`.params`) is DELIBERATE: a dnspython shape change that
    renamed it raises AttributeError, which check_apex_ech's outer try/except maps to
    "inconclusive" rather than a false confirmed "absent". A getattr-with-default
    would swallow that and mis-report absence. The params-keyed-by-5 assumption is
    pinned by the real-rdata test."""
    return _ECH_PARAM_KEY in rr.params


# Generic reply classification -----------------------------------------------------------------------------------------
def _classify_unparsed(query: dns.message.Message, wire: bytes) -> EchFrontStatus:
    """Classify a reply dnspython refused to parse, re-read with `continue_on_error`.
    "absent" if dnspython rejected a record of an answer HTTPS RRset (the client discards
    the whole RRset); a reply bad elsewhere, or with broken framing, is "inconclusive"."""
    verdict, reason = _verdict_for_unparsed(query, wire)
    logger.debug("ech: unparsed reply classified %s: %s", verdict, reason)
    return verdict


def _verdict_for_unparsed(query: dns.message.Message, wire: bytes) -> tuple[EchFrontStatus, str]:
    try:
        message = dns.message.from_wire(wire, continue_on_error=True)
        if not query.is_response(message):
            return "inconclusive", "reply does not answer the query"
        spans = _answer_https_spans(wire)  # framing first: a broken reply proves nothing
        owners = _answer_owner_names(message, query.question[0].name)
        for owner, start, end in spans:
            if owner in owners and any(start <= error.offset <= end for error in message.errors):
                return "absent", "dnspython rejected a record of the answer HTTPS RRset"
        if any(_has_ech_param(rr) for rr in _https_rrs(message)):
            return "present", "an HTTPS record carries ech and no answer HTTPS record was rejected"
        return "inconclusive", "the reply is bad outside the answer HTTPS RRset"
    except dns.exception.DNSException as e:  # includes FormError from the framing walk
        logger.warning("ech: reply is unreadable (%s); inconclusive", e)
        return "inconclusive", f"reply is unreadable: {e}"


def _answer_owner_names(message: dns.message.Message, qname: dns.name.Name) -> set[dns.name.Name]:
    """Owner names of the HTTPS RRset the query resolves to: the question name plus every
    CNAME target reachable from it through the answer section."""
    cnames = {rrset.name: rr.target for rrset in message.answer if rrset.rdtype == dns.rdatatype.CNAME for rr in rrset}
    owners = {qname}
    name = qname
    while name in cnames and cnames[name] not in owners:
        name = cnames[name]
        owners.add(name)
    return owners


def _answer_https_spans(wire: bytes) -> list[tuple[dns.name.Name, int, int]]:
    """(owner, start, end) of the rdata of each HTTPS record in the answer section. Walks
    every record in every section, so broken framing anywhere, or trailing bytes, raises
    FormError. That makes a record's end offset unambiguous: no framing error can be
    reported there."""
    parser = dns.wire.Parser(wire)
    _id, _flags, questions, answers, authority, additional = parser.get_struct("!6H")
    for _ in range(questions):
        parser.get_name(decompress=True)
        parser.get_struct("!HH")
    spans = []
    for index in range(answers + authority + additional):
        owner = parser.get_name(decompress=True)
        rrtype, _rdclass, _ttl, length = parser.get_struct("!HHIH")
        start = parser.current
        parser.get_bytes(length)
        if index < answers and rrtype == dns.rdatatype.HTTPS:
            spans.append((owner, start, start + length))
    if parser.remaining():
        raise dns.exception.FormError("trailing data after the last record")
    return spans
