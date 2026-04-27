"""DNS record rendering + verification for the built-in MTA.

`expected_records()` produces the canonical strings the deployer must publish.
`verify()` resolves and checks each one, returning a list of failure messages
(empty list on pass).
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass

import dns.exception
import dns.flags
import dns.rdatatype
import dns.resolver
import dns.reversename

logger = logging.getLogger(__name__)


# Public API ===========================================================================================================
def expected_records(
    domain: str,
    dkim_pubkey_by_selector: dict[str, str],
    *,
    admin_email: str,
    server_ip: str | None = None,
    nginx_ip: str | None = None,
    mta_sts_id: str | None = None,
) -> dict[str, list[str]]:
    """Return the canonical DNS records the deployer must publish.

    Keys are short labels (`MX`, `SPF`, `DMARC`, ...); values are list of zone-file lines.
    `dkim_pubkey_by_selector` maps active selector name -> base64 public key.
    During rotation overlap, this dict has two entries; otherwise one.
    """
    records: dict[str, list[str]] = {}

    records["MX"] = [f"{domain}.\tIN MX\t10 mail.{domain}."]

    a_lines = []
    if server_ip:
        a_lines.append(f"mail.{domain}.\tIN A\t{server_ip}")
    else:
        a_lines.append(f"mail.{domain}.\tIN A\t<your-server-ip>")
    if nginx_ip:
        a_lines.append(f"mta-sts.{domain}.\tIN A\t{nginx_ip}")
    else:
        a_lines.append(f"mta-sts.{domain}.\tIN A\t<your-nginx-ip>")
    records["A"] = a_lines

    if server_ip:
        try:
            ptr_name = dns.reversename.from_address(server_ip).to_text()
            records["PTR"] = [f"{ptr_name}\tIN PTR\tmail.{domain}."]
        except dns.exception.DNSException:
            records["PTR"] = [f"<reverse-of-{server_ip}>\tIN PTR\tmail.{domain}."]
    else:
        records["PTR"] = [f"<reverse-of-server-ip>\tIN PTR\tmail.{domain}."]

    records["SPF"] = [f'{domain}.\tIN TXT\t"v=spf1 mx -all"']

    admin_for_dmarc = admin_email or f"postmaster@{domain}"
    records["DMARC"] = [
        f'_dmarc.{domain}.\tIN TXT\t'
        f'"v=DMARC1; p=reject; adkim=s; aspf=s; '
        f'rua=mailto:{admin_for_dmarc}; ruf=mailto:{admin_for_dmarc}"'
    ]

    sts_id = mta_sts_id or "<unix-ts-or-version>"
    records["MTA-STS"] = [f'_mta-sts.{domain}.\tIN TXT\t"v=STSv1; id={sts_id}"']

    admin_for_tlsrpt = admin_email or f"tls-rpt@{domain}"
    records["TLS-RPT"] = [f'_smtp._tls.{domain}.\tIN TXT\t"v=TLSRPTv1; rua=mailto:{admin_for_tlsrpt}"']

    dkim_lines = []
    for selector, pubkey in sorted(dkim_pubkey_by_selector.items()):
        dkim_lines.append(f'{selector}._domainkey.{domain}.\tIN TXT\t'
                          f'"v=DKIM1; k=rsa; p={pubkey}"')
    if not dkim_lines:
        dkim_lines.append(
            f"<selector>._domainkey.{domain}.\tIN TXT\t"
            f'"v=DKIM1; k=rsa; p=<base64-pubkey> (run `postern mta show-dns` after first deploy)"'
        )
    records["DKIM"] = dkim_lines

    return records


def verify(
    domain: str,
    dkim_pubkey_by_selector: dict[str, str],
    *,
    admin_email: str,
    server_ip: str | None = None,
    nginx_ip: str | None = None,
    require_dnssec: bool = False,
    resolver: dns.resolver.Resolver | None = None,
) -> list[str]:
    """Verify every required record is published correctly. Returns failure messages, [] on pass."""
    r = resolver if resolver is not None else dns.resolver.Resolver()
    failures: list[str] = []

    failures.extend(_check_mx(r, domain))
    resolved_ip = _check_a_and_get_ip(r, f"mail.{domain}", failures, expected_ip=server_ip)
    if resolved_ip is not None:
        failures.extend(_check_ptr(r, resolved_ip, expected=f"mail.{domain}."))
    _check_a_and_get_ip(r, f"mta-sts.{domain}", failures, expected_ip=nginx_ip)
    failures.extend(_check_spf(r, domain))
    failures.extend(_check_dmarc(r, domain))
    failures.extend(_check_mta_sts(r, domain))
    failures.extend(_check_tls_rpt(r, domain))
    for selector, pubkey in dkim_pubkey_by_selector.items():
        failures.extend(_check_dkim(r, domain, selector, pubkey))

    if require_dnssec:
        failures.extend(_check_dnssec_ad_bit(r, domain))

    return failures


# Per-record checks ----------------------------------------------------------------------------------------------------
def _check_mx(resolver: dns.resolver.Resolver, domain: str) -> list[str]:
    expected = f"mail.{domain}."
    try:
        ans = resolver.resolve(domain, "MX")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return [f"MX {domain}: no record (expected `10 {expected}`)"]
    except dns.exception.DNSException as e:
        return [f"MX {domain}: lookup failed ({e})"]
    targets = sorted(str(r.exchange).lower() for r in ans)
    if expected.lower() not in targets:
        return [f"MX {domain}: got {targets}, expected {expected!r}"]
    return []


def _check_a_and_get_ip(
    resolver: dns.resolver.Resolver,
    name: str,
    failures: list[str],
    *,
    expected_ip: str | None,
) -> str | None:
    try:
        ans = resolver.resolve(name, "A")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        failures.append(f"A {name}: no record")
        return None
    except dns.exception.DNSException as e:
        failures.append(f"A {name}: lookup failed ({e})")
        return None
    ips = sorted(str(r.address) for r in ans)
    if expected_ip is not None and expected_ip not in ips:
        failures.append(f"A {name}: got {ips}, expected {expected_ip!r}")
    return ips[0] if ips else None


def _check_ptr(resolver: dns.resolver.Resolver, ip: str, *, expected: str) -> list[str]:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return [f"PTR {ip}: not a valid IP"]
    rev = dns.reversename.from_address(str(addr))
    try:
        ans = resolver.resolve(rev, "PTR")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return [f"PTR {ip}: no record (expected {expected!r})"]
    except dns.exception.DNSException as e:
        return [f"PTR {ip}: lookup failed ({e})"]
    targets = sorted(str(r.target).lower() for r in ans)
    if expected.lower() not in targets:
        return [f"PTR {ip}: got {targets}, expected {expected!r}"]
    return []


def _check_spf(resolver: dns.resolver.Resolver, domain: str) -> list[str]:
    txts = _resolve_txt(resolver, domain)
    if txts is None:
        return [f"SPF {domain}: no TXT record"]
    spf = next((t for t in txts if t.lower().startswith("v=spf1")), None)
    if spf is None:
        return [f'SPF {domain}: no "v=spf1 ..." TXT (expected "v=spf1 mx -all")']
    if "-all" not in spf.lower():
        return [f'SPF {domain}: {spf!r} lacks "-all" (got softfail or other)']
    if " mx" not in spf.lower() and " ip4:" not in spf.lower() and " ip6:" not in spf.lower():
        return [f'SPF {domain}: {spf!r} has no mx/ip4/ip6 mechanism']
    return []


def _check_dmarc(resolver: dns.resolver.Resolver, domain: str) -> list[str]:
    txts = _resolve_txt(resolver, f"_dmarc.{domain}")
    if txts is None:
        return [f"DMARC _dmarc.{domain}: no TXT record"]
    dmarc = next((t for t in txts if t.lower().startswith("v=dmarc1")), None)
    if dmarc is None:
        return [f"DMARC _dmarc.{domain}: no v=DMARC1 TXT"]
    failures: list[str] = []
    fields = {kv.split("=", 1)[0].strip().lower(): kv.split("=", 1)[1].strip() for kv in dmarc.split(";") if "=" in kv}
    if fields.get("p") != "reject":
        failures.append(f"DMARC _dmarc.{domain}: p={fields.get('p')!r}, expected p=reject")
    if fields.get("adkim", "r") != "s":
        failures.append(f"DMARC _dmarc.{domain}: adkim={fields.get('adkim', 'r')!r}, expected adkim=s")
    if fields.get("aspf", "r") != "s":
        failures.append(f"DMARC _dmarc.{domain}: aspf={fields.get('aspf', 'r')!r}, expected aspf=s")
    return failures


def _check_mta_sts(resolver: dns.resolver.Resolver, domain: str) -> list[str]:
    txts = _resolve_txt(resolver, f"_mta-sts.{domain}")
    if txts is None:
        return [f"MTA-STS _mta-sts.{domain}: no TXT record"]
    sts = next((t for t in txts if t.lower().startswith("v=stsv1")), None)
    if sts is None:
        return [f"MTA-STS _mta-sts.{domain}: no v=STSv1 TXT"]
    if "id=" not in sts.lower():
        return [f"MTA-STS _mta-sts.{domain}: missing id= field"]
    failures: list[str] = []
    try:
        with urllib.request.urlopen(  # noqa: S310 - https only by URL scheme below
            f"https://mta-sts.{domain}/.well-known/mta-sts.txt",
            timeout=10,
        ) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
        failures.append(f"MTA-STS https://mta-sts.{domain}/.well-known/mta-sts.txt: fetch failed ({e})")
        return failures
    if "version: STSv1" not in body:
        failures.append(f"MTA-STS policy file: no `version: STSv1` line")
    if "mode: enforce" not in body:
        failures.append(f"MTA-STS policy file: mode is not `enforce`")
    if f"mx: mail.{domain}" not in body:
        failures.append(f"MTA-STS policy file: no `mx: mail.{domain}` line")
    return failures


def _check_tls_rpt(resolver: dns.resolver.Resolver, domain: str) -> list[str]:
    txts = _resolve_txt(resolver, f"_smtp._tls.{domain}")
    if txts is None:
        return [f"TLS-RPT _smtp._tls.{domain}: no TXT record"]
    rpt = next((t for t in txts if t.lower().startswith("v=tlsrptv1")), None)
    if rpt is None:
        return [f"TLS-RPT _smtp._tls.{domain}: no v=TLSRPTv1 TXT"]
    if "rua=" not in rpt.lower():
        return [f"TLS-RPT _smtp._tls.{domain}: no rua= field"]
    return []


def _check_dkim(resolver: dns.resolver.Resolver, domain: str, selector: str, expected_pubkey: str) -> list[str]:
    name = f"{selector}._domainkey.{domain}"
    txts = _resolve_txt(resolver, name)
    if txts is None:
        return [f"DKIM {name}: no TXT record"]
    dkim = next((t for t in txts if "v=DKIM1" in t), None)
    if dkim is None:
        return [f"DKIM {name}: no v=DKIM1 TXT"]
    fields = dict(_parse_dkim_fields(dkim))
    got_p = fields.get("p", "").replace(" ", "").replace("\t", "")
    expected_p = expected_pubkey.replace(" ", "").replace("\t", "").replace("\n", "")
    if got_p != expected_p:
        return [f"DKIM {name}: published p= does not match local pubkey"]
    return []


def _check_dnssec_ad_bit(resolver: dns.resolver.Resolver, domain: str) -> list[str]:
    """Send a query and check the AD bit. Caller must use a validating resolver."""
    try:
        msg = resolver.resolve(domain, "SOA").response
    except dns.exception.DNSException as e:
        return [f"DNSSEC {domain}: SOA lookup failed ({e})"]
    if not (msg.flags & dns.flags.AD):
        return [
            f"DNSSEC {domain}: AD bit not set on SOA response. "
            f"Either domain is not signed or resolver is not validating."
        ]
    return []


# Helpers --------------------------------------------------------------------------------------------------------------
def _resolve_txt(resolver: dns.resolver.Resolver, name: str) -> list[str] | None:
    try:
        ans = resolver.resolve(name, "TXT")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return None
    except dns.exception.DNSException as e:
        logger.warning("TXT %s: lookup error %s", name, e)
        return None
    out: list[str] = []
    for r in ans:
        # dnspython returns each TXT record as a list of byte strings; concat per-record.
        out.append(b"".join(r.strings).decode("utf-8", errors="replace"))
    return out


def _parse_dkim_fields(txt: str) -> list[tuple[str, str]]:
    """Parse a DKIM TXT record body into (key, value) pairs."""
    pairs = []
    for token in txt.split(";"):
        token = token.strip()
        if "=" not in token:
            continue
        k, v = token.split("=", 1)
        pairs.append((k.strip(), v.strip()))
    return pairs
