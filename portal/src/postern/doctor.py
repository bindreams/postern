"""Operator-prereq verification for postern deployments.

Read-only health check that answers two questions:

  1. Have you set up the things postern cannot publish for you?
       - DS records at the domain registrar (DNSSEC chain).
       - PTR records at the VPS provider (rDNS for `mail.<domain>`).
     Both must be set ONCE per deployment, by hand, in panels postern
     doesn't talk to. Without them, the MTA refuses to start (PTR) or
     DNSSEC validation silently fails (DS) -- both surface only as
     cryptic startup errors.

  2. Are the records postern *does* publish actually live?
       - apex/wildcard A/AAAA + CAA from the cert manager (#116).
       - MX/SPF/DMARC/MTA-STS/TLS-RPT/TLSA + DKIM TXTs from the MTA
         manager (#119) and the DKIM rotation (existing).

Plus a basic connectivity probe (:443/tcp serves a valid TLS cert,
:25/tcp is reachable). Pure-read; no DNS, cert, or rotation state is
mutated. Exits non-zero on any FAIL so it's usable as a bring-up gate
or as a CI smoke step.
"""

from __future__ import annotations

import io
import ipaddress
import json as _json
import socket
import ssl
from dataclasses import asdict, dataclass, field
from typing import Callable, Literal

import dns.exception
import dns.resolver
import dns.reversename

from postern.mta import dns as mta_dns
from postern.mta import dnssec as mta_dnssec
from postern.mta.dns import MtaRecord

Section = Literal["external", "postern-managed", "connectivity"]
Status = Literal["ok", "fail", "skip"]

EXTERNAL: Section = "external"
POSTERN_MANAGED: Section = "postern-managed"
CONNECTIVITY: Section = "connectivity"

# Wide, descriptive label widths so the rendered table reads cleanly. Pinned by
# `test_render_layout_columns_aligned` in [tests/test_doctor.py]; widen here if
# you add a longer label.
_LABEL_W = 40


# Result types =========================================================================================================
@dataclass(frozen=True)
class CheckResult:
    """One row in the doctor's output. Fix hints are required on FAIL so the
    user always has somewhere to look; an OK row's `fix` is empty."""
    section: Section
    label: str
    status: Status
    detail: str = ""
    fix: str = ""


@dataclass
class DoctorReport:
    results: list[CheckResult] = field(default_factory=list)

    @property
    def failures(self) -> list[CheckResult]:
        return [r for r in self.results if r.status == "fail"]

    @property
    def exit_code(self) -> int:
        return 1 if self.failures else 0


# External checks (DS + PTR) ===========================================================================================
def check_ds(domain: str, *, resolvers: tuple[str, ...] = mta_dnssec.PUBLIC_VALIDATING_RESOLVERS) -> CheckResult:
    """DS at the registrar = AD bit set at public validating resolvers.

    Postern cannot publish DS itself (it lives at the TLD parent zone, owned
    by the registrar). If the AD bit isn't set, the operator must enable
    DNSSEC at their DNS provider and copy the DS records to their registrar.
    """
    failures = mta_dnssec.check(domain, resolvers=resolvers)
    if not failures:
        return CheckResult(
            section=EXTERNAL,
            label=f"DS for {domain} at registrar",
            status="ok",
            detail=f"AD bit set on >=2 of {len(resolvers)} public validating resolvers",
        )
    return CheckResult(
        section=EXTERNAL,
        label=f"DS for {domain} at registrar",
        status="fail",
        detail=failures[0],
        fix=(
            "Enable DNSSEC at your DNS provider, then copy the DS records "
            "into your registrar's control panel (search 'DS records' / 'DNSSEC'). "
            "Propagation can take up to 24h."
        ),
    )


def check_ptr(ip: str, *, expected: str, resolver: dns.resolver.Resolver | None = None) -> CheckResult:
    """PTR (rDNS) for `ip` matches `expected`. Owned by the IP-block holder
    (VPS provider), not by the DNS provider. The MTA refuses to start
    without it because forward-confirmed rDNS gates inbound TLS handshakes."""
    r = resolver if resolver is not None else dns.resolver.Resolver()
    label = f"PTR {ip}"
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return CheckResult(
            section=EXTERNAL,
            label=label,
            status="fail",
            detail=f"not a valid IP address: {ip!r}",
            fix="Check PUBLIC_IPV4 / PUBLIC_IPV6 in .env",
        )
    rev = dns.reversename.from_address(str(addr))
    try:
        ans = r.resolve(rev, "PTR")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return CheckResult(
            section=EXTERNAL,
            label=label,
            status="fail",
            detail=f"no PTR record (expected {expected!r})",
            fix=_ptr_fix_hint(ip),
        )
    except dns.exception.DNSException as e:
        return CheckResult(
            section=EXTERNAL,
            label=label,
            status="fail",
            detail=f"PTR lookup failed: {e}",
            fix=_ptr_fix_hint(ip),
        )
    targets = sorted(str(t.target).lower().rstrip(".") + "." for t in ans)
    if expected.lower() not in targets:
        return CheckResult(
            section=EXTERNAL,
            label=label,
            status="fail",
            detail=f"got {targets}, expected {expected!r}",
            fix=_ptr_fix_hint(ip),
        )
    return CheckResult(section=EXTERNAL, label=label, status="ok", detail=f"-> {expected}")


def _ptr_fix_hint(ip: str) -> str:
    family = "IPv6" if ":" in ip else "IPv4"
    return (
        f"Set the {family} PTR (rDNS) record at your VPS provider's control panel. "
        "This lives in the in-addr.arpa / ip6.arpa zones, not the forward zone -- "
        "your DNS provider can't do it; the IP-block holder must."
    )


# Postern-managed checks ===============================================================================================
@dataclass(frozen=True)
class PosternManagedExpectation:
    """One record the doctor will verify against live DNS. Reflects what the
    provisioner's two reconcilers (cert manager + MTA manager) publish."""
    label: str  # e.g. "A    hole.binarydreams.me"
    name: str
    type: str  # A | AAAA | CAA | MX | TXT | TLSA
    expected_content: str  # rendered form for matching on the wire
    fix: str


def build_postern_expectations(
    domain: str,
    *,
    public_ipv4: str,
    public_ipv6: str | None,
    admin_email: str,
    tlsa_cert_hex: str | None,
    dkim_pubkey_by_selector: dict[str, str] | None = None,
) -> list[PosternManagedExpectation]:
    """Compose the set of records the doctor expects to see live in DNS.

    The cert manager (#116) publishes apex/wildcard A/AAAA + CAA.
    The MTA manager (#119) publishes MX/SPF/DMARC/MTA-STS/TLS-RPT and (when
    a cert is on disk) TLSA. DKIM TXTs are published by the rotation state
    machine -- included when `dkim_pubkey_by_selector` is provided.
    """
    out: list[PosternManagedExpectation] = []

    cert_fix = "Wait for the next provisioner tick (~60s) or `docker compose restart provisioner`."
    mta_fix = "Wait for the next provisioner tick; if it persists, check `docker compose logs provisioner`."

    for fqdn in (domain, f"*.{domain}", f"mail.{domain}"):
        out.append(PosternManagedExpectation(
            label=f"A    {fqdn}", name=fqdn, type="A", expected_content=public_ipv4, fix=cert_fix
        ))
        if public_ipv6:
            out.append(PosternManagedExpectation(
                label=f"AAAA {fqdn}", name=fqdn, type="AAAA", expected_content=public_ipv6, fix=cert_fix
            ))
    out.append(PosternManagedExpectation(
        label=f"CAA  {domain}", name=domain, type="CAA",
        expected_content='0 issue "letsencrypt.org"', fix=cert_fix,
    ))

    for rec in mta_dns.expected_records_structured(domain, admin_email=admin_email, tlsa_cert_hex=tlsa_cert_hex):
        out.append(_expectation_from_mta_record(rec, fix=mta_fix))

    for selector, pubkey in (dkim_pubkey_by_selector or {}).items():
        out.append(PosternManagedExpectation(
            label=f"DKIM {selector}._domainkey.{domain}",
            name=f"{selector}._domainkey.{domain}",
            type="TXT",
            expected_content=f"v=DKIM1; k=rsa; p={pubkey}",
            fix="Run `postern mta rotation-status` to inspect the rotation state machine.",
        ))

    return out


def _expectation_from_mta_record(rec: MtaRecord, *, fix: str) -> PosternManagedExpectation:
    if rec.type == "MX":
        priority, target = rec.args
        # `mta_records.parseMXArgs` adds a trailing dot on the wire (#121).
        target = target.rstrip(".") + "."
        return PosternManagedExpectation(
            label=f"MX   {rec.name}", name=rec.name, type="MX",
            expected_content=f"{priority} {target}", fix=fix,
        )
    if rec.type == "TLSA":
        u, s, m, hexv = rec.args
        return PosternManagedExpectation(
            label=f"TLSA {rec.name}", name=rec.name, type="TLSA",
            expected_content=f"{u} {s} {m} {hexv}", fix=fix,
        )
    if rec.type == "TXT":
        return PosternManagedExpectation(
            label=_label_for_mta_txt(rec.name), name=rec.name, type="TXT",
            expected_content=rec.args[0], fix=fix,
        )
    raise ValueError(f"unsupported MtaRecord type: {rec.type}")


def _label_for_mta_txt(name: str) -> str:
    if name.startswith("_dmarc."):
        return f"DMARC {name}"
    if name.startswith("_mta-sts."):
        return f"MTA-STS {name}"
    if name.startswith("_smtp._tls."):
        return f"TLS-RPT {name}"
    return f"SPF  {name}"


def check_postern_record(
    exp: PosternManagedExpectation,
    *,
    resolver: dns.resolver.Resolver | None = None,
) -> CheckResult:
    """Query live DNS for one expected record. Wildcard names (`*.<domain>`)
    are probed via a synthetic sub-name because resolvers don't expand wildcards
    on queries for the literal `*.` name."""
    r = resolver if resolver is not None else dns.resolver.Resolver()
    probe = exp.name if not exp.name.startswith("*.") else f"doctor-probe.{exp.name[2:]}"
    try:
        ans = r.resolve(probe, exp.type, raise_on_no_answer=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return CheckResult(
            section=POSTERN_MANAGED, label=exp.label, status="fail",
            detail=f"no {exp.type} record (expected {exp.expected_content!r})", fix=exp.fix,
        )
    except dns.exception.DNSException as e:
        return CheckResult(
            section=POSTERN_MANAGED, label=exp.label, status="fail",
            detail=f"lookup failed: {e}", fix=exp.fix,
        )

    got = _rendered_answers(ans, exp.type)
    if _content_matches(exp.expected_content, got, exp.type):
        return CheckResult(section=POSTERN_MANAGED, label=exp.label, status="ok", detail=f"-> {exp.expected_content}")
    return CheckResult(
        section=POSTERN_MANAGED, label=exp.label, status="fail",
        detail=f"got {got}, expected {exp.expected_content!r}", fix=exp.fix,
    )


def _rendered_answers(ans: dns.resolver.Answer, type: str) -> list[str]:
    if ans.rrset is None:
        return []
    out: list[str] = []
    for r in ans:
        if type == "TXT":
            # dnspython concatenates multi-string TXTs when iterating .strings;
            # we want them joined byte-for-byte (RFC 7208 §3.4) without quotes.
            out.append(b"".join(r.strings).decode("utf-8", errors="replace"))
        elif type == "MX":
            out.append(f"{r.preference} {str(r.exchange).lower().rstrip('.') + '.'}")
        else:
            out.append(r.to_text())
    return out


def _content_matches(expected: str, got: list[str], type: str) -> bool:
    if type == "CAA":
        # dnspython renders CAA as `<flag> <tag> "<value>"`. Expected is in the same
        # shape but we tolerate case in tag.
        norm_expected = expected.strip().lower()
        return any(g.strip().lower() == norm_expected for g in got)
    if type == "TLSA":
        # libdns / dnspython may render the hex as lower or upper; tolerate either.
        return any(g.lower() == expected.lower() for g in got)
    return expected in got


# Connectivity checks ==================================================================================================
def check_tcp(host: str, port: int, *, timeout: float = 5.0) -> CheckResult:
    """TCP-connect to host:port. No protocol-level probe -- just SYN-ACK."""
    label = f":{port}/tcp {host}"
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return CheckResult(section=CONNECTIVITY, label=label, status="ok", detail="reachable")
    except OSError as e:
        return CheckResult(
            section=CONNECTIVITY, label=label, status="fail", detail=f"unreachable: {e}",
            fix=(
                f"Check that port {port} is open in the VPS firewall and not bound by a "
                "different process on the host."
            ),
        )


def check_tls(host: str, port: int = 443, *, timeout: float = 5.0) -> CheckResult:
    """TLS handshake against host:port using the system trust store; verifies
    the cert chain matches `host`. Catches the common 'cert expired but TCP
    still works' failure mode."""
    label = f"TLS {host}:{port}"
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return CheckResult(
                    section=CONNECTIVITY, label=label, status="ok",
                    detail="chain validates against system trust store",
                )
    except ssl.SSLCertVerificationError as e:
        return CheckResult(
            section=CONNECTIVITY, label=label, status="fail",
            detail=f"cert verification failed: {e.reason}",
            fix=(
                "Check `postern cert verify` and `postern cert show`. If the cert is "
                "expired, the provisioner should renew on its next tick."
            ),
        )
    except (OSError, ssl.SSLError) as e:
        return CheckResult(
            section=CONNECTIVITY, label=label, status="fail",
            detail=f"TLS handshake failed: {e}",
            fix="Check `docker compose logs nginx` and that :443/tcp is reachable.",
        )


# Runner ===============================================================================================================
@dataclass(frozen=True)
class DoctorSettings:
    """Inputs to the doctor. Resolved from `postern.settings.Settings` +
    optional state-file probes by the CLI wrapper. Injected so the module
    is independently testable."""
    domain: str
    public_ipv4: str
    public_ipv6: str | None
    admin_email: str
    tlsa_cert_hex: str | None = None
    dkim_pubkey_by_selector: dict[str, str] = field(default_factory=dict)


def run_doctor(
    settings: DoctorSettings,
    *,
    sections: tuple[Section, ...] = (EXTERNAL, POSTERN_MANAGED, CONNECTIVITY),
    resolver: dns.resolver.Resolver | None = None,
    tcp_probe: Callable[[str, int], CheckResult] | None = None,
    tls_probe: Callable[[str, int], CheckResult] | None = None,
    ds_probe: Callable[[str], CheckResult] | None = None,
    ptr_probe: Callable[[str, str], CheckResult] | None = None,
    record_probe: Callable[[PosternManagedExpectation], CheckResult] | None = None,
) -> DoctorReport:
    """Run all enabled sections and return a structured report.

    Probe parameters are dependency-injection seams for tests; production
    callers leave them None and the module's own functions are used.
    """
    do_ds = ds_probe if ds_probe is not None else (lambda d: check_ds(d))
    do_ptr = ptr_probe if ptr_probe is not None else (lambda ip, exp: check_ptr(ip, expected=exp, resolver=resolver))
    do_rec = record_probe if record_probe is not None else (lambda e: check_postern_record(e, resolver=resolver))
    do_tcp = tcp_probe if tcp_probe is not None else (lambda h, p: check_tcp(h, p))
    do_tls = tls_probe if tls_probe is not None else (lambda h, p: check_tls(h, p))

    report = DoctorReport()

    if EXTERNAL in sections:
        report.results.append(do_ds(settings.domain))
        ptr_expected = f"mail.{settings.domain}."
        report.results.append(do_ptr(settings.public_ipv4, ptr_expected))
        if settings.public_ipv6:
            report.results.append(do_ptr(settings.public_ipv6, ptr_expected))

    if POSTERN_MANAGED in sections:
        expectations = build_postern_expectations(
            settings.domain,
            public_ipv4=settings.public_ipv4,
            public_ipv6=settings.public_ipv6,
            admin_email=settings.admin_email,
            tlsa_cert_hex=settings.tlsa_cert_hex,
            dkim_pubkey_by_selector=settings.dkim_pubkey_by_selector,
        )
        for exp in expectations:
            report.results.append(do_rec(exp))

    if CONNECTIVITY in sections:
        host = settings.domain
        report.results.append(do_tcp(host, 443))
        report.results.append(do_tls(host, 443))
        report.results.append(do_tcp(f"mail.{settings.domain}", 25))

    return report


# Rendering ============================================================================================================
def render_text(report: DoctorReport) -> str:
    """Human-readable table grouped by section, with `Fix:` lines under FAILs."""
    buf = io.StringIO()
    by_section: dict[Section, list[CheckResult]] = {EXTERNAL: [], POSTERN_MANAGED: [], CONNECTIVITY: []}
    for r in report.results:
        by_section[r.section].append(r)

    headings = {
        EXTERNAL: "External (operator must publish; postern cannot):",
        POSTERN_MANAGED: "Postern-managed (current state vs expected):",
        CONNECTIVITY: "Connectivity:",
    }
    first = True
    for section in (EXTERNAL, POSTERN_MANAGED, CONNECTIVITY):
        rows = by_section[section]
        if not rows:
            continue
        if not first:
            buf.write("\n")
        first = False
        buf.write(headings[section] + "\n")
        for r in rows:
            marker = {"ok": "[OK]  ", "fail": "[FAIL]", "skip": "[SKIP]"}[r.status]
            line = f"  {marker} {r.label:<{_LABEL_W}}"
            if r.detail:
                line += f" {r.detail}"
            buf.write(line.rstrip() + "\n")
            if r.status == "fail" and r.fix:
                buf.write(f"         Fix: {r.fix}\n")

    failures = report.failures
    total = len(report.results)
    buf.write("\n")
    if failures:
        buf.write(f"{len(failures)} of {total} checks failed. See per-line \"Fix:\" hints above.\n")
    else:
        buf.write(f"All {total} checks passed.\n")
    return buf.getvalue()


def render_json(report: DoctorReport) -> str:
    return _json.dumps(
        {
            "exit_code": report.exit_code,
            "results": [asdict(r) for r in report.results],
        },
        indent=2,
    )
