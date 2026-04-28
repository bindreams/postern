"""Inspect an X.509 fullchain.pem -- SANs, expiry, issuer.

Used by `postern cert show`/`verify`/`renewal-status` and by the
provisioner's cert state machine (to decide whether the on-disk cert
already meets the wildcard SAN invariant or needs renewal).
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID


@dataclass
class CertInfo:
    sans: list[str] = field(default_factory=list)
    not_before: dt.datetime = dt.datetime.min.replace(tzinfo=dt.timezone.utc)
    not_after: dt.datetime = dt.datetime.min.replace(tzinfo=dt.timezone.utc)
    issuer: str = ""
    serial: int = 0

    def days_until_expiry(self, *, now: dt.datetime | None = None) -> float:
        when = now if now is not None else dt.datetime.now(tz=dt.timezone.utc)
        return (self.not_after - when).total_seconds() / 86400.0

    def sans_match(self, expected: set[str]) -> bool:
        """Exact-set equality. Defends the wildcard CT-leak invariant: extra
        subdomain SANs leak names to CT logs and are rejected."""
        return set(self.sans) == expected


def read_cert(path: Path) -> CertInfo:
    """Parse the leaf cert (first PEM block) from a fullchain.pem."""
    pem = path.read_bytes()
    # x509.load_pem_x509_certificate parses only the first PEM block, which is
    # exactly the leaf in a fullchain.pem produced by Lego or certbot.
    cert = x509.load_pem_x509_certificate(pem)

    sans: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = list(san_ext.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        pass

    issuer_cns = [a.value for a in cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)]
    issuer = issuer_cns[0] if issuer_cns else cert.issuer.rfc4514_string()

    # cryptography returns naive datetimes from .not_valid_before/_after (UTC).
    # The _utc variants are only available on cryptography>=42, but our pin is
    # >=42 anyway. Use them for clarity.
    return CertInfo(
        sans=sans,
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        issuer=issuer,
        serial=cert.serial_number,
    )
