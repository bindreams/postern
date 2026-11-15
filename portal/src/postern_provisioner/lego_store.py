"""Whether lego can load the state it keeps on disk.

A file lego cannot load fails every `lego run`, forced ones included, so no later tick recovers by itself. These
predicates mirror lego's loaders for the two things Postern keeps there: an ACME account and the stored certificate.
Lego writes the files non-atomically, so a crash can leave one truncated.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

logger = logging.getLogger(__name__)

# The JSON fields of lego's account file and certificate resource file, keyed by lowercase name (Go's decoder matches
# names case-insensitively and ignores the rest). A type is a Python scalar type; a list holds the element type; a dict
# is a nested object. A JSON null fits any of them.
_Spec = type | list | dict
_ACCOUNT_FIELDS: dict[str, _Spec] = {
    "id": str,
    "email": str,
    "keytype": str,
    "server": str,
    "origin": str,
    "registration": {
        "status": str,
        "contact": [str],
        "termsofserviceagreed": bool,
        "orders": str,
        "onlyreturnexisting": bool,
        "accounturl": str,
    },
}
# The fields of an embedded certificate resource: lego dereferences it, and Go allocates it only for a field present.
_RESOURCE_FIELDS: dict[str, _Spec] = {
    "id": str,
    "domains": [str],
    "keytype": str,
    "preferredchain": str,
    "profile": str,
    "certurl": str,
    "certstableurl": str,
}
_RESOURCE_FILE_FIELDS: dict[str, _Spec] = {**_RESOURCE_FIELDS, "origin": str}


def account_unloadable(account_dir: Path, email: str) -> bool:
    """Whether lego cannot load the account kept in `account_dir`: `account.json` does not decode into its account
    struct (a null or absent registration does, and the CA is asked), or it exists beside a `<email>.key` that is not a
    PEM RSA, EC or Ed25519 private key. A missing account is not unloadable (lego creates one), and a key is only read
    when `account.json` exists. A file that cannot be read at all is unloadable; it is logged."""
    try:
        raw = _read_or_none(account_dir / "account.json")
        if raw is None:
            return False
        if not _decodes_into(_load_json(raw), _ACCOUNT_FIELDS):
            return True
        key = _read_or_none(account_dir / f"{email}.key")
        return key is not None and not _is_private_key(key)
    except ValueError:
        return True
    except OSError as e:
        logger.error("cert: lego cannot read its account: %s", e)
        return True


def certificate_unloadable(certs_dir: Path, domain: str) -> bool:
    """Whether lego cannot load the certificate it stored for `domain` under `certs_dir`. Lego renews only while the
    resource file (`<domain>.json`) exists, and then needs it to decode into a resource with at least one field, and
    `<domain>.crt` to be a PEM bundle whose first certificate is not a CA. Without the resource file it obtains a new
    certificate, so nothing else is read. A file that cannot be read at all is unloadable; it is logged."""
    try:
        raw = _read_or_none(certs_dir / f"{domain}.json")
        if raw is None:
            return False
        resource = _load_json(raw)
        if not _decodes_into(resource, _RESOURCE_FILE_FIELDS):
            return True
        if not (isinstance(resource, dict) and any(k.lower() in _RESOURCE_FIELDS for k in resource)):
            return True
        bundle = _read_or_none(certs_dir / f"{domain}.crt")
        return bundle is None or _starts_with_a_ca(bundle)
    except ValueError:
        return True
    except OSError as e:
        logger.error("cert: lego cannot read its stored certificate: %s", e)
        return True


def _read_or_none(path: Path) -> bytes | None:
    try:
        return path.read_bytes()
    except FileNotFoundError:
        return None


def _reject_constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def _load_json(raw: bytes) -> Any:
    """Parse as Go's `encoding/json` does: no NaN or Infinity."""
    return json.loads(raw.decode("utf-8", errors="replace"), parse_constant=_reject_constant)


def _decodes_into(value: Any, spec: _Spec) -> bool:
    """Whether Go's `json.Unmarshal` accepts `value` into a struct (or field) of this shape: null always, a wrong type
    never, an unknown field silently."""
    if value is None:
        return True
    if isinstance(spec, dict):
        if not isinstance(value, dict):
            return False
        return all(_decodes_into(v, spec[k.lower()]) for k, v in value.items() if k.lower() in spec)
    if isinstance(spec, list):
        return isinstance(value, list) and all(_decodes_into(item, spec[0]) for item in value)
    return type(value) is spec


def _is_private_key(pem: bytes) -> bool:
    try:
        key = serialization.load_pem_private_key(pem, password=None)
    except (ValueError, TypeError):
        return False
    return isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey))


def _starts_with_a_ca(bundle: bytes) -> bool:
    """Whether the PEM bundle starts with a CA certificate; ValueError when it holds no parseable certificate."""
    first = x509.load_pem_x509_certificates(bundle)[0]
    try:
        return first.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        return False
