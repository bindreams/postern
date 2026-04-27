"""DKIM key file helpers.

Reads the public-key TXT companion files produced by `opendkim-genkey`.
Lives in the `postern` Python package so both the portal CLI and the
provisioner's entrypoint can use it.
"""

from __future__ import annotations

import re
from pathlib import Path

DEFAULT_KEYDIR = Path("/var/lib/opendkim")

_PUBKEY_RE = re.compile(r'p=([A-Za-z0-9+/=\s"]+)')


# Public API ===========================================================================================================
class DkimKeyNotFoundError(FileNotFoundError):
    pass


def read_local_pubkey(selector: str, *, keydir: Path | None = None) -> str:
    """Return the base64 DKIM public key for the given selector.

    Reads from ``<keydir>/<selector>.txt`` (the public-side companion produced
    by ``opendkim-genkey``) and extracts the ``p=...`` field, normalised to a
    single base64 string with no whitespace.

    Raises ``DkimKeyNotFoundError`` if the file is missing — typically because
    the provisioner hasn't generated the first key yet, or because the deployer
    hasn't enabled the built-in MTA.
    """
    keydir = DEFAULT_KEYDIR if keydir is None else keydir
    path = keydir / f"{selector}.txt"
    try:
        body = path.read_text(encoding="utf-8")
    except FileNotFoundError as e:
        raise DkimKeyNotFoundError(
            f"DKIM key not found at {path} — is the built-in MTA active? "
            f"(`COMPOSE_PROFILES=with-mta`, then `docker compose up -d`)"
        ) from e
    return _extract_pubkey(body)


def list_local_selectors(*, keydir: Path | None = None) -> list[str]:
    """Return every selector that has a `<selector>.txt` file in the keydir."""
    keydir = DEFAULT_KEYDIR if keydir is None else keydir
    if not keydir.exists():
        return []
    return sorted(p.stem for p in keydir.glob("*.txt") if (keydir / f"{p.stem}.private").exists())


# Internals ------------------------------------------------------------------------------------------------------------
def _extract_pubkey(body: str) -> str:
    """Pull the ``p=...`` value out of an ``opendkim-genkey``-produced TXT file.

    The file looks like:

        selector._domainkey IN TXT ("v=DKIM1; k=rsa; "
                  "p=MIIB...AB"
                  )

    We just want the base64 chunk.
    """
    match = _PUBKEY_RE.search(body)
    if match is None:
        raise ValueError("could not parse DKIM public key (no `p=` field found)")
    raw = match.group(1)
    return re.sub(r'[\s"]', "", raw)
