#!/usr/bin/env python3
"""Provisioner Docker healthcheck.

Two modes:

- CERT_RENEWAL=false (default): healthy iff DKIM state.json shows non-NO_KEYS,
  OR the deployment has DKIM disabled (DNS_PROVIDER=none AND no DKIM state file).
  This is today's de-facto behaviour, just made explicit.

- CERT_RENEWAL=true: healthy iff cert state.json shows INSTALLED, AND the
  DKIM condition above also holds.

Used by docker-compose's `depends_on: condition: service_healthy` so nginx
and mta block startup until the provisioner has done its first-issuance work.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from postern.cert import state as cert_state
from postern.mta import rotation


def _bool_env(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() not in ("false", "0", "no", "off", "")


def main() -> int:
    cert_renewal = _bool_env("CERT_RENEWAL", False)
    dns_provider = os.environ.get("DNS_PROVIDER", "none").strip().lower()

    # DKIM half --------------------------------------------------------------------------------------------------------
    # Read via DEFAULT_KEYDIR so tests can monkeypatch the path; production
    # default is /var/lib/opendkim.
    dkim_state = rotation.read_state()
    dkim_initialised = dkim_state.state != "NO_KEYS"
    dkim_state_exists = (Path(rotation.DEFAULT_KEYDIR) / "state.json").exists()
    dkim_healthy = dkim_initialised or (dns_provider == "none" and not dkim_state_exists)

    if not dkim_healthy:
        print(
            "dkim: state.json shows NO_KEYS and DNS_PROVIDER is set; provisioner has not yet generated initial key",
            file=sys.stderr
        )
        return 1

    # Cert half --------------------------------------------------------------------------------------------------------
    if cert_renewal:
        cert = cert_state.read_state()
        if cert.state != "INSTALLED":
            print(f"cert: state={cert.state}, waiting for INSTALLED", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
