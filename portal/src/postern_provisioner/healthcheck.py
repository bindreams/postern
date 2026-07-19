#!/usr/bin/env python3
"""Provisioner Docker healthcheck.

Four halves, all green required:

- DKIM: state.json shows non-NO_KEYS, OR DKIM is disabled (DNS_PROVIDER=none
  AND no DKIM state file). This is today's de-facto behaviour, made explicit.

- Cert (only when CERT_RENEWAL=true): state.json shows INSTALLED **and** the
  apex/wildcard A/AAAA + CAA records have been reconciled at least once
  (dns_records_state.json's last_reconciled_iso is non-null).

- MTA records (only when the built-in MTA is deployed -- the with-mta compose
  profile -- AND DNS_PROVIDER != none): mta_records_state.json's
  last_reconciled_iso is non-null. The MX/SPF/DMARC/MTA-STS/TLS-RPT/TLSA chain is
  in DNS before mta startup. Gating on DNS_PROVIDER alone would deadlock a
  cert-only or edge-only deployment (both set DNS_PROVIDER but never run the
  mta_records tick, so last_reconciled_iso would stay null forever).

- ECH (only when Postern manages the Cloudflare zone-ECH setting
  (`EDGE_CF_MANAGE_ZONE_ECH=true`)): the zone-ECH PATCH has succeeded at least
  once (ech_zone_state.json's last_enabled_ok_iso is non-null) AND is not
  currently failing (consecutive_failures == 0), so the signal tracks current
  reality rather than "ever worked once".

Used by docker-compose's `depends_on: condition: service_healthy` so nginx
and mta block startup until the provisioner has done its first-issuance work.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from postern.cert import dns_records as dns_records_state
from postern.cert import state as cert_state
from postern.mta import rotation
from postern_provisioner import ech as ech_state
from postern_provisioner import mta_records as mta_records_state
from postern_provisioner.enablement import MANAGE_ZONE_ECH_DEFAULT, compute_enablement, mta_deployed_from_profiles


def _bool_env(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() not in ("false", "0", "no", "off", "")


def main() -> int:
    cert_renewal = _bool_env("CERT_RENEWAL", False)
    dns_provider = os.environ.get("DNS_PROVIDER", "none").strip().lower()
    # Single source of truth, identical to the entrypoint's derivation, so the
    # health gate can never drift from which ticks the loop actually runs.
    enablement = compute_enablement(
        dns_provider=dns_provider,
        cert_renewal=cert_renewal,
        edge_profile=os.environ.get("EDGE_PROFILE", "none"),
        mta_deployed=mta_deployed_from_profiles(os.environ.get("COMPOSE_PROFILES", "")),
        manage_zone_ech=_bool_env("EDGE_CF_MANAGE_ZONE_ECH", MANAGE_ZONE_ECH_DEFAULT),
    )

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

        # DNS records half (apex/wildcard A/AAAA + CAA, #115) ----------------------------------------------------------
        # Healthy only after the first successful tick, so nginx/mta don't
        # start before the DNS chain is in place. Subsequent ticks may fail
        # without changing health (the reconciler increments
        # consecutive_failures internally, but a transient provider hiccup
        # shouldn't make every dependent unhealthy).
        dns = dns_records_state.read_state()
        if dns.last_reconciled_iso is None:
            print("dns: apex/wildcard A/AAAA + CAA records not yet reconciled", file=sys.stderr)
            return 1

    # MTA records half (MX/SPF/DMARC/MTA-STS/TLS-RPT/TLSA, #118) -------------------------------------------------------
    # Gate mta startup on the records being in place. Same first-tick-only gating
    # as the cert/DNS halves above. Only when the built-in MTA is actually
    # deployed (with-mta) -- a cert-only / edge-only deployment never runs the
    # mta_records tick, so waiting on it would deadlock service_healthy.
    if enablement.mta_enabled:
        mta = mta_records_state.read_state()
        if mta.last_reconciled_iso is None:
            print("mta-dns: MX/SPF/DMARC/MTA-STS/TLS-RPT records not yet reconciled", file=sys.stderr)
            return 1

    # ECH half (only when Postern manages the Cloudflare zone-ECH setting) ---------------------------------------------
    # Also red on consecutive_failures > 0 so the signal tracks current reality (a
    # regression after the first success), not merely "ever worked once".
    if enablement.ech_zone_enabled:
        ech = ech_state.read_state()
        if ech.last_enabled_ok_iso is None:
            print(
                "ech: Cloudflare zone ECH not yet enabled (last_enabled_ok_iso is null); "
                f"last_error: {ech.last_error or '(none)'}",
                file=sys.stderr,
            )
            return 1
        if ech.consecutive_failures > 0:
            print(
                f"ech: Cloudflare zone ECH enablement is currently failing "
                f"({ech.consecutive_failures} consecutive); last_error: {ech.last_error or '(none)'}",
                file=sys.stderr,
            )
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
