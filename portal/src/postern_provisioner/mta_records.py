"""Reconciler for MX/SPF/DMARC/MTA-STS/TLS-RPT/TLSA records.

Activated when the `with-mta` profile is on AND `DNS_PROVIDER != none`. Sibling
of [postern_provisioner.dns_records] (apex/wildcard A/AAAA + CAA) and
[postern_provisioner.cert]. Pure function over (state, settings, runner, time)
returning the next state; caller persists.

Records published (gated on inputs):

  <domain>           MX    10 mail.<domain>
  <domain>           TXT   "v=spf1 mx -all"
  _dmarc.<domain>    TXT   "v=DMARC1; p=reject; ...; rua=mailto:<encoded>; ruf=..."
  _mta-sts.<domain>  TXT   "v=STSv1; id=<sha256(policy)[:16]>"
  _smtp._tls.<domain> TXT  "v=TLSRPTv1; rua=mailto:<encoded>"
  _25._tcp.mail.<domain> TLSA  3 1 1 <sha256(SPKI hex)>     (only when cert is on disk)

DKIM TXTs are excluded -- the rotation state machine in
[postern_mta.rotation] publishes those on its own cadence.

Provider invocation: shells out to `postern-dns` (extended in #114). Subprocess
wrapper is injectable for tests.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import logging
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from postern.mta import dns as mta_dns

logger = logging.getLogger(__name__)

POSTERN_DNS_BIN = "/usr/local/bin/postern-dns"


# Settings =============================================================================================================
@dataclass
class MtaRecordsSettings:
    """Subset of portal settings used by the MTA-records reconciler. Injected
    from the provisioner entrypoint so this module doesn't import
    postern.settings."""
    domain: str
    dns_provider: str
    admin_email: str  # MTA_ADMIN_EMAIL; used in DMARC and TLS-RPT mailto: URIs


# postern-dns runner ===================================================================================================
class PosternDnsRunner:
    """Subprocess wrapper around the postern-dns Go binary. Swappable in tests."""

    def __init__(self, *, bin_path: str = POSTERN_DNS_BIN, env: dict[str, str] | None = None) -> None:
        self.bin = bin_path
        self.env = env if env is not None else dict(os.environ)

    def set_record(self, rec: mta_dns.MtaRecord) -> None:
        cmd = [self.bin, f"{rec.type.lower()}-set", rec.name, *rec.args]
        subprocess.run(cmd, env=self.env, check=True, capture_output=True, text=True)

    def delete_record(self, rec: mta_dns.MtaRecord) -> None:
        cmd = [self.bin, f"{rec.type.lower()}-delete", rec.name, *rec.args]
        subprocess.run(cmd, env=self.env, check=True, capture_output=True, text=True)


# Cert helpers =========================================================================================================
def compute_tlsa_cert_hex(cert_pem_path: Path) -> str | None:
    """Read fullchain.pem and return sha256(SubjectPublicKeyInfo) hex of the leaf.

    Returns None if the file is missing (first-issuance bootstrap window).
    """
    try:
        pem = cert_pem_path.read_bytes()
    except FileNotFoundError:
        return None

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    leaf = x509.load_pem_x509_certificates(pem)[0]
    spki_der = leaf.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki_der).hexdigest()


# State ================================================================================================================
SCHEMA_VERSION = 1
DEFAULT_KEYDIR = Path("/var/lib/opendkim")


@dataclass
class MtaRecordsState:
    """State for the MTA-records reconciler. Lives at /var/lib/opendkim/mta_records_state.json
    (sibling of the DKIM rotation state.json; separate file).

    Each `last_published_*` mirrors the on-the-wire value of the corresponding
    record. The reconciler compares against the desired-record set produced by
    `mta_dns.expected_records_structured` and publishes only on drift.
    """
    schema_version: int = SCHEMA_VERSION
    last_published_mx: str = ""  # "10 mail.<domain>"
    last_published_spf: str = ""  # TXT content, unquoted (libdns wraps on write)
    last_published_dmarc: str = ""  # TXT content, unquoted
    last_published_mta_sts: str = ""  # TXT content, unquoted (includes id=)
    last_published_tls_rpt: str = ""  # TXT content, unquoted
    last_published_tlsa: str = ""  # "3 1 1 <hex>"
    last_reconciled_iso: str | None = None
    consecutive_failures: int = 0


def state_path(keydir: Path | None = None) -> Path:
    return (keydir or DEFAULT_KEYDIR) / "mta_records_state.json"


def trigger_path(keydir: Path | None = None) -> Path:
    """Operator -> provisioner: force a reconcile on the next tick."""
    return (keydir or DEFAULT_KEYDIR) / ".publish-mta-dns"


def read_state(keydir: Path | None = None) -> MtaRecordsState:
    import json
    path = state_path(keydir)
    if not path.exists():
        return MtaRecordsState()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        logger.warning("mta_records: state.json unreadable (%s); treating as empty", e)
        return MtaRecordsState()
    if raw.get("schema_version", 0) > SCHEMA_VERSION:
        logger.warning(
            "mta_records: state.json schema_version=%d is newer than supported %d; "
            "fields we don't recognise will be ignored", raw.get("schema_version"), SCHEMA_VERSION
        )
    fields_known = set(MtaRecordsState.__dataclass_fields__)
    return MtaRecordsState(**{k: v for k, v in raw.items() if k in fields_known})


def write_state(state: MtaRecordsState, *, keydir: Path | None = None) -> None:
    import json
    import tempfile
    path = state_path(keydir)
    path.parent.mkdir(parents=True, exist_ok=True)
    serialised = json.dumps(state.__dict__, indent=2, sort_keys=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".mta_records_state.", suffix=".json.tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(serialised)
            f.write("\n")
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# Reconciler ===========================================================================================================
def _record_signature(rec: mta_dns.MtaRecord) -> str:
    """Stable string representation of a record's content for state-comparison.
    For MX: "preference target". For TXT: the (unquoted) content. For TLSA: "u s m hex".
    """
    return " ".join(rec.args)


def _args_from_signature(type: str, sig: str) -> tuple[str, ...]:
    """Inverse of `_record_signature`. TXT content contains internal whitespace
    and must NOT be split (1 positional arg to postern-dns txt-delete);
    MX/TLSA are space-separated positional args."""
    if type == "TXT":
        return (sig, )
    return tuple(sig.split(" "))


def _last_published_for(state: MtaRecordsState, name: str, type: str) -> str:
    """Map a record (name, type) to the corresponding state field."""
    if type == "MX":
        return state.last_published_mx
    if type == "TLSA":
        return state.last_published_tlsa
    if type == "TXT":
        if name.startswith("_dmarc."):
            return state.last_published_dmarc
        if name.startswith("_mta-sts."):
            return state.last_published_mta_sts
        if name.startswith("_smtp._tls."):
            return state.last_published_tls_rpt
        # apex TXT == SPF
        return state.last_published_spf
    return ""


def _set_last_published(state: MtaRecordsState, name: str, type: str, value: str) -> None:
    if type == "MX":
        state.last_published_mx = value
    elif type == "TLSA":
        state.last_published_tlsa = value
    elif type == "TXT":
        if name.startswith("_dmarc."):
            state.last_published_dmarc = value
        elif name.startswith("_mta-sts."):
            state.last_published_mta_sts = value
        elif name.startswith("_smtp._tls."):
            state.last_published_tls_rpt = value
        else:
            state.last_published_spf = value


def reconcile_mta_records(
    state: MtaRecordsState,
    *,
    settings: MtaRecordsSettings,
    cert_pem_path: Path,
    runner: PosternDnsRunner,
    now: dt.datetime | None = None,
) -> MtaRecordsState:
    """One reconciliation tick. Pure function over (state, settings, runner, time).

    Strategy:
      1. Compute desired records from current settings + cert (if on disk).
      2. For each record, compare its on-the-wire content against state. If
         drift: delete the previously-published version (if state shows one),
         then set the new one.
      3. Idempotent skip when no drift.

    TLSA is skipped on first run before any cert exists; once the cert is on
    disk, every tick computes the SPKI hash and republishes on cert rotation
    (cert renewals change the pubkey by default).
    """
    now = now or dt.datetime.now(dt.timezone.utc)
    new_state = MtaRecordsState(
        schema_version=SCHEMA_VERSION,
        last_published_mx=state.last_published_mx,
        last_published_spf=state.last_published_spf,
        last_published_dmarc=state.last_published_dmarc,
        last_published_mta_sts=state.last_published_mta_sts,
        last_published_tls_rpt=state.last_published_tls_rpt,
        last_published_tlsa=state.last_published_tlsa,
        last_reconciled_iso=state.last_reconciled_iso,
        consecutive_failures=state.consecutive_failures,
    )

    tlsa_hex = compute_tlsa_cert_hex(cert_pem_path)
    desired = mta_dns.expected_records_structured(
        settings.domain, admin_email=settings.admin_email, tlsa_cert_hex=tlsa_hex
    )

    try:
        for rec in desired:
            want_sig = _record_signature(rec)
            have_sig = _last_published_for(state, rec.name, rec.type)
            if have_sig == want_sig:
                continue  # already in sync
            # Drift: delete the previously-published version before publishing the new one.
            if have_sig:
                old = mta_dns.MtaRecord(name=rec.name, type=rec.type, args=_args_from_signature(rec.type, have_sig))
                try:
                    runner.delete_record(old)
                    logger.info("mta-dns: deleted stale %s %s -> %s", rec.type, rec.name, have_sig)
                except subprocess.CalledProcessError as e:
                    # Stale-record delete failures are non-fatal here. The provider's
                    # txt-set / etc. will overwrite, or the state-of-the-world is already
                    # what we want. Log and continue.
                    stderr = (e.stderr or "").strip()
                    logger.warning(
                        "mta-dns: failed to delete stale %s %s (continuing): %s%s", rec.type, rec.name, e,
                        f": {stderr}" if stderr else ""
                    )
            runner.set_record(rec)
            logger.info("mta-dns: published %s %s -> %s", rec.type, rec.name, want_sig)
            _set_last_published(new_state, rec.name, rec.type, want_sig)

        # If TLSA was previously published but the cert is now gone (e.g. operator
        # rolled back, or we lost the volume), the desired-records list won't
        # include TLSA -- and the loop above never touches state.last_published_tlsa.
        # Leave it intact so we can detect the situation in `postern mta verify-dns`
        # rather than silently dropping it.

        new_state.last_reconciled_iso = now.isoformat()
        new_state.consecutive_failures = 0
    except subprocess.CalledProcessError as e:
        new_state.consecutive_failures = state.consecutive_failures + 1
        stderr = (e.stderr or "").strip()
        logger.error(
            "mta-dns: reconcile step failed (%d consecutive): %s%s", new_state.consecutive_failures, e,
            f": {stderr}" if stderr else ""
        )

    return new_state
