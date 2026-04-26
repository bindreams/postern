"""Generate a self-signed CA + leaf for the e2e test stack.

Used by the `e2e_certs` pytest fixture (see conftest.py) for normal test runs,
and runnable as a standalone script for ad-hoc compose bring-up:

    python tests/e2e/_certs.py /tmp/postern-e2e-tls

Output (all PEM):
    ca.pem        - root CA cert (also written as chain.pem for nginx OCSP)
    privkey.pem   - leaf private key (Ed25519)
    fullchain.pem - leaf cert + CA cert (concatenated for nginx)
    chain.pem     - CA cert only, byte-identical to ca.pem

Cert shape is documented in the plan; key invariants enforced here:
- Ed25519 keys (instant generation, accepted by nginx/OpenSSL3, Go crypto/tls,
  Python ssl).
- not_valid_after = now + 30 days; not_valid_before = now - 5 minutes (the
  backdate absorbs host/container clock skew).
- SANs cover {hostname} and *.{hostname}; CN is informational.
- AKI on the leaf points at the CA's SKI so older Go TLS verifiers stay happy.
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CA_VALIDITY = timedelta(days=30)
LEAF_VALIDITY = timedelta(days=30)
CLOCK_SKEW_MARGIN = timedelta(minutes=5)

CA_KEY_USAGE = x509.KeyUsage(
    digital_signature=False,
    content_commitment=False,
    key_encipherment=False,
    data_encipherment=False,
    key_agreement=False,
    key_cert_sign=True,
    crl_sign=True,
    encipher_only=False,
    decipher_only=False,
)
LEAF_KEY_USAGE = x509.KeyUsage(
    digital_signature=True,
    content_commitment=False,
    key_encipherment=True,
    data_encipherment=False,
    key_agreement=False,
    key_cert_sign=False,
    crl_sign=False,
    encipher_only=False,
    decipher_only=False,
)


def generate_test_pki(out_dir: Path, *, hostname: str = "postern.test") -> None:
    """Write a fresh self-signed CA + leaf into out_dir.

    Always overwrites; does not honor any pre-existing files in out_dir.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    not_before = datetime.now(tz=timezone.utc) - CLOCK_SKEW_MARGIN
    leaf_not_after = not_before + CLOCK_SKEW_MARGIN + LEAF_VALIDITY
    ca_not_after = not_before + CLOCK_SKEW_MARGIN + CA_VALIDITY

    # Root CA ==========================================================================================================
    ca_key = Ed25519PrivateKey.generate()
    ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Postern Test Root CA")])
    ca_ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())

    ca_builder = x509.CertificateBuilder()
    ca_builder = ca_builder.subject_name(ca_subject)
    ca_builder = ca_builder.issuer_name(ca_subject)  # self-signed
    ca_builder = ca_builder.public_key(ca_key.public_key())
    ca_builder = ca_builder.serial_number(x509.random_serial_number())
    ca_builder = ca_builder.not_valid_before(not_before)
    ca_builder = ca_builder.not_valid_after(ca_not_after)
    ca_builder = ca_builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    ca_builder = ca_builder.add_extension(CA_KEY_USAGE, critical=True)
    ca_builder = ca_builder.add_extension(ca_ski, critical=False)
    ca_cert = ca_builder.sign(private_key=ca_key, algorithm=None)  # algorithm=None is required for Ed25519

    # Leaf =============================================================================================================
    leaf_key = Ed25519PrivateKey.generate()
    leaf_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    leaf_san = x509.SubjectAlternativeName([x509.DNSName(hostname), x509.DNSName(f"*.{hostname}")])
    leaf_aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski)

    leaf_builder = x509.CertificateBuilder()
    leaf_builder = leaf_builder.subject_name(leaf_subject)
    leaf_builder = leaf_builder.issuer_name(ca_subject)
    leaf_builder = leaf_builder.public_key(leaf_key.public_key())
    leaf_builder = leaf_builder.serial_number(x509.random_serial_number())
    leaf_builder = leaf_builder.not_valid_before(not_before)
    leaf_builder = leaf_builder.not_valid_after(leaf_not_after)
    leaf_builder = leaf_builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    leaf_builder = leaf_builder.add_extension(LEAF_KEY_USAGE, critical=True)
    leaf_builder = leaf_builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    leaf_builder = leaf_builder.add_extension(leaf_san, critical=False)
    leaf_builder = leaf_builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False
    )
    leaf_builder = leaf_builder.add_extension(leaf_aki, critical=False)
    leaf_cert = leaf_builder.sign(private_key=ca_key, algorithm=None)  # algorithm=None is required for Ed25519

    # Serialize ========================================================================================================
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    leaf_pem = leaf_cert.public_bytes(serialization.Encoding.PEM)
    privkey_pem = leaf_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    (out_dir / "ca.pem").write_bytes(ca_pem)
    (out_dir / "privkey.pem").write_bytes(privkey_pem)
    (out_dir / "fullchain.pem").write_bytes(leaf_pem + ca_pem)
    (out_dir / "chain.pem").write_bytes(ca_pem)

    # Make the dir + files world-traversable / world-readable so the nginx and
    # ssclient containers (running as a non-root UID different from the test
    # runner's UID) can read the bind-mounted files. Without this, pytest's
    # tmp_path_factory creates 0o700 dirs and nginx fails with "Permission
    # denied" on the bind-mounted cert. These are throwaway test certs; the
    # private key has no security value.
    out_dir.chmod(0o755)
    for name in ("ca.pem", "privkey.pem", "fullchain.pem", "chain.pem"):
        (out_dir / name).chmod(0o644)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"usage: python {sys.argv[0]} <out_dir>", file=sys.stderr)
        sys.exit(2)
    out = Path(sys.argv[1])
    generate_test_pki(out)
    print(out)
