"""Unit tests for the e2e cert-generation helper.

Lives outside tests/e2e/ on purpose: it does not need docker, and we do not
want it to inherit the e2e marker that's auto-applied to anything in tests/e2e/.
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID

from tests.e2e._certs import generate_test_pki


# Helpers ==============================================================================================================
def _load_cert(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def _load_first_cert(path: Path) -> x509.Certificate:
    """Load the first cert from a (possibly bundled) PEM file."""
    return x509.load_pem_x509_certificates(path.read_bytes())[0]


def _ext(cert: x509.Certificate, oid):
    return cert.extensions.get_extension_for_oid(oid)


# File-shape tests =====================================================================================================
def test_generate_writes_four_pem_files(tmp_path):
    generate_test_pki(tmp_path)
    for name in ("ca.pem", "privkey.pem", "fullchain.pem", "chain.pem"):
        assert (tmp_path / name).is_file(), f"missing {name}"


def test_chain_pem_is_just_the_ca(tmp_path):
    generate_test_pki(tmp_path)
    chain_certs = x509.load_pem_x509_certificates((tmp_path / "chain.pem").read_bytes())
    assert len(chain_certs) == 1
    # chain.pem and ca.pem should be byte-identical: chain.pem is the CA-only bundle
    # nginx reads for OCSP, and we ship the CA itself for that role.
    assert (tmp_path / "chain.pem").read_bytes() == (tmp_path / "ca.pem").read_bytes()


def test_fullchain_is_leaf_then_ca(tmp_path):
    generate_test_pki(tmp_path)
    ca = _load_cert(tmp_path / "ca.pem")
    bundle = x509.load_pem_x509_certificates((tmp_path / "fullchain.pem").read_bytes())
    assert len(bundle) == 2
    assert bundle[0].subject != ca.subject  # leaf first
    assert bundle[1].subject == ca.subject  # CA second


# Algorithm tests ======================================================================================================
def test_keys_are_ed25519(tmp_path):
    generate_test_pki(tmp_path)
    ca = _load_cert(tmp_path / "ca.pem")
    leaf = _load_first_cert(tmp_path / "fullchain.pem")
    assert isinstance(ca.public_key(), Ed25519PublicKey)
    assert isinstance(leaf.public_key(), Ed25519PublicKey)
    privkey = serialization.load_pem_private_key((tmp_path / "privkey.pem").read_bytes(), password=None)
    assert isinstance(privkey, Ed25519PrivateKey)


# Signature / chain validity ===========================================================================================
def test_leaf_is_signed_by_ca(tmp_path):
    generate_test_pki(tmp_path)
    ca = _load_cert(tmp_path / "ca.pem")
    leaf = _load_first_cert(tmp_path / "fullchain.pem")
    ca_pub = ca.public_key()
    assert isinstance(ca_pub, Ed25519PublicKey)
    # Ed25519 verify: raises on mismatch.
    ca_pub.verify(leaf.signature, leaf.tbs_certificate_bytes)
    assert leaf.issuer == ca.subject


def test_privkey_matches_leaf(tmp_path):
    generate_test_pki(tmp_path)
    leaf = _load_first_cert(tmp_path / "fullchain.pem")
    privkey = serialization.load_pem_private_key((tmp_path / "privkey.pem").read_bytes(), password=None)
    assert isinstance(privkey, Ed25519PrivateKey)
    leaf_pub_bytes = leaf.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    priv_pub_bytes = privkey.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    assert leaf_pub_bytes == priv_pub_bytes


# Extension tests ======================================================================================================
def test_ca_basic_constraints(tmp_path):
    generate_test_pki(tmp_path)
    ca = _load_cert(tmp_path / "ca.pem")
    bc = _ext(ca, ExtensionOID.BASIC_CONSTRAINTS)
    assert bc.critical is True
    assert bc.value.ca is True


def test_leaf_basic_constraints(tmp_path):
    generate_test_pki(tmp_path)
    leaf = _load_first_cert(tmp_path / "fullchain.pem")
    bc = _ext(leaf, ExtensionOID.BASIC_CONSTRAINTS)
    assert bc.critical is True
    assert bc.value.ca is False


def test_leaf_extended_key_usage_serverauth(tmp_path):
    generate_test_pki(tmp_path)
    leaf = _load_first_cert(tmp_path / "fullchain.pem")
    eku = _ext(leaf, ExtensionOID.EXTENDED_KEY_USAGE)
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku.value


def test_leaf_san_default_hostname(tmp_path):
    generate_test_pki(tmp_path)
    leaf = _load_first_cert(tmp_path / "fullchain.pem")
    san = _ext(leaf, ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    dns_names = san.value.get_values_for_type(x509.DNSName)
    assert "postern.test" in dns_names
    assert "*.postern.test" in dns_names


def test_leaf_san_custom_hostname(tmp_path):
    generate_test_pki(tmp_path, hostname="example.local")
    leaf = _load_first_cert(tmp_path / "fullchain.pem")
    san = _ext(leaf, ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    dns_names = san.value.get_values_for_type(x509.DNSName)
    assert "example.local" in dns_names
    assert "*.example.local" in dns_names


def test_leaf_aki_matches_ca_ski(tmp_path):
    generate_test_pki(tmp_path)
    ca = _load_cert(tmp_path / "ca.pem")
    leaf = _load_first_cert(tmp_path / "fullchain.pem")
    ca_ski = _ext(ca, ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest
    leaf_aki = _ext(leaf, ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value.key_identifier
    assert leaf_aki == ca_ski


# Validity-window tests ================================================================================================
def test_not_valid_before_is_in_the_past(tmp_path):
    generate_test_pki(tmp_path)
    leaf = _load_first_cert(tmp_path / "fullchain.pem")
    now = datetime.now(tz=timezone.utc)
    # Plan specifies a 5-minute backdate for clock-skew margin.
    assert leaf.not_valid_before_utc <= now - timedelta(minutes=1)


def test_validity_is_about_30_days(tmp_path):
    generate_test_pki(tmp_path)
    leaf = _load_first_cert(tmp_path / "fullchain.pem")
    span = leaf.not_valid_after_utc - leaf.not_valid_before_utc
    assert timedelta(days=29, hours=23) <= span <= timedelta(days=30, hours=1)


# Filesystem-mode tests ================================================================================================
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits are no-ops on Windows")
def test_output_dir_and_files_are_world_readable(tmp_path):
    """Containerized consumers (nginx, ssclient) run as a non-root UID
    different from the test runner's. Without world-traversable dir + world-
    readable files, the bind mount fails with `Permission denied`. Regression
    test for an early CI failure on PR #13."""
    generate_test_pki(tmp_path)
    dir_mode = tmp_path.stat().st_mode & 0o777
    assert dir_mode & 0o005 == 0o005, f"out_dir not world-traversable: {oct(dir_mode)}"
    for name in ("ca.pem", "privkey.pem", "fullchain.pem", "chain.pem"):
        file_mode = (tmp_path / name).stat().st_mode & 0o777
        assert file_mode & 0o004 == 0o004, f"{name} not world-readable: {oct(file_mode)}"


# Idempotence ==========================================================================================================
def test_running_twice_overwrites_files_on_disk(tmp_path):
    """Second invocation must rewrite every file; not just generate fresh
    in-memory state and silently no-op the disk writes."""
    generate_test_pki(tmp_path)
    snapshot = {
        name: (tmp_path / name).read_bytes()
        for name in ("ca.pem", "privkey.pem", "fullchain.pem", "chain.pem")
    }
    serial1 = _load_first_cert(tmp_path / "fullchain.pem").serial_number
    generate_test_pki(tmp_path)
    serial2 = _load_first_cert(tmp_path / "fullchain.pem").serial_number
    assert serial1 != serial2  # in-memory generation produced fresh material
    for name, prior_bytes in snapshot.items():
        assert (tmp_path / name).read_bytes() != prior_bytes, f"{name} was not rewritten on disk"
