"""Tests for postern.cert.inspect -- read SANs, expiry, issuer from a fullchain.pem."""

import datetime as dt
from pathlib import Path

import pytest

from postern.cert import inspect as cert_inspect
from tests.e2e._certs import generate_test_pki


@pytest.fixture
def fullchain_path(tmp_path: Path) -> Path:
    generate_test_pki(tmp_path, hostname="postern.test")
    return tmp_path / "fullchain.pem"


def test_inspect_reads_sans(fullchain_path: Path):
    info = cert_inspect.read_cert(fullchain_path)
    assert set(info.sans) == {"postern.test", "*.postern.test"}


def test_inspect_reads_not_after_in_the_future(fullchain_path: Path):
    info = cert_inspect.read_cert(fullchain_path)
    now = dt.datetime.now(tz=dt.timezone.utc)
    assert info.not_after > now
    assert info.not_after < now + dt.timedelta(days=31)  # generate_test_pki uses 30 days


def test_inspect_reads_not_before_in_the_past(fullchain_path: Path):
    info = cert_inspect.read_cert(fullchain_path)
    now = dt.datetime.now(tz=dt.timezone.utc)
    assert info.not_before < now


def test_inspect_reads_issuer(fullchain_path: Path):
    info = cert_inspect.read_cert(fullchain_path)
    # The test PKI's CA CN is "Postern Test Root CA".
    assert "Postern Test Root CA" in info.issuer


def test_inspect_raises_on_missing_file(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        cert_inspect.read_cert(tmp_path / "does-not-exist.pem")


def test_sans_match_predicate(fullchain_path: Path):
    info = cert_inspect.read_cert(fullchain_path)
    assert info.sans_match({"postern.test", "*.postern.test"})
    assert not info.sans_match({"postern.test"})  # too narrow
    assert not info.sans_match({"postern.test", "*.postern.test", "extra.test"})  # too wide


def test_days_until_expiry_is_positive_for_valid_cert(fullchain_path: Path):
    info = cert_inspect.read_cert(fullchain_path)
    days = info.days_until_expiry()
    assert 0 < days <= 30


def test_key_matches_cert_accepts_the_certs_own_key(tmp_path: Path):
    generate_test_pki(tmp_path)
    assert cert_inspect.key_matches_cert(tmp_path / "fullchain.pem", tmp_path / "privkey.pem")


def test_key_matches_cert_rejects_another_certs_key(tmp_path: Path):
    generate_test_pki(tmp_path / "a")
    generate_test_pki(tmp_path / "b")
    assert not cert_inspect.key_matches_cert(tmp_path / "a" / "fullchain.pem", tmp_path / "b" / "privkey.pem")


def test_key_matches_cert_raises_value_error_on_an_unreadable_key(tmp_path: Path):
    generate_test_pki(tmp_path)
    (tmp_path / "privkey.pem").write_text("not a key")
    with pytest.raises(ValueError):
        cert_inspect.key_matches_cert(tmp_path / "fullchain.pem", tmp_path / "privkey.pem")


def _other_name_ca(path: Path) -> None:
    """A self-signed CA whose subject is not the leaf's issuer."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Some Other CA")])
    now = dt.datetime.now(tz=dt.timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(
            x509.random_serial_number()
        ).not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=1)).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        ).sign(key, hashes.SHA256())
    )
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def test_issued_directly_by_accepts_the_issuing_ca(tmp_path: Path):
    generate_test_pki(tmp_path)
    assert cert_inspect.issued_directly_by(tmp_path / "fullchain.pem", tmp_path / "chain.pem")


def test_issued_directly_by_rejects_a_ca_with_the_right_name_and_another_key(tmp_path: Path):
    generate_test_pki(tmp_path / "a")
    generate_test_pki(tmp_path / "b")
    assert not cert_inspect.issued_directly_by(tmp_path / "a" / "fullchain.pem", tmp_path / "b" / "chain.pem")


def test_issued_directly_by_rejects_a_ca_with_another_name(tmp_path: Path):
    generate_test_pki(tmp_path)
    _other_name_ca(tmp_path / "other.pem")
    assert not cert_inspect.issued_directly_by(tmp_path / "fullchain.pem", tmp_path / "other.pem")


def test_issued_directly_by_raises_value_error_on_an_unparseable_issuer(tmp_path: Path):
    generate_test_pki(tmp_path)
    (tmp_path / "chain.pem").write_text("not a certificate")
    with pytest.raises(ValueError):
        cert_inspect.issued_directly_by(tmp_path / "fullchain.pem", tmp_path / "chain.pem")


def test_issued_directly_by_treats_an_unsupported_signature_algorithm_as_not_issued(tmp_path: Path, monkeypatch):
    """The issuer certificate parses but its key or signature is of a kind this build cannot verify."""
    from cryptography.exceptions import UnsupportedAlgorithm

    class _Unverifiable:

        def verify_directly_issued_by(self, issuer):
            raise UnsupportedAlgorithm("no such signature algorithm")

    generate_test_pki(tmp_path)
    monkeypatch.setattr(cert_inspect.x509, "load_pem_x509_certificate", lambda pem: _Unverifiable())
    assert not cert_inspect.issued_directly_by(tmp_path / "fullchain.pem", tmp_path / "chain.pem")


def test_issued_directly_by_raises_os_error_on_a_missing_issuer(tmp_path: Path):
    generate_test_pki(tmp_path)
    with pytest.raises(OSError):
        cert_inspect.issued_directly_by(tmp_path / "fullchain.pem", tmp_path / "nowhere.pem")
