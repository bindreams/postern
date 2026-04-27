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
