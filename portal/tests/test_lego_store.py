"""Tests for postern_provisioner.lego_store -- whether lego can load the state it keeps on disk."""

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from postern_provisioner import lego_store
from tests.e2e._certs import generate_test_pki

EMAIL = "ops@postern.test"
DOMAIN = "postern.test"


def _key_pem(kind: str) -> bytes:
    key = rsa.generate_private_key(65537, 2048) if kind == "rsa" else ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
    )


@pytest.fixture
def account_dir(tmp_path: Path) -> Path:
    path = tmp_path / "accounts" / "ca.test" / EMAIL
    path.mkdir(parents=True)
    return path


# Account ==============================================================================================================
# A file that does not decode into lego's account struct is fatal to lego (it writes the file non-atomically, so a crash
# can truncate it); a missing or null registration is not (the CA is asked).
@pytest.mark.parametrize(
    ("body", "unloadable"),
    [
        (json.dumps({"registration": {"status": "valid"}}), False),
        (json.dumps({"registration": None}), False),
        ("{}", False),
        ("null", False),
        (json.dumps({"id": None, "email": None}), False),
        (json.dumps({"registration": {"body": {"status": "valid"}}}), False),
        (json.dumps({"registration": {"contact": [None]}}), False),
        (json.dumps({"unknown": 5}), False),
        (json.dumps({"registration": "valid"}), True),
        (json.dumps({"registration": {"status": 5}}), True),
        (json.dumps({"registration": {"contact": "mailto:x"}}), True),
        (json.dumps({"registration": {"contact": [1]}}), True),
        (json.dumps({"registration": {"termsOfServiceAgreed": "yes"}}), True),
        (json.dumps({"email": 5}), True),
        (json.dumps({"KeyType": 5}), True),
        ("[]", True),
        ("5", True),
        ('{"id": "ops@po', True),
        ("", True),
        ('{"registration": {"status": NaN}}', True),
    ],
    ids=[
        "v5-registered", "null-registration", "empty-object", "null-document", "null-strings", "v4-shaped",
        "null-contact-entry", "unknown-field", "registration-not-an-object", "status-not-a-string",
        "contact-not-a-list", "contact-entry-not-a-string", "bool-field-a-string", "email-not-a-string",
        "key-matched-case-insensitively", "list-document", "number-document", "truncated", "empty", "nan"
    ],
)
def test_account_file_is_judged_as_lego_v5_decodes_it(account_dir, body, unloadable):
    (account_dir / "account.json").write_text(body)
    assert lego_store.account_unloadable(account_dir, EMAIL) is unloadable


def test_a_missing_account_is_not_unloadable(account_dir):
    assert lego_store.account_unloadable(account_dir, EMAIL) is False


def test_a_missing_account_directory_is_not_unloadable(tmp_path):
    assert lego_store.account_unloadable(tmp_path / "nowhere", EMAIL) is False


def test_an_account_file_that_cannot_be_read_is_unloadable_and_logged(account_dir, caplog):
    (account_dir / "account.json").mkdir()
    assert lego_store.account_unloadable(account_dir, EMAIL) is True
    assert "account.json" in caplog.text


@pytest.mark.parametrize("kind", ["rsa", "ec"])
def test_an_account_key_that_loads_is_not_unloadable(account_dir, kind):
    (account_dir / "account.json").write_text("{}")
    (account_dir / f"{EMAIL}.key").write_bytes(_key_pem(kind))
    assert lego_store.account_unloadable(account_dir, EMAIL) is False


@pytest.mark.parametrize(
    "junk", [b"", b"key", b"-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n"]
)
def test_an_account_key_that_does_not_load_is_unloadable_when_the_account_file_exists(account_dir, junk):
    (account_dir / "account.json").write_text("{}")
    (account_dir / f"{EMAIL}.key").write_bytes(junk)
    assert lego_store.account_unloadable(account_dir, EMAIL) is True


def test_an_account_key_that_does_not_load_is_ignored_without_an_account_file(account_dir):
    """lego creates a new account, with a new key over the old one, when `account.json` is absent."""
    (account_dir / f"{EMAIL}.key").write_bytes(b"key")
    assert lego_store.account_unloadable(account_dir, EMAIL) is False


def test_an_account_key_that_is_a_directory_is_unloadable(account_dir):
    (account_dir / "account.json").write_text("{}")
    (account_dir / f"{EMAIL}.key").mkdir()
    assert lego_store.account_unloadable(account_dir, EMAIL) is True


# Certificate ==========================================================================================================
@pytest.fixture
def certs(tmp_path: Path) -> Path:
    path = tmp_path / "certificates"
    path.mkdir()
    return path


def _pki(certs: Path, name: str) -> bytes:
    generate_test_pki(certs.parent / "pki", hostname=DOMAIN)
    return (certs.parent / "pki" / name).read_bytes()


def _store(certs: Path, resource: str | None = '{"id": "postern.test"}', crt: bytes | None = b"fullchain") -> None:
    """lego's stored set; `crt=b"fullchain"` stands for a loadable bundle."""
    if resource is not None:
        (certs / f"{DOMAIN}.json").write_text(resource)
    if crt is not None:
        (certs / f"{DOMAIN}.crt").write_bytes(_pki(certs, "fullchain.pem") if crt == b"fullchain" else crt)


def test_a_stored_certificate_that_lego_loads_is_not_unloadable(certs):
    _store(certs)
    assert lego_store.certificate_unloadable(certs, DOMAIN) is False


def test_without_a_resource_file_lego_obtains_afresh_whatever_the_certificate_is(certs):
    _store(certs, resource=None, crt=b"not a certificate")
    assert lego_store.certificate_unloadable(certs, DOMAIN) is False


def test_an_empty_store_is_not_unloadable(certs):
    assert lego_store.certificate_unloadable(certs, DOMAIN) is False


@pytest.mark.parametrize(
    "resource",
    ['{"id": "postern.test", "domains": ["postern.test"', "", "[]", "5", '{"domains": "postern.test"}', '{"id": 5}'],
    ids=["truncated", "empty", "list", "number", "domains-not-a-list", "id-not-a-string"],
)
def test_a_resource_file_that_does_not_decode_is_unloadable(certs, resource):
    _store(certs, resource=resource)
    assert lego_store.certificate_unloadable(certs, DOMAIN) is True


@pytest.mark.parametrize("resource", ["{}", "null", '{"unknown": 1}'])
def test_a_resource_file_with_none_of_the_resource_fields_is_unloadable(certs, resource):
    """The decoded resource has no embedded `certificate.Resource`, and lego dereferences it (`resource.Profile`)."""
    _store(certs, resource=resource)
    assert lego_store.certificate_unloadable(certs, DOMAIN) is True


def test_a_resource_field_is_matched_case_insensitively(certs):
    _store(certs, resource='{"ID": "postern.test"}')
    assert lego_store.certificate_unloadable(certs, DOMAIN) is False


@pytest.mark.parametrize(
    "crt",
    [None, b"not a certificate", b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"],
    ids=["missing", "not-pem", "bad-der"],
)
def test_a_certificate_lego_cannot_parse_is_unloadable_when_the_resource_file_exists(certs, crt):
    _store(certs, crt=crt)
    assert lego_store.certificate_unloadable(certs, DOMAIN) is True


def test_a_certificate_bundle_that_starts_with_a_ca_is_unloadable(certs):
    """lego refuses it: "certificate bundle ... starts with a CA certificate"."""
    _store(certs, crt=_pki(certs, "chain.pem"))
    assert lego_store.certificate_unloadable(certs, DOMAIN) is True


def test_a_resource_file_that_cannot_be_read_is_unloadable_and_logged(certs, caplog):
    (certs / f"{DOMAIN}.json").mkdir()
    assert lego_store.certificate_unloadable(certs, DOMAIN) is True
    assert f"{DOMAIN}.json" in caplog.text


def test_a_certificate_file_that_cannot_be_read_is_unloadable_and_logged(certs, caplog):
    _store(certs, crt=None)
    (certs / f"{DOMAIN}.crt").mkdir()
    assert lego_store.certificate_unloadable(certs, DOMAIN) is True
    assert f"{DOMAIN}.crt" in caplog.text
