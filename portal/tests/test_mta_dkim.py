"""Tests for postern.mta.dkim -- DKIM key file helpers."""

from pathlib import Path

import pytest

from postern.mta import dkim as mta_dkim

_OPENDKIM_TXT_SAMPLE = """\
postern-2026-04._domainkey IN TXT ( "v=DKIM1; h=sha256; k=rsa; "
\t  "p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtest123sample"
\t  )  ; ----- DKIM key postern-2026-04 for postern.example.com
"""


def test_read_local_pubkey_extracts_p_field(tmp_path: Path):
    keyfile = tmp_path / "postern-2026-04.txt"
    keyfile.write_text(_OPENDKIM_TXT_SAMPLE)
    (tmp_path / "postern-2026-04.private").write_text("dummy")

    pubkey = mta_dkim.read_local_pubkey("postern-2026-04", keydir=tmp_path)
    assert pubkey == "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtest123sample"


def test_read_local_pubkey_strips_whitespace_and_quotes(tmp_path: Path):
    keyfile = tmp_path / "sel.txt"
    keyfile.write_text('foo IN TXT "v=DKIM1" "p=ABC123"\n')
    (tmp_path / "sel.private").write_text("dummy")

    assert mta_dkim.read_local_pubkey("sel", keydir=tmp_path) == "ABC123"


def test_read_local_pubkey_missing_raises_with_actionable_message(tmp_path: Path):
    with pytest.raises(mta_dkim.DkimKeyNotFoundError) as exc_info:
        mta_dkim.read_local_pubkey("never-existed", keydir=tmp_path)

    msg = str(exc_info.value)
    assert "never-existed.txt" in msg
    assert "COMPOSE_PROFILES=with-mta" in msg


def test_list_local_selectors_returns_only_selectors_with_both_files(tmp_path: Path):
    (tmp_path / "active.txt").write_text("foo")
    (tmp_path / "active.private").write_text("dummy")
    (tmp_path / "orphan-pub.txt").write_text("foo")
    (tmp_path / "orphan-priv.private").write_text("dummy")

    assert mta_dkim.list_local_selectors(keydir=tmp_path) == ["active"]


def test_list_local_selectors_returns_empty_when_dir_missing(tmp_path: Path):
    assert mta_dkim.list_local_selectors(keydir=tmp_path / "nonexistent") == []
