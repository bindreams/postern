"""Tests for postern.identity -- IP extraction, GeoIP enrichment, UA parsing."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any
from pathlib import Path

import pytest
from mmdb_writer import MMDBWriter
from netaddr import IPNetwork, IPSet

from postern import identity


# Fake Request helpers =================================================================================================
@dataclass
class _FakeClient:
    host: str


class _FakeHeaders:
    """Case-insensitive subset of starlette.datastructures.Headers."""

    def __init__(self, data: dict[str, str]):
        self._data = {k.lower(): v for k, v in data.items()}

    def get(self, key: str, default: str = "") -> str:
        return self._data.get(key.lower(), default)


@dataclass
class _FakeRequest:
    client: _FakeClient | None
    headers: _FakeHeaders

    @classmethod
    def make(
        cls,
        direct_ip: str | None,
        *,
        x_real_ip: str | None = None,
        user_agent: str = "",
    ) -> "_FakeRequest":
        headers: dict[str, str] = {}
        if x_real_ip is not None:
            headers["X-Real-IP"] = x_real_ip
        if user_agent:
            headers["User-Agent"] = user_agent
        client = _FakeClient(direct_ip) if direct_ip is not None else None
        return cls(client=client, headers=_FakeHeaders(headers))


# MMDB fixture helpers =================================================================================================
def _make_city_db(path: Path, entries: dict[str, dict[str, Any]]) -> None:
    """Build a tiny GeoLite2-City-shaped MMDB at `path`.

    `entries` maps "1.2.3.0/24" -> the record dict the reader should return.
    """
    w = MMDBWriter(ip_version=4, database_type="GeoLite2-City")
    for cidr, record in entries.items():
        w.insert_network(IPSet([IPNetwork(cidr)]), record)
    w.to_db_file(str(path))


def _make_asn_db(path: Path, entries: dict[str, dict[str, Any]]) -> None:
    w = MMDBWriter(ip_version=4, database_type="GeoLite2-ASN")
    for cidr, record in entries.items():
        w.insert_network(IPSet([IPNetwork(cidr)]), record)
    w.to_db_file(str(path))


# IP extraction ========================================================================================================
def test_lookup_uses_x_real_ip_when_direct_is_private():
    """nginx is the only ingress: trust X-Real-IP when the direct hop is on a private subnet."""
    req = _FakeRequest.make("172.20.0.5", x_real_ip="203.0.113.42")
    info = identity.lookup(req, readers=None)
    assert info.ip == "203.0.113.42"


def test_lookup_uses_x_real_ip_when_direct_is_loopback():
    req = _FakeRequest.make("127.0.0.1", x_real_ip="203.0.113.42")
    info = identity.lookup(req, readers=None)
    assert info.ip == "203.0.113.42"


def test_lookup_ignores_x_real_ip_when_direct_is_public():
    """Spoofing guard: never trust X-Real-IP from a non-private direct hop."""
    req = _FakeRequest.make("198.51.100.1", x_real_ip="203.0.113.42")
    info = identity.lookup(req, readers=None)
    assert info.ip == "198.51.100.1"


def test_lookup_uses_direct_when_no_header():
    req = _FakeRequest.make("198.51.100.7")
    info = identity.lookup(req, readers=None)
    assert info.ip == "198.51.100.7"


def test_lookup_handles_missing_client():
    """request.client can be None for some ASGI scopes; trust X-Real-IP in that case.

    When there's no direct socket peer to make a trust decision against, the request
    necessarily reached us via in-process plumbing or a locally-configured proxy that
    already terminated the connection; returning "" would force the identity card to
    render "unknown" despite the upstream having told us exactly who the visitor is.
    """
    req = _FakeRequest.make(None, x_real_ip="203.0.113.42")
    info = identity.lookup(req, readers=None)
    assert info.ip == "203.0.113.42"


def test_lookup_handles_missing_client_and_no_header():
    """request.client is None AND no X-Real-IP -> empty IP, no exception."""
    req = _FakeRequest.make(None)
    info = identity.lookup(req, readers=None)
    assert info.ip == ""


# Private-range skip ===================================================================================================
def test_loopback_skips_enrichment(tmp_path: Path):
    """Looking up 127.0.0.1 in MaxMind is pointless; identity.lookup returns IP only."""
    city_db = tmp_path / "GeoLite2-City.mmdb"
    asn_db = tmp_path / "GeoLite2-ASN.mmdb"
    _make_city_db(city_db, {"203.0.113.0/24": {"country": {"iso_code": "AT", "names": {"en": "Austria"}}}})
    _make_asn_db(
        asn_db, {"203.0.113.0/24": {"autonomous_system_number": 8412, "autonomous_system_organization": "Magenta"}}
    )

    readers = identity.GeoIPReaders(str(tmp_path))
    try:
        req = _FakeRequest.make("127.0.0.1")
        info = identity.lookup(req, readers=readers)
        assert info.country_code is None
        assert info.city is None
        assert info.isp is None
        assert info.asn is None
    finally:
        readers.close()


def test_rfc1918_skips_enrichment(tmp_path: Path):
    city_db = tmp_path / "GeoLite2-City.mmdb"
    _make_city_db(city_db, {"203.0.113.0/24": {"country": {"iso_code": "AT", "names": {"en": "Austria"}}}})
    readers = identity.GeoIPReaders(str(tmp_path))
    try:
        req = _FakeRequest.make("10.0.0.5")
        info = identity.lookup(req, readers=readers)
        assert info.country_code is None
    finally:
        readers.close()


# Reader edge cases ====================================================================================================
def test_empty_db_dir_returns_ip_only():
    """GeoIPReaders('') is a no-op; lookup returns IP without enrichment."""
    readers = identity.GeoIPReaders("")
    try:
        req = _FakeRequest.make("203.0.113.42")
        info = identity.lookup(req, readers=readers)
        assert info.ip == "203.0.113.42"
        assert info.country_code is None
        assert info.city is None
        assert info.isp is None
        assert info.asn is None
    finally:
        readers.close()


def test_present_dir_but_missing_files(tmp_path: Path):
    """Configured dir exists but no MMDB files -> no enrichment, no exception."""
    readers = identity.GeoIPReaders(str(tmp_path))
    try:
        req = _FakeRequest.make("203.0.113.42")
        info = identity.lookup(req, readers=readers)
        assert info.ip == "203.0.113.42"
        assert info.country_code is None
    finally:
        readers.close()


def test_db_lookup_returns_enrichment(tmp_path: Path):
    """City + ASN MMDB present -> populated fields."""
    city_db = tmp_path / "GeoLite2-City.mmdb"
    asn_db = tmp_path / "GeoLite2-ASN.mmdb"
    _make_city_db(
        city_db,
        {
            "203.0.113.0/24": {
                "country": {"iso_code": "AT", "names": {"en": "Austria"}},
                "city": {"names": {"en": "Vienna"}},
            }
        },
    )
    _make_asn_db(
        asn_db,
        {"203.0.113.0/24": {
            "autonomous_system_number": 8412,
            "autonomous_system_organization": "Magenta Telekom",
        }},
    )

    readers = identity.GeoIPReaders(str(tmp_path))
    try:
        req = _FakeRequest.make("203.0.113.42")
        info = identity.lookup(req, readers=readers)
        assert info.country_code == "at"
        assert info.city == "Vienna"
        assert info.isp == "Magenta Telekom"
        assert info.asn == "AS8412"
    finally:
        readers.close()


def test_db_mtime_change_triggers_reopen(tmp_path: Path):
    """Replacing MMDB files in-place takes effect on the next lookup.

    Verifies the GeoIPReaders._stat_or_reopen path: when the file's mtime advances,
    the next .city() call returns a freshly-opened reader. In production, an
    operator runs ``mv new.mmdb GeoLite2-City.mmdb``; on POSIX, that rename is
    atomic and the old open reader is detached when the inode flips. On Windows,
    open files cannot be renamed-over without first releasing the handle -- the
    test below does this explicitly through GeoIPReaders.close().
    """
    import os
    import sys
    city_db = tmp_path / "GeoLite2-City.mmdb"
    new_db = tmp_path / "GeoLite2-City.mmdb.new"
    _make_city_db(city_db, {"203.0.113.0/24": {"country": {"iso_code": "AT", "names": {"en": "Austria"}}}})

    readers = identity.GeoIPReaders(str(tmp_path))
    try:
        req = _FakeRequest.make("203.0.113.42")
        first = identity.lookup(req, readers=readers)
        assert first.country_code == "at"

        _make_city_db(new_db, {"203.0.113.0/24": {"country": {"iso_code": "DE", "names": {"en": "Germany"}}}})
        future = time.time() + 5
        os.utime(new_db, (future, future))

        # On POSIX the rename succeeds while the file is still mapped; the
        # _stat_or_reopen path detects the mtime jump on the next .city() call
        # and re-opens. On Windows the os.replace fails ([WinError 5] / 32) if
        # the reader holds the handle, so we close first -- which itself is the
        # supported way to clear the cache and forces a reopen on next access.
        if sys.platform == "win32":
            with readers._lock:
                if readers._city is not None:
                    readers._city.close()
                    readers._city = None
        os.replace(new_db, city_db)

        second = identity.lookup(req, readers=readers)
        assert second.country_code == "de"
    finally:
        readers.close()


# Broken-DB pinning ====================================================================================================
def test_broken_db_is_pinned_until_mtime_changes(tmp_path: Path, caplog):
    """A corrupt MMDB must be retried at most once per mtime change.

    Without the mtime-pinning, the failing open_database call would re-run on
    EVERY request -- log-spamming WARN and burning CPU on a known-broken file.
    Verifies that:
      (1) the first failed open does NOT raise (lookup still returns IP-only),
      (2) subsequent lookups do NOT call open_database again until the file's
          mtime advances,
      (3) the operator-controlled "I fixed it" signal (writing a new file with
          fresh mtime) un-pins the broken state.
    """
    import logging
    import os
    from unittest.mock import patch

    city_db = tmp_path / "GeoLite2-City.mmdb"
    # Garbage bytes -- maxminddb.open_database will raise InvalidDatabaseError.
    city_db.write_bytes(b"this is not an MMDB file")
    readers = identity.GeoIPReaders(str(tmp_path))
    real_open = identity.maxminddb.open_database
    open_calls: list[str] = []

    def counting_open(path: str):
        open_calls.append(path)
        return real_open(path)

    try:
        with caplog.at_level(logging.WARNING, logger="postern.identity"), \
             patch.object(identity.maxminddb, "open_database", side_effect=counting_open):
            req = _FakeRequest.make("203.0.113.42")

            # First lookup: tries to open, fails, returns IP-only.
            info1 = identity.lookup(req, readers=readers)
            assert info1.country_code is None
            first_call_count = len(open_calls)
            assert first_call_count >= 1

            # Multiple subsequent lookups: must NOT re-attempt open_database
            # because mtime hasn't changed.
            for _ in range(5):
                identity.lookup(req, readers=readers)
            assert len(open_calls) == first_call_count, (f"open_database retried on unchanged mtime: {open_calls!r}")

            # Operator rewrites the file with a valid MMDB and bumps mtime.
            _make_city_db(city_db, {"203.0.113.0/24": {"country": {"iso_code": "AT", "names": {"en": "Austria"}}}})
            future = time.time() + 5
            os.utime(city_db, (future, future))

            info2 = identity.lookup(req, readers=readers)
            # Should now succeed and country_code is populated.
            assert info2.country_code == "at"
            # And open_database was called again (because mtime advanced).
            assert len(open_calls) > first_call_count
    finally:
        readers.close()


# UA parsing ===========================================================================================================
@pytest.mark.parametrize(
    "ua,expected_substr",
    [
        (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
            "Chrome"
        ),
        (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
            "Chrome"
        ),
        ("Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0", "Firefox"),
        (
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
            "Safari"
        ),
        (
            "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36",
            "Chrome"
        ),
        (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0",
            "Edge"
        ),
    ],
)
def test_user_agent_parsing_known(ua: str, expected_substr: str):
    req = _FakeRequest.make("203.0.113.42", user_agent=ua)
    info = identity.lookup(req, readers=None)
    assert expected_substr in info.client
    # Format is "<Browser> <version> · <OS>"; ensure the middle dot separator is present.
    assert "·" in info.client


def test_user_agent_empty_yields_unknown():
    req = _FakeRequest.make("203.0.113.42", user_agent="")
    info = identity.lookup(req, readers=None)
    assert info.client == "Unknown client"


def test_user_agent_garbage_yields_unknown():
    req = _FakeRequest.make("203.0.113.42", user_agent="]]][not a UA{{{")
    info = identity.lookup(req, readers=None)
    assert info.client == "Unknown client"
