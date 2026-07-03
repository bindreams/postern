"""Unit tests for the Cloudflare edge IP-range publisher (EDGE_PROFILE=cloudflare)."""
from __future__ import annotations

import http.client
import json
import urllib.error
from dataclasses import dataclass

import pytest

from postern_provisioner import edge_ranges


# Fakes ================================================================================================================
@dataclass
class FakeFetcher:
    """Returns a canned body, or raises a canned exception, from fetch()."""
    body: str | None = None
    raise_exc: BaseException | None = None
    calls: int = 0

    def fetch(self) -> str:
        self.calls += 1
        if self.raise_exc is not None:
            raise self.raise_exc
        assert self.body is not None
        return self.body


# Real fetcher seam ====================================================================================================
def test_real_cloudflare_fetcher_raises_urlerror_on_unreachable_host():
    """Exercise the actual urllib path (every reconcile test swaps in FakeFetcher).
    An unreachable origin must raise URLError -- a type inside reconcile's declared
    catch set, so a real network failure degrades to last-known-good, not a crash."""
    fetcher = edge_ranges.CloudflareIpsFetcher(url="http://127.0.0.1:1/", timeout=1.0)
    with pytest.raises(urllib.error.URLError):
        fetcher.fetch()


def _cf_body(ipv4, ipv6, *, success=True, errors=None, messages=None) -> str:
    return json.dumps({
        "result": {"ipv4_cidrs": list(ipv4), "ipv6_cidrs": list(ipv6), "etag": "x"},
        "success": success,
        "errors": errors or [],
        "messages": messages or [],
    })


SAMPLE_V4 = ["173.245.48.0/20", "103.21.244.0/22", "104.16.0.0/13"]
SAMPLE_V6 = ["2606:4700::/32", "2400:cb00::/32"]


# reconcile_edge_ranges: happy path ====================================================================================
def test_first_tick_writes_and_reports_changed(tmp_path):
    out = tmp_path / "cloudflare-ranges.conf"
    res = edge_ranges.reconcile_edge_ranges(fetcher=FakeFetcher(body=_cf_body(SAMPLE_V4, SAMPLE_V6)), out_path=out)
    assert res.changed is True
    assert res.error is None
    assert res.ipv4_count == 3 and res.ipv6_count == 2
    text = out.read_text()
    for cidr in SAMPLE_V4 + SAMPLE_V6:
        assert f"set_real_ip_from {cidr};" in text
    # No real_ip_header here -- that lives in edge.conf (render.sh); this file is include-only.
    assert "real_ip_header" not in text


def test_output_is_canonically_sorted(tmp_path):
    out = tmp_path / "cloudflare-ranges.conf"
    edge_ranges.reconcile_edge_ranges(fetcher=FakeFetcher(body=_cf_body(SAMPLE_V4, SAMPLE_V6)), out_path=out)
    v4 = [
        ln.split()[1].rstrip(";") for ln in out.read_text().splitlines() if "set_real_ip_from" in ln and ":" not in ln
    ]
    assert v4 == ["103.21.244.0/22", "104.16.0.0/13", "173.245.48.0/20"]


def test_reordered_payload_is_not_a_change(tmp_path):
    """Canonical sort collapses a reordered-but-equal payload -> no rewrite (atomic-on-change)."""
    out = tmp_path / "cloudflare-ranges.conf"
    first = edge_ranges.reconcile_edge_ranges(fetcher=FakeFetcher(body=_cf_body(SAMPLE_V4, SAMPLE_V6)), out_path=out)
    assert first.changed is True
    before = out.read_text()
    shuffled = edge_ranges.reconcile_edge_ranges(
        fetcher=FakeFetcher(body=_cf_body(list(reversed(SAMPLE_V4)), list(reversed(SAMPLE_V6)))),
        out_path=out,
    )
    assert shuffled.changed is False
    assert shuffled.error is None
    assert out.read_text() == before  # file untouched


# reconcile_edge_ranges: exception taxonomy ============================================================================
def test_out_of_set_exception_propagates(tmp_path):
    """A TypeError raised in the FETCH stage is out of the fetch catch family
    (URLError, HTTPException, OSError, TimeoutError) and MUST escape -- crash the
    tick loudly, never fold into result.error."""
    out = tmp_path / "cloudflare-ranges.conf"
    with pytest.raises(TypeError, match="boom"):
        edge_ranges.reconcile_edge_ranges(fetcher=FakeFetcher(raise_exc=TypeError("boom")), out_path=out)
    assert not out.exists()


def test_incomplete_read_is_caught_as_error(tmp_path):
    """http.client.IncompleteRead (an HTTPException) is IN the fetch catch family;
    it lands in result.error and nothing escapes / nothing is written."""
    out = tmp_path / "cloudflare-ranges.conf"
    res = edge_ranges.reconcile_edge_ranges(
        fetcher=FakeFetcher(raise_exc=http.client.IncompleteRead(b"partial")),
        out_path=out,
    )
    assert res.changed is False
    assert res.error is not None and "IncompleteRead" in res.error
    assert not out.exists()


def test_fetch_failure_keeps_last_known_good(tmp_path):
    out = tmp_path / "cloudflare-ranges.conf"
    good = edge_ranges.reconcile_edge_ranges(fetcher=FakeFetcher(body=_cf_body(SAMPLE_V4, SAMPLE_V6)), out_path=out)
    assert good.changed
    before = out.read_text()
    res = edge_ranges.reconcile_edge_ranges(
        fetcher=FakeFetcher(raise_exc=urllib.error.URLError("dns down")), out_path=out
    )
    assert res.error is not None and "URLError" in res.error
    assert out.read_text() == before  # last-known-good retained


def test_malformed_json_is_parse_error(tmp_path):
    out = tmp_path / "cloudflare-ranges.conf"
    res = edge_ranges.reconcile_edge_ranges(fetcher=FakeFetcher(body="{not json"), out_path=out)
    assert res.changed is False
    assert res.error is not None and "JSONDecodeError" in res.error
    assert not out.exists()


def test_bad_cidr_is_parse_error(tmp_path):
    """A non-CIDR string makes ipaddress raise AddressValueError (a ValueError)
    inside the parse stage -> folded into result.error, allowlist untouched."""
    out = tmp_path / "cloudflare-ranges.conf"
    res = edge_ranges.reconcile_edge_ranges(fetcher=FakeFetcher(body=_cf_body(["not-a-cidr"], [])), out_path=out)
    assert res.changed is False
    assert res.error is not None
    assert not out.exists()


def test_wrong_shape_typeerror_is_parse_error(tmp_path):
    """result is a list, not a dict -> result["ipv4_cidrs"] raises TypeError INSIDE
    the parse stage (catch family includes TypeError) -> result.error. Contrast
    with the fetch-stage TypeError which propagates."""
    out = tmp_path / "cloudflare-ranges.conf"
    body = json.dumps({"result": ["not", "a", "dict"], "success": True, "errors": [], "messages": []})
    res = edge_ranges.reconcile_edge_ranges(fetcher=FakeFetcher(body=body), out_path=out)
    assert res.changed is False
    assert res.error is not None and "TypeError" in res.error
    assert not out.exists()


def test_success_false_surfaces_cf_errors(tmp_path):
    out = tmp_path / "cloudflare-ranges.conf"
    body = _cf_body([], [],
                    success=False,
                    errors=[{"code": 9109, "message": "Invalid access token"}],
                    messages=["retry"])
    res = edge_ranges.reconcile_edge_ranges(fetcher=FakeFetcher(body=body), out_path=out)
    assert res.changed is False
    assert res.error is not None
    assert "9109" in res.error and "Invalid access token" in res.error
    assert not out.exists()


def test_empty_ranges_is_error_not_wipe(tmp_path):
    """A success=true payload with empty CIDR lists must NOT overwrite the
    last-known-good allowlist with an empty file."""
    out = tmp_path / "cloudflare-ranges.conf"
    edge_ranges.reconcile_edge_ranges(fetcher=FakeFetcher(body=_cf_body(SAMPLE_V4, SAMPLE_V6)), out_path=out)
    before = out.read_text()
    res = edge_ranges.reconcile_edge_ranges(fetcher=FakeFetcher(body=_cf_body([], [])), out_path=out)
    assert res.changed is False
    assert res.error is not None
    assert out.read_text() == before


# atomic write =========================================================================================================
def test_write_oserror_returns_error_and_leaves_file_untouched(tmp_path, monkeypatch):
    """An OSError raised during _atomic_write (e.g. disk full, bad perms) must
    surface as result.error with changed=False and leave any pre-existing
    on-disk file untouched (last-known-good preserved)."""
    out = tmp_path / "cloudflare-ranges.conf"
    # Seed a known-good file so we can verify it is not clobbered.
    good = edge_ranges.reconcile_edge_ranges(fetcher=FakeFetcher(body=_cf_body(SAMPLE_V4, SAMPLE_V6)), out_path=out)
    assert good.changed
    before = out.read_text()

    def _raise_disk_full(*_a, **_kw):
        raise OSError("disk full")

    monkeypatch.setattr(edge_ranges, "_atomic_write", _raise_disk_full)
    # Use a different payload so the content-equality short-circuit does not skip _atomic_write.
    alt_v4 = ["103.21.244.0/22"]
    res = edge_ranges.reconcile_edge_ranges(fetcher=FakeFetcher(body=_cf_body(alt_v4, [])), out_path=out)

    assert res.error is not None and "OSError" in res.error
    assert res.changed is False
    assert out.read_text() == before  # last-known-good retained


def test_no_temp_files_left_after_write(tmp_path):
    out = tmp_path / "cloudflare-ranges.conf"
    edge_ranges.reconcile_edge_ranges(fetcher=FakeFetcher(body=_cf_body(SAMPLE_V4, SAMPLE_V6)), out_path=out)
    assert [p.name for p in tmp_path.iterdir() if p.name != out.name] == []


def test_output_file_world_readable(tmp_path):
    out = tmp_path / "cloudflare-ranges.conf"
    edge_ranges.reconcile_edge_ranges(fetcher=FakeFetcher(body=_cf_body(SAMPLE_V4, SAMPLE_V6)), out_path=out)
    assert (out.stat().st_mode & 0o777) & 0o004
