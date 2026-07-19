"""Tests for the provisioner entrypoint's tick wiring (the ssl tick specifically).

entrypoint.py imports `from postern_mta import ...`; that name only exists in-image
(the Dockerfile COPYs postern.mta -> site-packages/postern_mta). We alias the real
postern.mta modules under that name and load the file by path, so the wiring is
actually exercised (not just py_compile'd)."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

import postern.mta  # noqa: F401  (aliased below as `postern_mta`)
import postern.mta.dkim
import postern.mta.rotation

REPO_ROOT = Path(__file__).parents[2]


@pytest.fixture
def entrypoint(monkeypatch):
    import postern.mta as _mta
    monkeypatch.setitem(sys.modules, "postern_mta", _mta)
    monkeypatch.setitem(sys.modules, "postern_mta.dkim", postern.mta.dkim)
    monkeypatch.setitem(sys.modules, "postern_mta.rotation", postern.mta.rotation)
    spec = importlib.util.spec_from_file_location(
        "provisioner_entrypoint", REPO_ROOT / "provisioner" / "entrypoint.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_build_ticks_wires_ssl_tick_to_target(entrypoint, monkeypatch):
    from postern_provisioner.enablement import compute_enablement
    captured: dict = {}
    monkeypatch.setattr(entrypoint.ssl_driver, "SslModeRunner", lambda: "runner")
    monkeypatch.setattr(entrypoint.ssl_driver, "reconcile_and_persist", lambda **k: captured.update(k))
    counters = {"ssl": 0}
    en = compute_enablement(
        dns_provider="cloudflare", cert_renewal=False, edge_profile="cloudflare", mta_deployed=False
    )
    ticks = entrypoint._build_ticks("postern.test", "s", "full", counters, en)
    assert "ssl" in ticks
    ticks["ssl"]()
    assert captured["settings"].domain == "postern.test"
    assert captured["settings"].target == "full"  # the configured target flows through
    assert counters["ssl"] == 0  # success path resets the counter


def test_try_advance_ssl_counts_failures(entrypoint, monkeypatch):
    # The except branch of the entrypoint wrapper (distinct from reconcile_ssl_mode's own
    # state-counter): a raising reconcile_and_persist must bump counters["ssl"].
    monkeypatch.setattr(entrypoint.ssl_driver, "SslModeRunner", lambda: "runner")

    def boom(**k):
        raise RuntimeError("provisioner-side bug")

    monkeypatch.setattr(entrypoint.ssl_driver, "reconcile_and_persist", boom)
    counters = {"ssl": 0}
    entrypoint._try_advance_ssl("postern.test", "strict", counters)
    assert counters["ssl"] == 1
    entrypoint._try_advance_ssl("postern.test", "strict", counters)
    assert counters["ssl"] == 2  # accumulates across ticks


def test_ssl_target_from_env_reads_the_right_var_and_validates(entrypoint, monkeypatch):
    # Pins the env-name -> parse_ssl_target wiring: right var name, and parse applied.
    monkeypatch.setenv("EDGE_CF_SSL_MODE", "full")
    assert entrypoint._ssl_target_from_env() == "full"
    monkeypatch.delenv("EDGE_CF_SSL_MODE", raising=False)
    assert entrypoint._ssl_target_from_env() == "strict"  # default
    monkeypatch.setenv("EDGE_CF_SSL_MODE", "off")
    with pytest.raises(ValueError):  # bad value fails loud (not silently coerced)
        entrypoint._ssl_target_from_env()


def _en(entrypoint, *, manage_ssl_mode):
    from postern_provisioner.enablement import compute_enablement
    return compute_enablement(
        dns_provider="cloudflare", cert_renewal=False, edge_profile="cloudflare", mta_deployed=False,
        manage_ssl_mode=manage_ssl_mode,
    )


def test_resolve_ssl_target_enabled_validates(entrypoint, monkeypatch):
    # Management ON: the env value is validated. Good -> returned; bad -> ValueError
    # (main() turns it into die()). Pins the load-bearing fail-loud path.
    en = _en(entrypoint, manage_ssl_mode=True)
    monkeypatch.setenv("EDGE_CF_SSL_MODE", "full")
    assert entrypoint._resolve_ssl_target(en) == "full"
    monkeypatch.setenv("EDGE_CF_SSL_MODE", "off")
    with pytest.raises(ValueError):
        entrypoint._resolve_ssl_target(en)


def test_resolve_ssl_target_disabled_tolerates_bad_value(entrypoint, monkeypatch):
    # Management OFF: a stray/typo'd EDGE_CF_SSL_MODE must NOT raise (it would die() the
    # whole provisioner, taking down DKIM/cert/mta). Returns the unused placeholder.
    en = _en(entrypoint, manage_ssl_mode=False)
    monkeypatch.setenv("EDGE_CF_SSL_MODE", "off")  # bad, but inert when disabled
    assert entrypoint._resolve_ssl_target(en) == "strict"


def test_resolve_ssl_target_or_die_exits_on_bad_value(entrypoint, monkeypatch):
    # The main()-glue: a bad value under management-on must die() (SystemExit), not raise
    # an unhandled ValueError nor fall through with an invalid target.
    en = _en(entrypoint, manage_ssl_mode=True)
    monkeypatch.setenv("EDGE_CF_SSL_MODE", "off")
    with pytest.raises(SystemExit):
        entrypoint._resolve_ssl_target_or_die(en)


def test_resolve_ssl_target_or_die_returns_valid(entrypoint, monkeypatch):
    en = _en(entrypoint, manage_ssl_mode=True)
    monkeypatch.setenv("EDGE_CF_SSL_MODE", "full")
    assert entrypoint._resolve_ssl_target_or_die(en) == "full"
