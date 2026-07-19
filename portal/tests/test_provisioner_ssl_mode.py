"""Tests for the provisioner zone SSL/TLS-mode reconciler + state."""
from __future__ import annotations

import datetime as dt
import logging
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from postern_provisioner import ssl_mode

_NOW = dt.datetime(2026, 7, 18, tzinfo=dt.timezone.utc)


@dataclass
class FakeRunner:
    fail: bool = False
    stderr: str = ""
    observed: str | None = None  # mode reported on success; None -> the target (a full raise)
    calls: list[tuple[str, str]] = field(default_factory=list)

    def set(self, domain: str, target: str) -> str:
        self.calls.append((domain, target))
        if self.fail:
            raise subprocess.CalledProcessError(1, ["postern-dns", "ssl-set", domain, target], stderr=self.stderr)
        return target if self.observed is None else self.observed


def _settings():
    return ssl_mode.SslModeSettings(domain="postern.test", target="strict")


def test_reconcile_records_success(caplog):
    caplog.set_level(logging.INFO, logger="postern_provisioner.ssl_mode")
    runner = FakeRunner()
    new = ssl_mode.reconcile_ssl_mode(ssl_mode.SslModeState(), settings=_settings(), runner=runner, now=_NOW)
    assert runner.calls == [("postern.test", "strict")]
    assert new.last_set_ok_iso == _NOW.isoformat()
    assert new.consecutive_failures == 0
    assert new.last_observed_mode == "strict"  # the mode CF left the zone in
    assert "SSL/TLS mode" in caplog.text


def test_reconcile_records_target_vs_actual_drift(caplog):
    # target=strict but the zone was already at full -> raise-only leaves it at full;
    # last_observed_mode records the ACTUAL 'full' and a drift warning is logged (%r -> quoted).
    caplog.set_level(logging.WARNING, logger="postern_provisioner.ssl_mode")
    new = ssl_mode.reconcile_ssl_mode(
        ssl_mode.SslModeState(), settings=_settings(), runner=FakeRunner(observed="full"), now=_NOW
    )
    assert new.last_observed_mode == "full"
    assert "is at 'full'" in caplog.text and "target is 'strict'" in caplog.text


def test_reconcile_drift_warning_deduped_on_repeat(caplog):
    # Second tick observing the SAME already-recorded drift must NOT re-emit the WARNING
    # (warn-once, not ~24x/day). Pins the `observed != new.last_observed_mode` dedup clause.
    caplog.set_level(logging.WARNING, logger="postern_provisioner.ssl_mode")
    prior = ssl_mode.SslModeState(last_set_ok_iso="2026-01-01T00:00:00+00:00", last_observed_mode="full")
    ssl_mode.reconcile_ssl_mode(prior, settings=_settings(), runner=FakeRunner(observed="full"), now=_NOW)
    assert not any(r.levelno == logging.WARNING for r in caplog.records)


@pytest.mark.parametrize("bogus", ["", "flexible", "off", "garbage"])
def test_reconcile_rejects_unexpected_observed_mode(bogus, caplog):
    # ssl-set exited 0 but printed an unexpected mode (contract violation): reconcile must
    # treat it as a FAILURE (red healthcheck), NOT a green success on a bogus mode.
    caplog.set_level(logging.ERROR, logger="postern_provisioner.ssl_mode")
    new = ssl_mode.reconcile_ssl_mode(
        ssl_mode.SslModeState(), settings=_settings(), runner=FakeRunner(observed=bogus), now=_NOW
    )
    assert new.last_set_ok_iso is None
    assert new.consecutive_failures == 1
    assert "unexpected mode" in new.last_error
    assert "unexpected mode" in caplog.text


def test_reconcile_steady_state_is_a_noop(caplog):
    caplog.set_level(logging.INFO, logger="postern_provisioner.ssl_mode")
    prior = ssl_mode.SslModeState(last_set_ok_iso="2026-01-01T00:00:00+00:00", last_observed_mode="strict")
    new = ssl_mode.reconcile_ssl_mode(prior, settings=_settings(), runner=FakeRunner(), now=_NOW)
    assert new == prior  # structured proof of no-op; the caller writes nothing
    # No first-success/recovery transition -> no INFO log fires (level-based, so it does
    # not rot if the success message's wording changes).
    assert not any(r.levelno == logging.INFO for r in caplog.records)


def test_reconcile_counts_failures_and_preserves_prior_ok():
    prior = ssl_mode.SslModeState(last_set_ok_iso="2026-01-01T00:00:00+00:00")
    runner = FakeRunner(fail=True, stderr="SSL/TLS mode not available on this plan")
    new = ssl_mode.reconcile_ssl_mode(prior, settings=_settings(), runner=runner, now=_NOW)
    assert new.consecutive_failures == 1
    assert new.last_set_ok_iso == "2026-01-01T00:00:00+00:00"
    assert "SSL/TLS mode not available on this plan" in new.last_error


def test_reconcile_accumulates_consecutive_failures():
    prior = ssl_mode.SslModeState(consecutive_failures=2)
    new = ssl_mode.reconcile_ssl_mode(prior, settings=_settings(), runner=FakeRunner(fail=True, stderr="boom"), now=_NOW)
    assert new.consecutive_failures == 3


def test_reconcile_recovery_restamps_set_ok():
    prior = ssl_mode.SslModeState(last_set_ok_iso="2026-01-01T00:00:00+00:00", consecutive_failures=1)
    new = ssl_mode.reconcile_ssl_mode(prior, settings=_settings(), runner=FakeRunner(), now=_NOW)
    assert new.last_set_ok_iso == _NOW.isoformat()
    assert new.consecutive_failures == 0


def test_reconcile_records_launch_failure_in_state():
    class MissingBinaryRunner:

        def set(self, domain, target):
            raise FileNotFoundError(2, "No such file or directory", "/usr/local/bin/postern-dns")

    new = ssl_mode.reconcile_ssl_mode(ssl_mode.SslModeState(), settings=_settings(), runner=MissingBinaryRunner(), now=_NOW)
    assert new.consecutive_failures == 1
    assert new.last_set_ok_iso is None
    assert "postern-dns" in new.last_error


def test_reconcile_and_persist_writes_only_on_change(tmp_path: Path, monkeypatch):
    writes: list = []
    real_write = ssl_mode.write_state
    monkeypatch.setattr(ssl_mode, "write_state", lambda st, **k: (writes.append(st), real_write(st, **k))[-1])
    s = _settings()
    ssl_mode.reconcile_and_persist(settings=s, runner=FakeRunner(), state_dir=tmp_path, now=_NOW)
    assert len(writes) == 1
    ssl_mode.reconcile_and_persist(settings=s, runner=FakeRunner(), state_dir=tmp_path, now=_NOW)
    assert len(writes) == 1


def test_reconcile_and_persist_distinct_log_on_write_failure(tmp_path: Path, monkeypatch, caplog):
    # The COMPOUND-failure path: the CF set itself failed AND the state write then failed
    # (the write branch is entered on failure too, since the failure-state differs from
    # prior). The write-failure log must be neutral -- it must NOT emit the success line,
    # or an operator would think the set landed. INFO level so the success line WOULD be
    # captured if wrongly emitted. Still re-raises so the tick is counted.
    caplog.set_level(logging.INFO, logger="postern_provisioner.ssl_mode")

    def boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(ssl_mode, "write_state", boom)
    with pytest.raises(OSError):
        ssl_mode.reconcile_and_persist(
            settings=_settings(), runner=FakeRunner(fail=True, stderr="403 token lacks Zone Settings:Edit"),
            state_dir=tmp_path, now=_NOW,
        )
    assert "persisting ssl-mode state failed" in caplog.text
    # Must not claim success on the compound-failure path. Level-based (no INFO record
    # fires when the set failed), so it does not rot if the success wording changes.
    assert not any(r.levelno == logging.INFO for r in caplog.records)


def test_reconcile_and_persist_persists_internal_error_on_unexpected_exception(tmp_path: Path):
    # A programming bug (not subprocess/OSError) escapes reconcile_ssl_mode's narrow
    # catch. reconcile_and_persist must PERSIST a distinct internal-error record (so
    # `edge ssl-status` / the healthcheck stop reporting stale last-known-good) and
    # re-raise (so _try_advance_ssl logs the traceback). Seed a prior success first.
    ssl_mode.write_state(ssl_mode.SslModeState(last_set_ok_iso="2026-01-01T00:00:00+00:00"), state_dir=tmp_path)

    class BuggyRunner:

        def set(self, domain, target):
            raise TypeError("unexpected kwarg")  # NOT a subprocess/OSError

    with pytest.raises(TypeError):
        ssl_mode.reconcile_and_persist(settings=_settings(), runner=BuggyRunner(), state_dir=tmp_path, now=_NOW)
    persisted = ssl_mode.read_state(state_dir=tmp_path)
    assert persisted.consecutive_failures == 1  # no longer stale-green
    assert "internal error" in persisted.last_error
    assert persisted.last_set_ok_iso == "2026-01-01T00:00:00+00:00"  # prior success preserved


def test_parse_ssl_target_accepts_exact():
    assert ssl_mode.parse_ssl_target("full") == "full"
    assert ssl_mode.parse_ssl_target("strict") == "strict"


# Case/whitespace variants MUST fail loud (exact-match): the portal's Literal rejects
# them too, so both containers agree rather than splitting the stack. See parse_ssl_target.
@pytest.mark.parametrize("bad", ["off", "flexible", "", "fulll", "garbage", "Full", "STRICT", " strict ", "full "])
def test_parse_ssl_target_invalid_fails_loud(bad):
    with pytest.raises(ValueError, match="'full' or 'strict'"):
        ssl_mode.parse_ssl_target(bad)


def test_ssl_mode_runner_real_subprocess_argv(tmp_path: Path):
    # Exercise the REAL SslModeRunner (not FakeRunner): the production subprocess path
    # must shell `postern-dns ssl-set <domain> <target>` in that argv order.
    argv_log = tmp_path / "argv.txt"
    fake = tmp_path / "postern-dns"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        f"open({str(argv_log)!r}, 'w').write(' '.join(sys.argv[1:]))\n"
    )
    fake.chmod(0o755)
    assert ssl_mode.SslModeRunner(bin_path=str(fake)).set("postern.test", "strict") == ""  # shim prints nothing
    assert argv_log.read_text() == "ssl-set postern.test strict"


def test_ssl_mode_runner_returns_stdout_observed_mode(tmp_path: Path):
    # ssl-set prints the mode the zone was left in; the runner must return it (stripped),
    # and reconcile_ssl_mode must persist it into last_observed_mode.
    fake = tmp_path / "postern-dns"
    fake.write_text("#!/usr/bin/env python3\nprint('full')\n")
    fake.chmod(0o755)
    runner = ssl_mode.SslModeRunner(bin_path=str(fake))
    assert runner.set("postern.test", "strict") == "full"
    new = ssl_mode.reconcile_ssl_mode(ssl_mode.SslModeState(), settings=_settings(), runner=runner, now=_NOW)
    assert new.last_observed_mode == "full"


def test_ssl_mode_runner_real_subprocess_stderr_flows_to_last_error(tmp_path: Path):
    # A nonzero-exit REAL subprocess: capture_output=True + text=True must give the
    # CalledProcessError a str .stderr, which reconcile_ssl_mode records verbatim (the
    # FakeRunner tests only ASSUME this; here we verify it against real subprocess semantics).
    fake = tmp_path / "postern-dns"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "sys.stderr.write('token lacks Zone Settings:Edit\\n')\n"
        "sys.exit(1)\n"
    )
    fake.chmod(0o755)
    runner = ssl_mode.SslModeRunner(bin_path=str(fake))
    new = ssl_mode.reconcile_ssl_mode(ssl_mode.SslModeState(), settings=_settings(), runner=runner, now=_NOW)
    assert new.consecutive_failures == 1
    assert "Zone Settings:Edit" in new.last_error


def test_reconcile_records_timeout_stderr():
    # SET_TIMEOUT_SECONDS bounds a hung postern-dns child; verify reconcile_ssl_mode
    # records a real subprocess.TimeoutExpired's str .stderr (populated by text=True).
    # Constructed deterministically rather than via a real sleep-past-timeout race (a
    # time-synchronized test), which would be flaky under CI load; the handling of the
    # exact exception type + its .stderr is what matters here.
    class TimeoutRunner:

        def set(self, domain, target):
            raise subprocess.TimeoutExpired(
                cmd=["postern-dns", "ssl-set", domain, target], timeout=120, stderr="partial output before hang\n"
            )

    new = ssl_mode.reconcile_ssl_mode(ssl_mode.SslModeState(), settings=_settings(), runner=TimeoutRunner(), now=_NOW)
    assert new.consecutive_failures == 1
    assert "partial output before hang" in new.last_error


def test_ssl_mode_runner_passes_env_to_child(tmp_path: Path):
    # postern-dns authenticates to CF with CLOUDFLARE_API_TOKEN (+ libdns provider vars)
    # from its environment; the child MUST inherit the runner's env. Pin it: an env={} or
    # token-stripped regression would break live-CF auth while passing the argv/stderr tests.
    import os
    env_log = tmp_path / "env.txt"
    fake = tmp_path / "postern-dns"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import os\n"
        f"open({str(env_log)!r}, 'w').write(os.environ.get('CLOUDFLARE_API_TOKEN', '<missing>'))\n"
    )
    fake.chmod(0o755)
    # Keep PATH etc. (the shebang needs them) but inject a marker token.
    runner = ssl_mode.SslModeRunner(bin_path=str(fake), env={**os.environ, "CLOUDFLARE_API_TOKEN": "tok-abc"})
    runner.set("postern.test", "strict")
    assert env_log.read_text() == "tok-abc"


def test_ssl_mode_runner_passes_timeout(monkeypatch):
    # SET_TIMEOUT_SECONDS must actually reach subprocess.run (it bounds a hung child).
    # Mock-based -> no real wait, no time-sync.
    calls: dict = {}

    def fake_run(*args, **kwargs):
        calls.update(kwargs)

        class R:  # set() reads result.stdout
            stdout = "strict\n"

        return R()

    monkeypatch.setattr(ssl_mode.subprocess, "run", fake_run)
    ssl_mode.SslModeRunner(bin_path="/nonexistent/postern-dns").set("postern.test", "strict")
    assert calls["timeout"] == ssl_mode.SET_TIMEOUT_SECONDS


def test_state_roundtrip(tmp_path: Path):
    st = ssl_mode.SslModeState(
        last_set_ok_iso="2026-07-18T00:00:00+00:00", consecutive_failures=2, last_error="x", last_observed_mode="full"
    )
    ssl_mode.write_state(st, state_dir=tmp_path)
    assert ssl_mode.read_state(state_dir=tmp_path) == st


def test_write_state_is_mode_0644(tmp_path: Path):
    # 0644 is load-bearing cross-container: the portal CLI (`edge ssl-status`, a different
    # UID) reads what the provisioner (UID 110) writes. A dropped os.chmod leaves mkstemp's
    # 0600 and breaks the portal read -- invisible in this single-UID test env otherwise.
    import stat
    ssl_mode.write_state(ssl_mode.SslModeState(last_set_ok_iso="x"), state_dir=tmp_path)
    assert stat.S_IMODE((tmp_path / ssl_mode.STATE_FILENAME).stat().st_mode) == 0o644


def test_read_state_missing_is_empty(tmp_path: Path):
    assert ssl_mode.read_state(state_dir=tmp_path) == ssl_mode.SslModeState()


def test_read_state_corrupt_json_is_empty(tmp_path: Path):
    (tmp_path / ssl_mode.STATE_FILENAME).write_text("{not valid json", encoding="utf-8")
    assert ssl_mode.read_state(state_dir=tmp_path) == ssl_mode.SslModeState()


def test_write_state_cleans_up_tmp_on_replace_failure(tmp_path: Path, monkeypatch):

    def boom(src, dst):
        raise OSError("disk full")

    monkeypatch.setattr(ssl_mode.os, "replace", boom)
    with pytest.raises(OSError):
        ssl_mode.write_state(ssl_mode.SslModeState(last_set_ok_iso="x"), state_dir=tmp_path)
    assert not list(tmp_path.glob(".ssl_mode_state.*.tmp"))
