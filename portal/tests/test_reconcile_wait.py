"""The `postern reconcile --wait` completion handshake (issue #196).

Real FIFOs on tmp_path, no Docker, no portal. Every test either signals first and
then reads (so select() returns without waiting) or asserts the timeout branch with
timeout=0 -- nothing here waits on the clock.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

from postern import reconcile_wait


def _raise_permission_error(*_args, **_kwargs):
    raise PermissionError("simulated")


# Paths ================================================================================================================
def test_data_dir_is_the_database_directory():
    assert reconcile_wait.data_dir("/data/postern.db") == Path("/data")
    assert reconcile_wait.waiters_dir("/data/postern.db") == Path("/data/.reconcile-waiters")


# Registration and signalling ==========================================================================================
def test_register_waiter_creates_a_fifo_the_snapshot_sees(tmp_path):
    db_path = str(tmp_path / "postern.db")
    waiter = reconcile_wait.register_waiter(db_path)
    try:
        assert waiter.path.parent == tmp_path / reconcile_wait.WAITERS_DIRNAME
        assert stat.S_ISFIFO(waiter.path.stat().st_mode)
        assert reconcile_wait.snapshot_waiters(db_path) == [waiter.path]
    finally:
        reconcile_wait.close_waiter(waiter)


def test_notify_reports_a_successful_pass(tmp_path):
    db_path = str(tmp_path / "postern.db")
    waiter = reconcile_wait.register_waiter(db_path)
    try:
        reconcile_wait.notify_waiters(reconcile_wait.snapshot_waiters(db_path), ok=True)
        # timeout=0 proves the wake already happened: select() returns without waiting.
        assert reconcile_wait.wait_for_notify(waiter, timeout=0) == "ok"
    finally:
        reconcile_wait.close_waiter(waiter)


def test_notify_reports_a_failed_pass(tmp_path):
    db_path = str(tmp_path / "postern.db")
    waiter = reconcile_wait.register_waiter(db_path)
    try:
        reconcile_wait.notify_waiters(reconcile_wait.snapshot_waiters(db_path), ok=False)
        assert reconcile_wait.wait_for_notify(waiter, timeout=0) == "failed"
    finally:
        reconcile_wait.close_waiter(waiter)


def test_a_writer_that_writes_nothing_counts_as_failure(tmp_path):
    """Fail safe: a write end opened and closed without a byte (a loop that died
    mid-notify) must not be readable as success."""
    db_path = str(tmp_path / "postern.db")
    waiter = reconcile_wait.register_waiter(db_path)
    try:
        os.close(os.open(waiter.path, os.O_WRONLY | os.O_NONBLOCK))
        assert reconcile_wait.wait_for_notify(waiter, timeout=0) == "failed"
    finally:
        reconcile_wait.close_waiter(waiter)


def test_wait_for_notify_reports_timeout_without_a_signal(tmp_path):
    db_path = str(tmp_path / "postern.db")
    waiter = reconcile_wait.register_waiter(db_path)
    try:
        assert reconcile_wait.wait_for_notify(waiter, timeout=0) is None
    finally:
        reconcile_wait.close_waiter(waiter)


def test_close_waiter_removes_both_files(tmp_path):
    db_path = str(tmp_path / "postern.db")
    waiter = reconcile_wait.register_waiter(db_path)
    reconcile_wait.close_waiter(waiter)
    assert not waiter.path.exists()
    assert not waiter.lock_path.exists()
    assert reconcile_wait.snapshot_waiters(db_path) == []
    assert list(reconcile_wait.waiters_dir(db_path).iterdir()) == []


def test_register_waiter_retries_when_the_sweeper_collects_its_lock(tmp_path, monkeypatch):
    """A sweeper may collect the lock file in the window between creating it and
    locking it. st_nlink == 0 is how that is detected; losing the race must cost one
    more attempt, not the command."""
    db_path = str(tmp_path / "postern.db")
    real_fstat = os.fstat
    calls: list[int] = []

    class _Unlinked:
        st_nlink = 0

    def flaky_fstat(fd, *args, **kwargs):
        calls.append(fd)
        if len(calls) == 1:
            return _Unlinked()  # as if a sweeper had collected the lock file
        return real_fstat(fd, *args, **kwargs)

    monkeypatch.setattr(os, "fstat", flaky_fstat)
    waiter = reconcile_wait.register_waiter(db_path)
    try:
        assert len(calls) == 2
        assert waiter.path.exists()
        assert waiter.lock_path.exists()
    finally:
        reconcile_wait.close_waiter(waiter)


def test_snapshot_ignores_lock_files(tmp_path):
    db_path = str(tmp_path / "postern.db")
    waiter = reconcile_wait.register_waiter(db_path)
    try:
        assert waiter.lock_path.exists()
        assert reconcile_wait.snapshot_waiters(db_path) == [waiter.path]
    finally:
        reconcile_wait.close_waiter(waiter)


# Garbage collection ===================================================================================================
def test_notify_leaves_a_reader_less_fifo_alone(tmp_path):
    """It may be a registration in progress. Deleting it is the sweeper's call, and
    only once its lock is free."""
    db_path = str(tmp_path / "postern.db")
    directory = reconcile_wait.waiters_dir(db_path)
    directory.mkdir()
    lonely = directory / "deadbeef"
    os.mkfifo(lonely)
    reconcile_wait.notify_waiters([lonely], ok=True)
    assert lonely.exists()


def test_sweep_keeps_a_pair_whose_lock_is_held(tmp_path):
    db_path = str(tmp_path / "postern.db")
    waiter = reconcile_wait.register_waiter(db_path)
    try:
        reconcile_wait.sweep_orphan_waiters(db_path)
        assert waiter.path.exists()
        assert waiter.lock_path.exists()
    finally:
        reconcile_wait.close_waiter(waiter)


def test_sweep_removes_a_pair_nobody_holds(tmp_path):
    """What a CLI killed after registering leaves behind: both files present, lock
    free. Uncollected these accumulate on the postern-data volume forever."""
    db_path = str(tmp_path / "postern.db")
    directory = reconcile_wait.waiters_dir(db_path)
    directory.mkdir()
    abandoned = directory / "deadbeef"
    abandoned_lock = directory / f"deadbeef{reconcile_wait.LOCK_SUFFIX}"
    os.mkfifo(abandoned)
    abandoned_lock.touch()
    reconcile_wait.sweep_orphan_waiters(db_path)
    assert not abandoned.exists()
    assert not abandoned_lock.exists()


def test_sweep_collects_a_lock_left_without_its_fifo(tmp_path):
    """A CLI killed between locking and mkfifo leaves only the lock file."""
    db_path = str(tmp_path / "postern.db")
    directory = reconcile_wait.waiters_dir(db_path)
    directory.mkdir()
    orphan_lock = directory / f"deadbeef{reconcile_wait.LOCK_SUFFIX}"
    orphan_lock.touch()
    reconcile_wait.sweep_orphan_waiters(db_path)
    assert not orphan_lock.exists()


# Nothing here may raise ===============================================================================================
# An exception from any of these escapes reconciliation_loop, whose task app.py never
# inspects until shutdown -- leaving a portal that answers /healthz and has silently
# stopped reconciling. That is the failure class this whole issue exists to close.
def test_snapshot_never_raises(tmp_path, monkeypatch):
    db_path = str(tmp_path / "postern.db")
    reconcile_wait.waiters_dir(db_path).mkdir()
    monkeypatch.setattr(Path, "iterdir", _raise_permission_error)
    assert reconcile_wait.snapshot_waiters(db_path) == []


def test_snapshot_of_a_missing_directory_is_empty(tmp_path):
    assert reconcile_wait.snapshot_waiters(str(tmp_path / "postern.db")) == []


def test_sweep_of_a_missing_directory_is_a_no_op(tmp_path):
    """First boot: nothing has registered yet, so the directory does not exist. The
    sweep must neither raise nor create it."""
    db_path = str(tmp_path / "postern.db")
    reconcile_wait.sweep_orphan_waiters(db_path)
    assert not reconcile_wait.waiters_dir(db_path).exists()


def test_snapshot_ignores_a_regular_file_left_in_the_directory(tmp_path):
    """notify_waiters opens whatever the snapshot hands it for writing; a stray
    regular file would get its first byte overwritten on every pass."""
    db_path = str(tmp_path / "postern.db")
    directory = reconcile_wait.waiters_dir(db_path)
    directory.mkdir()
    stray = directory / "notes.txt"
    stray.write_text("hello\n")
    assert reconcile_wait.snapshot_waiters(db_path) == []
    assert stray.read_text() == "hello\n"


def test_sweep_never_raises(tmp_path, monkeypatch):
    db_path = str(tmp_path / "postern.db")
    reconcile_wait.waiters_dir(db_path).mkdir()
    monkeypatch.setattr(Path, "iterdir", _raise_permission_error)
    reconcile_wait.sweep_orphan_waiters(db_path)


def test_notify_never_raises(tmp_path, monkeypatch):
    db_path = str(tmp_path / "postern.db")
    reconcile_wait.waiters_dir(db_path).mkdir()
    monkeypatch.setattr(os, "open", _raise_permission_error)
    reconcile_wait.notify_waiters([reconcile_wait.waiters_dir(db_path) / "nope"], ok=True)
