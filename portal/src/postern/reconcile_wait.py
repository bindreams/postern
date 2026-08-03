"""Completion handshake behind `postern reconcile --wait`.

Kept out of reconciler.py on purpose: that module imports the Docker SDK at module
scope, and the CLI needs this protocol for every `--wait` invocation, including for
commands (`user list`, `mta show-dns`, ...) that never touch Docker. Nothing here
imports outside the standard library.

The protocol, in the data directory that also holds `.reconcile-now`:

    CLI   flock(waiters/<uuid>.lock) -> mkfifo(waiters/<uuid>) -> open read end
                                     -> touch .reconcile-now -> select()
    loop  sweep orphans -> snapshot waiters/ -> run the pass -> write the outcome byte

A FIFO present in the snapshot existed before the pass started, so the pass ran
entirely after whatever the waiter had already done. That ordering is the guarantee
the deploy script buys; the byte carries the outcome.

Ownership: the CLI creates and removes its own pair. `notify_waiters` only writes.
`sweep_orphan_waiters` is the sole garbage collector, and "abandoned" is decided by
an flock rather than by an age threshold, a PID in the filename, or a /proc scan:

  * an age threshold is a timeout wearing a different hat;
  * a PID in the filename is not recycle-safe in this container -- the portal
    restarts on every deploy, PIDs restart at 1, and tini(1)/uvicorn(2) then hold
    the low numbers for the container's whole life, so a FIFO named for PID 2
    would look owned forever;
  * scanning /proc/<pid>/fd needs same-uid access to every process (unprivileged,
    it fails closed and never collects), compares a raw path against the kernel's
    canonical one (a symlinked/relative DATABASE_PATH breaks it), and assumes the
    waiter shares the reconciler's PID namespace (false for a sidecar or `compose
    run` container).

`flock` has none of those properties: namespace-agnostic, path-canonicalisation-
agnostic, works cross-container on the shared volume, and is testable unprivileged.
The lock is taken before the FIFO exists, so a sweeper can never unlink a FIFO that
has a live reader.
"""

from __future__ import annotations

import contextlib
import fcntl
import os
import select
import stat
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

WAITERS_DIRNAME = ".reconcile-waiters"
LOCK_SUFFIX = ".lock"
NOTIFY_OK = b"0"
NOTIFY_FAILED = b"1"


@dataclass
class Waiter:
    """Always tear down via close_waiter -- never unlink or close these fields by hand."""

    path: Path
    fd: int
    lock_path: Path
    lock_fd: int


# Paths ================================================================================================================
def data_dir(database_path: str) -> Path:
    """The directory holding the DB, `.reconcile-now`, and the waiter FIFOs.

    Single derivation on purpose -- cli.py's trigger writer, the reconciler loop's
    watcher, and this protocol all route through here instead of spelling out
    `dirname(database_path)` in more than one place.
    """
    return Path(database_path).parent


def waiters_dir(database_path: str) -> Path:
    return data_dir(database_path) / WAITERS_DIRNAME


def _unlink_quietly(target: Path) -> None:
    with contextlib.suppress(OSError):
        target.unlink()


# Waiter side (the CLI) ================================================================================================
def register_waiter(database_path: str) -> Waiter:
    """Take a lock, then create the FIFO it protects, and open its read end.

    Order matters: `sweep_orphan_waiters` may only unlink a pair whose lock it can
    take, so once this lock is held the FIFO created under it cannot be collected.
    The one window is between creating the lock file and locking it -- a sweeper that
    got there first has already unlinked the file we now hold, which `st_nlink == 0`
    reports exactly. Then we retry under a fresh name. No attempt limit and no sleep:
    the loop ends the first time an attempt survives, and a sweep runs at most once
    per reconcile pass.
    """
    directory = waiters_dir(database_path)
    directory.mkdir(exist_ok=True)
    while True:
        name = uuid.uuid4().hex
        lock_path = directory / f"{name}{LOCK_SUFFIX}"
        lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        if os.fstat(lock_fd).st_nlink == 0:
            os.close(lock_fd)  # collected in the gap; the name is dead
            continue

        fifo_path = directory / name
        os.mkfifo(fifo_path, 0o600)
        fd = os.open(fifo_path, os.O_RDONLY | os.O_NONBLOCK)
        return Waiter(path=fifo_path, fd=fd, lock_path=lock_path, lock_fd=lock_fd)


def wait_for_notify(waiter: Waiter, *, timeout: float | None) -> str | None:
    """Block until the loop reports a pass.

    Returns "ok" if it completed, "failed" if it raised or was cancelled, and None if
    `timeout` elapsed first.

    "ok" means a pass ran to completion -- NOT that state converged: `reconcile()`
    returns normally when the image is missing, and per-container failures are logged
    and swallowed. Ordering is what this buys; whether the result is correct is what
    deploy verification (`scripts/verify-deploy.py`) is for.

    select() is the wait -- the process is parked in the kernel, nothing polls.
    `timeout=None` waits indefinitely, which is the default for `--wait`: any number
    would be a guess about how long a pass takes on this host. A caller that wants a
    liveness bound passes one, and it is reported, never retried.

    A write end opened and closed without a byte (a loop that died mid-notify) reads
    as b"" and is reported as "failed" -- the fail-safe direction.
    """
    ready, _, _ = select.select([waiter.fd], [], [], timeout)
    if not ready:
        return None
    return "ok" if os.read(waiter.fd, 1) == NOTIFY_OK else "failed"


def close_waiter(waiter: Waiter) -> None:
    """Drop the FIFO and release the lock.

    Two orderings are load-bearing and must not be "tidied":
      * both unlinks happen while the lock is still held, so a sweeper cannot collect
        a half-torn-down pair;
      * the FIFO is unlinked BEFORE its lock. A crash between the two therefore leaves
        a lock without a FIFO, which the sweeper can collect. The reverse order would
        leave a FIFO with no lock -- and a lock-less FIFO is invisible to the sweeper,
        which keys on lock files, so it would leak forever.
    """
    with contextlib.suppress(OSError):
        os.close(waiter.fd)
    waiter.fd = -1
    _unlink_quietly(waiter.path)
    _unlink_quietly(waiter.lock_path)
    with contextlib.suppress(OSError):
        os.close(waiter.lock_fd)
    waiter.lock_fd = -1


# Loop side (the reconciler) ===========================================================================================
def snapshot_waiters(database_path: str) -> list[Path]:
    """FIFOs registered before this pass started. Never raises.

    Lock files live in the same directory and are not waiters. Anything that is not a
    FIFO is ignored too: `notify_waiters` opens what it is given for writing, and a
    regular file left here by hand would have its first byte overwritten every pass.
    """
    try:
        entries = sorted(waiters_dir(database_path).iterdir())
    except OSError:
        return []

    waiters = []
    for entry in entries:
        if entry.suffix == LOCK_SUFFIX:
            continue
        try:
            if stat.S_ISFIFO(entry.stat().st_mode):
                waiters.append(entry)
        except OSError:
            continue
    return waiters


def notify_waiters(paths: Iterable[Path], *, ok: bool) -> None:
    """Report the pass outcome to each waiter. Never raises, never unlinks.

    A FIFO that cannot be opened for writing is skipped: ENXIO means "no reader",
    which is indistinguishable from a registration that started a microsecond ago.
    Deleting it is `sweep_orphan_waiters`' call, and only once nothing holds it.
    """
    payload = NOTIFY_OK if ok else NOTIFY_FAILED
    for target in paths:
        try:
            fd = os.open(target, os.O_WRONLY | os.O_NONBLOCK)
        except OSError:
            continue
        try:
            os.write(fd, payload)
        except OSError:
            pass
        finally:
            with contextlib.suppress(OSError):
                os.close(fd)


def sweep_orphan_waiters(database_path: str) -> None:
    """Unlink waiter pairs whose owner is gone. Never raises.

    Iterates lock files, because the lock -- not the FIFO -- is the registration
    record: a lock we can take is one nobody holds, so its FIFO will never be read.
    A CLI killed after registering leaves such a pair, and uncollected they accumulate
    on the postern-data volume forever.
    """
    try:
        entries = list(waiters_dir(database_path).iterdir())
    except OSError:
        return

    for lock_path in entries:
        if lock_path.suffix != LOCK_SUFFIX:
            continue
        try:
            lock_fd = os.open(lock_path, os.O_RDWR)
        except OSError:
            continue  # already gone
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(lock_fd)  # a live waiter holds it
            continue
        try:
            # Unlink while still holding the lock, and close the fd only afterwards.
            # A registrar blocked in flock(LOCK_EX) on this same file wakes up owning
            # an already-unlinked inode, which is exactly what its `st_nlink == 0`
            # check detects. Closing first would hand it a live-looking lock on a file
            # we are about to delete -- reopening the registration race, silently.
            _unlink_quietly(lock_path.with_suffix(""))  # the FIFO, if it got that far
            _unlink_quietly(lock_path)
        finally:
            with contextlib.suppress(OSError):
                os.close(lock_fd)
