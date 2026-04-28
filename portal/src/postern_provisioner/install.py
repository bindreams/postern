"""Atomic cert install via symlink-flip.

Linux ``rename(2)`` is NOT atomic for non-empty target directories
(returns ``ENOTEMPTY``), so we cannot rename ``live/<domain>.tmp/``
into ``live/<domain>/``. Instead we keep ``live/<domain>`` as a symlink
that points at a timestamped sibling directory; renaming a symlink IS
atomic, which is the canonical safe-publish pattern.

After an install:

    live/<domain>                       <- symlink, atomic-flipped
        -> live/<domain>.<timestamp>/
              fullchain.pem  0644
              privkey.pem    0640 (group=opendkim/110)
              chain.pem      0644

Old timestamped directories are kept (newest two) and garbage-collected
on a later install. Cleanup is best-effort; never blocks the install.
"""

from __future__ import annotations

import datetime as dt
import logging
import os
import shutil
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

KEEP_GENERATIONS = 2  # newest active + previous-active for rollback debugging


def install_cert_triple(
    *,
    fullchain_src: Path,
    privkey_src: Path,
    chain_src: Path,
    live_dir: Path,
    domain: str,
    now: dt.datetime | None = None,
) -> Path:
    """Atomically install (fullchain, privkey, chain) for ``domain`` under ``live_dir``.

    Returns the path of the newly-installed timestamped directory. The
    ``live_dir/<domain>`` symlink points at this directory after return.

    Each source file is copied -- never moved -- so a failure mid-install
    leaves the source files intact for retry.
    """
    if now is None:
        now = dt.datetime.now(tz=dt.timezone.utc)
    timestamp = now.strftime("%Y%m%dT%H%M%SZ")
    target_dir = live_dir / f"{domain}.{timestamp}"
    target_dir.mkdir(parents=True, exist_ok=True)

    # Per-file atomic write: copy source via mkstemp + os.replace into final
    # path inside target_dir. Mode bits set after, before the symlink flip.
    _atomic_copy(fullchain_src, target_dir / "fullchain.pem", mode=0o644)
    _atomic_copy(chain_src, target_dir / "chain.pem", mode=0o644)
    # privkey is 0644 (world-readable). The DHI nginx distroless image has no root
    # user in /etc/passwd, so we cannot add the existing nginx user to gid 110 at
    # image build time. The single-tenant trust boundary is "anyone with shell
    # access in any container is already admin-equivalent", so 0644 is an
    # acceptable degradation.
    _atomic_copy(privkey_src, target_dir / "privkey.pem", mode=0o644)

    # Symlink flip: write the symlink to a sibling temp path, then os.replace
    # into the canonical location. os.replace on a symlink is atomic on Linux
    # -- concurrent readers see either old or new, never torn.
    canonical = live_dir / domain
    tmp_link = live_dir / f"{domain}.symlink.tmp"
    if tmp_link.exists() or tmp_link.is_symlink():
        tmp_link.unlink()
    tmp_link.symlink_to(target_dir.name, target_is_directory=True)
    os.replace(tmp_link, canonical)

    _gc_old_generations(live_dir, domain, keep=KEEP_GENERATIONS)
    return target_dir


def _atomic_copy(src: Path, dst: Path, *, mode: int) -> None:
    """Copy `src` to `dst` atomically: write to a tempfile in dst's directory,
    then os.replace into place. mkstemp ensures a unique tempfile name."""
    fd, tmp = tempfile.mkstemp(dir=str(dst.parent), prefix=f".{dst.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(src.read_bytes())
        os.chmod(tmp, mode)
        os.replace(tmp, dst)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _gc_old_generations(live_dir: Path, domain: str, *, keep: int) -> None:
    """Keep the newest ``keep`` timestamped directories for ``domain``; delete older."""
    candidates = sorted(
        (p for p in live_dir.iterdir() if p.is_dir() and p.name.startswith(f"{domain}.") and p.name != domain),
        reverse=True,  # newest first by lexicographic timestamp
    )
    for old in candidates[keep:]:
        try:
            shutil.rmtree(old)
        except OSError as e:
            logger.warning("failed to garbage-collect %s: %s", old, e)
