"""Tests for postern_provisioner.install -- symlink-flip atomic install.

The install module uses POSIX symlink semantics (rename(2) on a symlink is
atomic on Linux). Windows symlinks need elevated privileges and don't honour
mode bits or POSIX rename. The provisioner only ever runs in a Linux container,
so we skip these tests on non-POSIX hosts -- Linux CI exercises them fully.
"""

import datetime as dt
import os
from pathlib import Path

import pytest

from postern_provisioner import install

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX symlink semantics required")


@pytest.fixture
def src_triple(tmp_path: Path) -> tuple[Path, Path, Path]:
    src = tmp_path / "lego_out"
    src.mkdir()
    (src / "fullchain").write_bytes(b"FULL")
    (src / "key").write_bytes(b"KEY")
    (src / "chain").write_bytes(b"CHAIN")
    return src / "fullchain", src / "key", src / "chain"


@pytest.fixture
def live_dir(tmp_path: Path) -> Path:
    d = tmp_path / "live"
    d.mkdir()
    return d


def test_install_creates_timestamped_dir(src_triple, live_dir):
    fc, pk, ch = src_triple
    target = install.install_cert_triple(
        fullchain_src=fc,
        privkey_src=pk,
        chain_src=ch,
        live_dir=live_dir,
        domain="postern.example.com",
    )
    assert target.is_dir()
    assert target.name.startswith("postern.example.com.")
    assert (target / "fullchain.pem").read_bytes() == b"FULL"
    assert (target / "privkey.pem").read_bytes() == b"KEY"
    assert (target / "chain.pem").read_bytes() == b"CHAIN"


def test_install_creates_canonical_symlink(src_triple, live_dir):
    fc, pk, ch = src_triple
    target = install.install_cert_triple(
        fullchain_src=fc, privkey_src=pk, chain_src=ch, live_dir=live_dir, domain="postern.example.com"
    )
    canonical = live_dir / "postern.example.com"
    assert canonical.is_symlink()
    assert canonical.resolve() == target.resolve()


def test_install_sets_permissions(src_triple, live_dir):
    fc, pk, ch = src_triple
    target = install.install_cert_triple(
        fullchain_src=fc, privkey_src=pk, chain_src=ch, live_dir=live_dir, domain="postern.example.com"
    )
    assert (target / "fullchain.pem").stat().st_mode & 0o777 == 0o644
    assert (target / "chain.pem").stat().st_mode & 0o777 == 0o644
    assert (target / "privkey.pem").stat().st_mode & 0o777 == 0o644


def test_second_install_swaps_symlink_atomically(src_triple, live_dir):
    fc, pk, ch = src_triple
    t0 = dt.datetime(2026, 4, 27, 12, 0, 0, tzinfo=dt.timezone.utc)
    t1 = dt.datetime(2026, 4, 28, 12, 0, 0, tzinfo=dt.timezone.utc)
    first = install.install_cert_triple(
        fullchain_src=fc,
        privkey_src=pk,
        chain_src=ch,
        live_dir=live_dir,
        domain="postern.example.com",
        now=t0,
    )
    fc.write_bytes(b"FULL2")
    pk.write_bytes(b"KEY2")
    ch.write_bytes(b"CHAIN2")
    second = install.install_cert_triple(
        fullchain_src=fc,
        privkey_src=pk,
        chain_src=ch,
        live_dir=live_dir,
        domain="postern.example.com",
        now=t1,
    )
    assert first != second
    canonical = live_dir / "postern.example.com"
    assert canonical.resolve() == second.resolve()
    # First gen still on disk for rollback
    assert first.is_dir()
    assert (first / "fullchain.pem").read_bytes() == b"FULL"
    assert (second / "fullchain.pem").read_bytes() == b"FULL2"


def test_install_garbage_collects_oldest_beyond_keep(src_triple, live_dir):
    fc, pk, ch = src_triple
    base = dt.datetime(2026, 4, 27, tzinfo=dt.timezone.utc)
    targets = []
    for i in range(4):
        t = base + dt.timedelta(days=i)
        targets.append(
            install.install_cert_triple(
                fullchain_src=fc,
                privkey_src=pk,
                chain_src=ch,
                live_dir=live_dir,
                domain="postern.example.com",
                now=t,
            )
        )
    # KEEP_GENERATIONS=2 -> only newest two survive.
    assert not targets[0].exists()
    assert not targets[1].exists()
    assert targets[2].exists()
    assert targets[3].exists()


def test_install_overwrites_stale_tmp_symlink(src_triple, live_dir):
    """If a previous install crashed mid-flip leaving <domain>.symlink.tmp behind,
    the next install must clean it up rather than fail."""
    fc, pk, ch = src_triple
    stale = live_dir / "postern.example.com.symlink.tmp"
    stale.symlink_to("nonexistent.target", target_is_directory=True)
    install.install_cert_triple(
        fullchain_src=fc, privkey_src=pk, chain_src=ch, live_dir=live_dir, domain="postern.example.com"
    )
    canonical = live_dir / "postern.example.com"
    assert canonical.is_symlink()
    assert canonical.resolve().exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink semantics required")
def test_canonical_symlink_resolves_relatively(src_triple, live_dir):
    """The symlink target is the sibling dir name, not an absolute path. This
    keeps the volume relocatable (e.g. cross-host migration via tarball)."""
    fc, pk, ch = src_triple
    install.install_cert_triple(
        fullchain_src=fc, privkey_src=pk, chain_src=ch, live_dir=live_dir, domain="postern.example.com"
    )
    canonical = live_dir / "postern.example.com"
    target = os.readlink(canonical)
    assert not Path(target).is_absolute()
    assert target.startswith("postern.example.com.")
