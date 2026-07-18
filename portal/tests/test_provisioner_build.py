"""Guard tests for the provisioner image build (no Docker required).

Two classes of image-only bug that runtime `go test`/`pytest` can't see:
  * the Dockerfile COPYs an EXPLICIT list of `postern-dns` `*.go` sources into the
    go-build stage (a missing file passes `go test ./...` but fails the build with
    `undefined:`);
  * named volumes the provisioner (uid 110) writes must have their mountpoint dir
    prepared 110-owned in the image, or a fresh volume is created root-owned and
    writes fail with EACCES (#178).
Pin both here, where CI catches them without a Docker build.
"""
from __future__ import annotations

import re
from pathlib import Path

# portal/tests/ -> portal/ -> repo root
REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def test_provisioner_dockerfile_copies_all_go_sources():
    dockerfile = (REPO_ROOT / "provisioner" / "Dockerfile").read_text(encoding="utf-8")
    src_dir = REPO_ROOT / "provisioner" / "postern-dns"
    sources = {p.name for p in src_dir.glob("*.go") if not p.name.endswith("_test.go")}
    copied = set(re.findall(r"provisioner/postern-dns/(\S+\.go)", dockerfile))
    missing = sources - copied
    assert not missing, (
        "provisioner/Dockerfile does not COPY these postern-dns Go sources into the go-build "
        f"stage: {sorted(missing)}. `go test ./...` passes (it sees the whole directory) but the "
        "image build fails with 'undefined:' errors -- add them to the COPY line."
    )


def test_provisioner_prepares_edge_volume_dir_owned_by_110():
    dockerfile = (REPO_ROOT / "provisioner" / "Dockerfile").read_text(encoding="utf-8")
    # The runtime COPY sets the ownership a fresh postern-edge named volume inherits
    # on first mount; without --chown=110:110 the volume is root-owned and the edge
    # reconciler's atomic write fails with PermissionError (#178). Mirrors opendkim.
    assert "--chown=110:110 /var/lib/postern-edge" in dockerfile, (
        "provisioner/Dockerfile must COPY /var/lib/postern-edge with --chown=110:110 so a fresh "
        "postern-edge volume is owned by the provisioner (uid 110); otherwise the volume is "
        "root-owned and the edge IP-range reconciler fails with PermissionError (#178)."
    )
    # The build stage must create the dir so the --chown COPY source exists.
    assert re.search(r"mkdir[^\n]*\s/var/lib/postern-edge(\s|$)", dockerfile), (
        "provisioner/Dockerfile must `mkdir /var/lib/postern-edge` in the build stage "
        "(the source of the --chown=110:110 COPY)."
    )
