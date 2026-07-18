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
    # Anchor the whole instruction incl. `--from=build`: a COPY from the wrong stage
    # (go-build never creates the dir) or from the local context would build-fail but
    # pass a bare substring check.
    assert re.search(
        r"COPY\s+--from=build\s+--chown=110:110\s+/var/lib/postern-edge\s+/var/lib/postern-edge",
        dockerfile,
    ), (
        "provisioner/Dockerfile must `COPY --from=build --chown=110:110 /var/lib/postern-edge ...` so a fresh "
        "postern-edge volume inherits uid-110 ownership (mirrors the opendkim dir); otherwise the volume is "
        "root-owned and the edge IP-range reconciler fails with PermissionError (#178)."
    )
    # Scope the mkdir check to the `FROM ... AS build` stage's text (the COPY source),
    # so a mkdir in the wrong stage doesn't satisfy it.
    build_stage = re.search(r"^FROM\s+\S+\s+AS\s+build\b(.*?)(?=^FROM\s)", dockerfile, re.S | re.M)
    assert build_stage and re.search(r"mkdir[^\n]*\s/var/lib/postern-edge(\s|$)", build_stage.group(1)), (
        "provisioner/Dockerfile must `mkdir /var/lib/postern-edge` in the `FROM ... AS build` stage "
        "(the source of the --from=build --chown=110:110 COPY)."
    )
