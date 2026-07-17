"""Guard tests for the provisioner image build (no Docker required).

The provisioner Dockerfile COPYs an EXPLICIT list of `postern-dns` `*.go` sources
into the go-build stage. Adding a source file without updating that list passes
`go test ./...` (which sees the whole directory) but breaks the image build with an
`undefined:` symbol error -- so pin it here, where CI catches it without a Docker
build.
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
