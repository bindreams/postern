"""Every TLS client Postern ships rejects the compromised eMudhra chain (issue #254).

Eight eMudhra intermediates (April 2025) have publicly recoverable private keys:
<https://emudhra.we-have-a-problem.com/>. Old trust stores reach them through the
`emSign ECC Root CA - G3` cross-sign. Each floor below is the first release that
stops trusting them, per that page and measured against its test hosts.
"""
from __future__ import annotations

import hashlib
import re
import ssl
from pathlib import Path

import certifi
from packaging.version import Version

from tests._compose import load_compose

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# SHA-256 of the roots that issue or cross-sign the compromised intermediates (the
# advisory's roots.json). certifi 2026.2.25 still carried `emSign ECC Root CA - G3`.
COMPROMISED_CHAIN_ROOTS = {
    "7DD78D5F4F13459A83DFF9ABBBA62EDBAF6F2D102BF257FD712F4D9F2746ED8D": "emSign Root TLS CA - G3",
    "F2EDAAFF3D9B701FB4D14C9F285F8C0BAD90FC3BCC1FA07D47F4718EDABA34A5": "emSign Root CS CA - G3",
    "D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4": "AAA Certificate Services",
    "86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B": "emSign ECC Root CA - G3",
}

# crypto/x509.Verify drops chains through the intermediates from these releases on.
GO_FLOOR = Version("1.27.3")
FLOORED_CA_CERTIFICATES = "'ca-certificates>=20261020-r0'"
UV_FLOOR = Version("0.13.4")

DOCKERFILES = (
    "mta/Dockerfile", "provisioner/Dockerfile", "shadowsocks/Dockerfile", "portal/tests/e2e/ssclient.Dockerfile"
)


def test_certifi_bundle_excludes_compromised_chain_roots():
    """httpx (dnspython DoH) and requests verify against certifi, not the system store."""
    pems = re.findall(
        r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----",
        Path(certifi.where()).read_text(), re.S
    )
    fingerprints = {hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest().upper() for pem in pems}
    trusted = fingerprints & COMPROMISED_CHAIN_ROOTS.keys()
    assert not trusted, [COMPROMISED_CHAIN_ROOTS[f] for f in trusted]


def test_go_directive_meets_floor():
    """With GOTOOLCHAIN=local the `go` line is the build-time floor: a stale cached
    image fails `go mod download` instead of linking postern-dns and lego against a
    vulnerable crypto/x509."""
    go_mod = (REPO_ROOT / "provisioner/postern-dns/go.mod").read_text()
    match = re.search(r"^go (\S+)$", go_mod, re.M)
    assert match is not None
    assert Version(match[1]) >= GO_FLOOR


def test_go_build_stage_pins_local_toolchain():
    """Under GOTOOLCHAIN=auto, `go install lego@...` picks its toolchain from lego's
    go.mod, not ours, and would build with whatever Go the image has."""
    _base, body = _stages((REPO_ROOT / "provisioner/Dockerfile").read_text())["go-build"]
    assert re.search(r"^ENV GOTOOLCHAIN=local$", body, re.M)


def test_pip_installs_verify_against_system_bundle():
    """pip 26.2.1 adds its vendored certifi, which still trusts the chain, to every
    connection and ignores --cert. legacy-certs makes --cert the only trust anchor."""
    for dockerfile in DOCKERFILES:
        commands = re.findall(r"pip install[^\n&]*", (REPO_ROOT / dockerfile).read_text().replace("\\\n", " "))
        for command in commands:
            assert "--use-deprecated=legacy-certs --cert /etc/ssl/certs/ca-certificates.crt" in command, f"{dockerfile}: {command}"


def _apk_adds(text: str) -> list[str]:
    """Each `apk add` command, backslash continuations included."""
    return re.findall(r"apk add[^\n&]*", text.replace("\\\n", " "))


def _stages(text: str) -> dict[str, tuple[str, str]]:
    """Stage name -> (FROM image or stage, stage text)."""
    stages = {}
    for chunk in re.split(r"^(?=FROM )", text, flags=re.M)[1:]:
        match = re.match(r"FROM (\S+)(?: AS (\S+))?", chunk)
        assert match is not None
        stages[match[2] or f"#{len(stages)}"] = (match[1], chunk)
    return stages


def test_apk_ca_certificates_meets_floor():
    """The constraint also changes the RUN line, so a cached layer holding the old
    bundle is rebuilt rather than reused."""
    for dockerfile in DOCKERFILES:
        packages = [
            token for cmd in _apk_adds((REPO_ROOT / dockerfile).read_text()) for token in cmd.split()
            if "ca-certificates" in token
        ]
        assert packages and set(packages) == {FLOORED_CA_CERTIFICATES}, dockerfile


def test_alpine_download_stages_use_floored_bundle():
    """dhi.io/alpine-base:3.23-dev ships ca-certificates-bundle 20260909-r0, which
    trusts the chain. A download stage fetches the binary and its SHA256SUMS from
    the same origin, so the checksum does not cover a forged certificate."""
    for dockerfile in DOCKERFILES:
        stages = _stages((REPO_ROOT / dockerfile).read_text())
        for name, (_base, body) in stages.items():
            if not re.search(r"\b(wget|curl)\b", body):
                continue
            stage, floored = name, False
            while stage in stages:
                floored = floored or any(FLOORED_CA_CERTIFICATES in cmd for cmd in _apk_adds(stages[stage][1]))
                stage = stages[stage][0]
            if stage.startswith("dhi.io/alpine-base:"):
                assert floored, f"{dockerfile}: stage {name} downloads without a floored CA bundle"


def test_uv_image_meets_floor():
    text = (REPO_ROOT / "portal/Dockerfile").read_text()
    versions = re.findall(r"ghcr\.io/astral-sh/uv:(\S+)", text)
    assert versions
    assert all(Version(v) >= UV_FLOOR for v in versions), versions


def test_compose_builds_pull_base_images():
    """Without a pull, `docker compose up -d --build` reuses a locally cached base
    image -- including the distroless portal runtime, whose CA bundle no RUN line
    can refresh."""
    services = load_compose(REPO_ROOT / "compose.yaml")["services"]
    built = {name: svc["build"] for name, svc in services.items() if "build" in svc}
    assert built
    assert {name: build.get("pull") for name, build in built.items()} == {name: True for name in built}


# The ssserver build's TLS client (hickory DNS-over-HTTPS/TLS). Postern never sets a
# `dns` key, but the code ships.
RUST_CRATE_FLOORS = {"rustls-webpki": Version("0.103.16"), "webpki-roots": Version("1.0.10")}


def _locked_versions(lockfile: Path, crate: str) -> list[Version]:
    return [Version(v) for v in re.findall(rf'^name = "{crate}"\nversion = "([^"]+)"', lockfile.read_text(), re.M)]


def test_ssserver_build_overrides_stale_rust_crates():
    """While the vendored Cargo.lock lags a floor, the build stage must raise that
    crate with `cargo update --precise` before building. Once a subrepo pull meets
    the floor, the override must go, or it would pin the crate back down."""
    lockfile = REPO_ROOT / "external/shadowsocks-rust/Cargo.lock"
    _base, body = _stages((REPO_ROOT / "shadowsocks/Dockerfile").read_text())["build-shadowsocks"]
    build_at = body.index("cargo build")
    for crate, floor in RUST_CRATE_FLOORS.items():
        stale = [v for v in _locked_versions(lockfile, crate) if v.major == floor.major and v < floor]
        override = re.search(rf"cargo update -p {crate}(@\S+)? --precise (\S+)", body)
        if stale:
            assert override is not None, f"{crate} {stale} is below {floor}"
            assert override.start() < build_at
            assert Version(override[2]) >= floor
            assert override[1] in (None, f"@{stale[0]}")
        else:
            assert override is None, f"Cargo.lock now meets {crate} {floor}; drop the override"
