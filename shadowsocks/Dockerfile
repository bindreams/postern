# syntax=docker/dockerfile:1

FROM dhi.io/alpine-base:3.23-dev AS download-ex-ray
ARG TARGETARCH
# renovate: datasource=github-tags depName=bindreams/hole
ARG EX_RAY_VERSION=v0.2.0
# ex-ray is bindreams/hole's first-party v2ray-core SIP003 shim. It is
# wire-compatible with stock shadowsocks/v2ray-plugin, so we install it under
# the `v2ray-plugin` name: ssserver execs `v2ray-plugin` by SIP003 name and the
# SS_CONFIG `plugin` field stays "v2ray-plugin" (clients need no re-download).
# Release asset names omit the leading `v`; tags include it.
RUN <<-EOF
	set -eu
	v="${EX_RAY_VERSION#v}"
	asset="ex-ray-${v}-linux-${TARGETARCH}"
	base="https://github.com/bindreams/hole/releases/download/releases/ex-ray/${EX_RAY_VERSION}"
	cd /tmp
	wget -q -O "${asset}" "${base}/${asset}"
	wget -q -O SHA256SUMS "${base}/SHA256SUMS"
	# BusyBox sha256sum lacks --ignore-missing. Filter SHA256SUMS to the single
	# line that names our asset (text-mode "<hash>  <file>", same format as galoshes).
	grep -F "  ${asset}" SHA256SUMS > SHA256SUMS.one
	sha256sum -c SHA256SUMS.one
	install -m 0755 "${asset}" /ex-ray
	test -x /ex-ray
EOF

FROM dhi.io/alpine-base:3.23-dev AS download-ex-ray-license
ARG EX_RAY_VERSION=v0.2.0
# ex-ray is Apache-2.0; NOTICES.md carries the MIT attribution for the
# v2ray-plugin-derived config-building (see crates/ex-ray/README.md).
RUN <<-EOF
	set -eu
	base="https://raw.githubusercontent.com/bindreams/hole/refs/tags/releases/ex-ray/${EX_RAY_VERSION}"
	wget -q -O /LICENSE "${base}/crates/ex-ray/LICENSE"
	wget -q -O /NOTICES.md "${base}/NOTICES.md"
EOF

FROM dhi.io/alpine-base:3.23-dev AS download-galoshes
ARG TARGETARCH
# renovate: datasource=github-tags depName=bindreams/hole
ARG GALOSHES_VERSION=v0.3.0
RUN <<-EOF
	set -eu
	# Release asset names omit the leading `v`; tags include it.
	v="${GALOSHES_VERSION#v}"
	asset="galoshes-${v}-linux-${TARGETARCH}"
	base="https://github.com/bindreams/hole/releases/download/releases/galoshes/${GALOSHES_VERSION}"
	cd /tmp
	wget -q -O "${asset}" "${base}/${asset}"
	wget -q -O SHA256SUMS "${base}/SHA256SUMS"
	grep -F "  ${asset}" SHA256SUMS > SHA256SUMS.one
	sha256sum -c SHA256SUMS.one
	install -m 0755 "${asset}" /galoshes
EOF

FROM dhi.io/alpine-base:3.23-dev AS download-galoshes-license
ARG GALOSHES_VERSION=v0.3.0
RUN wget -q -O /LICENSE.md \
	"https://raw.githubusercontent.com/bindreams/hole/refs/tags/releases/galoshes/${GALOSHES_VERSION}/crates/galoshes/LICENSE.md"

FROM dhi.io/rust:1-debian13-dev AS build-shadowsocks
WORKDIR /src
COPY external/shadowsocks-rust/ .
RUN cargo build --release --bin ssserver

# Runtime is dhi.io/debian-base:trixie (glibc 2.41) -- NOT alpine-base. The
# galoshes pre-built binary is glibc-dynamically-linked and demands
# GLIBC_2.39+; Alpine's musl loader cannot run it (missing
# /lib64/ld-linux-x86-64.so.2 plus libgcc_s unwind / __res_init mismatches)
# and Debian 12 (bookworm, glibc 2.36) is too old. Building galoshes from
# source against musl would require cloning the whole bindreams/hole Cargo
# workspace at the release tag, so glibc-base is the simpler trade.
FROM dhi.io/debian-base:trixie
LABEL org.opencontainers.image.source="https://github.com/bindreams/postern"
LABEL org.opencontainers.image.url="https://github.com/bindreams/postern"
LABEL org.opencontainers.image.title="postern-shadowsocks"
LABEL org.opencontainers.image.description="Per-connection Shadowsocks-rust + ex-ray (wire-compatible v2ray-plugin) / galoshes tunnel for Postern"
LABEL org.opencontainers.image.licenses="AGPL-3.0-or-later"
COPY --from=download-ex-ray /ex-ray /usr/local/bin/v2ray-plugin
COPY --from=download-galoshes /galoshes /usr/local/bin/galoshes
COPY --from=build-shadowsocks /src/target/release/ssserver /usr/local/bin/ssserver
COPY LICENSE.md /usr/share/licenses/postern/LICENSE.md
COPY --from=download-ex-ray-license /LICENSE /usr/share/licenses/ex-ray/LICENSE
COPY --from=download-ex-ray-license /NOTICES.md /usr/share/licenses/ex-ray/NOTICES.md
COPY --from=download-galoshes-license /LICENSE.md /usr/share/licenses/galoshes/LICENSE.md
COPY external/shadowsocks-rust/LICENSE /usr/share/licenses/shadowsocks-rust/LICENSE

# Config is passed as base64-encoded SS_CONFIG env var; entrypoint.sh decodes it
# to /tmp (the only nonroot-writable path at runtime) and execs ssserver.
COPY --chmod=755 shadowsocks/entrypoint.sh /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
