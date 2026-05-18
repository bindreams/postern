# syntax=docker/dockerfile:1

FROM dhi.io/alpine-base:3.23-dev AS download-v2ray-plugin
ARG TARGETARCH
# renovate: datasource=github-tags depName=bindreams/hole
ARG V2RAY_PLUGIN_VERSION=v1.3.3-hole.1
RUN <<-EOF
	set -eu
	asset="v2ray-plugin-linux-${TARGETARCH}-${V2RAY_PLUGIN_VERSION}.tar.gz"
	base="https://github.com/bindreams/hole/releases/download/releases/v2ray-plugin/${V2RAY_PLUGIN_VERSION}"
	cd /tmp
	wget -q -O "${asset}" "${base}/${asset}"
	wget -q -O SHA256SUMS "${base}/SHA256SUMS"
	# BusyBox sha256sum lacks --ignore-missing. Filter SHA256SUMS to the single
	# line that names our asset (linux entries use text-mode "<hash>  <file>").
	grep -F "  ${asset}" SHA256SUMS > SHA256SUMS.one
	sha256sum -c SHA256SUMS.one
	tar -xzf "${asset}" -C /
	test -x /v2ray-plugin
EOF

FROM dhi.io/alpine-base:3.23-dev AS download-v2ray-plugin-license
ARG V2RAY_PLUGIN_VERSION=v1.3.3-hole.1
RUN wget -q -O /LICENSE \
	"https://raw.githubusercontent.com/bindreams/hole/refs/tags/releases/v2ray-plugin/${V2RAY_PLUGIN_VERSION}/external/v2ray-plugin/LICENSE"

FROM dhi.io/alpine-base:3.23-dev AS download-galoshes
ARG TARGETARCH
# renovate: datasource=github-tags depName=bindreams/hole
ARG GALOSHES_VERSION=v0.1.0
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
ARG GALOSHES_VERSION=v0.1.0
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
LABEL org.opencontainers.image.description="Per-connection Shadowsocks-rust + v2ray-plugin/galoshes tunnel for Postern"
LABEL org.opencontainers.image.licenses="AGPL-3.0-or-later"
COPY --from=download-v2ray-plugin /v2ray-plugin /usr/local/bin/v2ray-plugin
COPY --from=download-galoshes /galoshes /usr/local/bin/galoshes
COPY --from=build-shadowsocks /src/target/release/ssserver /usr/local/bin/ssserver
COPY LICENSE.md /usr/share/licenses/postern/LICENSE.md
COPY --from=download-v2ray-plugin-license /LICENSE /usr/share/licenses/v2ray-plugin/LICENSE
COPY --from=download-galoshes-license /LICENSE.md /usr/share/licenses/galoshes/LICENSE.md
COPY external/shadowsocks-rust/LICENSE /usr/share/licenses/shadowsocks-rust/LICENSE

# Config is passed as base64-encoded SS_CONFIG env var; entrypoint.sh decodes it
# to /tmp (the only nonroot-writable path at runtime) and execs ssserver.
COPY --chmod=755 shadowsocks/entrypoint.sh /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
