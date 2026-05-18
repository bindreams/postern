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
	grep "  ${asset}\$" SHA256SUMS > SHA256SUMS.one
	sha256sum -c SHA256SUMS.one
	tar -xzf "${asset}" -C /
	test -x /v2ray-plugin
EOF

FROM dhi.io/alpine-base:3.23-dev AS download-v2ray-plugin-license
ARG V2RAY_PLUGIN_VERSION=v1.3.3-hole.1
RUN wget -q -O /LICENSE \
	"https://raw.githubusercontent.com/bindreams/hole/refs/tags/releases/v2ray-plugin/${V2RAY_PLUGIN_VERSION}/external/v2ray-plugin/LICENSE"

FROM dhi.io/rust:1-alpine3.23-dev AS build-shadowsocks
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY external/shadowsocks-rust/ .
RUN cargo build --release --bin ssserver

FROM dhi.io/alpine-base:3.23
LABEL org.opencontainers.image.source="https://github.com/bindreams/postern"
LABEL org.opencontainers.image.url="https://github.com/bindreams/postern"
LABEL org.opencontainers.image.title="postern-shadowsocks"
LABEL org.opencontainers.image.description="Per-connection Shadowsocks-rust + v2ray-plugin tunnel for Postern"
LABEL org.opencontainers.image.licenses="AGPL-3.0-or-later"
# ssserver links libgcc_s at runtime; non-dev alpine-base doesn't ship it, so
# copy from the builder (where apk provided it via musl-dev transitive deps).
COPY --from=build-shadowsocks /usr/lib/libgcc_s.so.1 /usr/lib/libgcc_s.so.1
COPY --from=download-v2ray-plugin /v2ray-plugin /usr/local/bin/v2ray-plugin
COPY --from=build-shadowsocks /src/target/release/ssserver /usr/local/bin/ssserver
COPY LICENSE.md /usr/share/licenses/postern/LICENSE.md
COPY --from=download-v2ray-plugin-license /LICENSE /usr/share/licenses/v2ray-plugin/LICENSE
COPY external/shadowsocks-rust/LICENSE /usr/share/licenses/shadowsocks-rust/LICENSE

# Config is passed as base64-encoded SS_CONFIG env var; entrypoint.sh decodes it
# to /tmp (the only nonroot-writable path at runtime) and execs ssserver.
COPY --chmod=755 shadowsocks/entrypoint.sh /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
