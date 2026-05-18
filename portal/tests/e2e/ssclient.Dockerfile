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
	grep -F "  ${asset}" SHA256SUMS > SHA256SUMS.one
	sha256sum -c SHA256SUMS.one
	tar -xzf "${asset}" -C /
	test -x /v2ray-plugin
EOF

FROM dhi.io/alpine-base:3.23-dev AS download-galoshes
ARG TARGETARCH
# renovate: datasource=github-tags depName=bindreams/hole
ARG GALOSHES_VERSION=v0.1.0
RUN <<-EOF
	set -eu
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

FROM dhi.io/rust:1-debian13-dev AS build-shadowsocks
WORKDIR /src
COPY external/shadowsocks-rust/ .
RUN cargo build --release --bin sslocal

# Runtime: debian-base:trixie-dev (glibc 2.41) -- non-dev trixie lacks apt,
# and the test exec'ing in needs python3 (UDP probe), curl, netcat,
# procps, ca-certificates. The galoshes pre-built is glibc-2.39+; alpine
# musl cannot run it.
FROM dhi.io/debian-base:trixie-dev
RUN apt-get update \
	&& apt-get install -y --no-install-recommends \
		ca-certificates \
		curl \
		netcat-openbsd \
		procps \
		python3 \
	&& rm -rf /var/lib/apt/lists/*
COPY --from=download-v2ray-plugin /v2ray-plugin /usr/local/bin/v2ray-plugin
COPY --from=download-galoshes /galoshes /usr/local/bin/galoshes
COPY --from=build-shadowsocks /src/target/release/sslocal /usr/local/bin/sslocal

# Trust setup happens in the compose `command:` at startup, not here, so the
# image is content-stable across cert regenerations.
CMD ["sleep", "infinity"]
