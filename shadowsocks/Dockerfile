# syntax=docker/dockerfile:1

FROM dhi.io/golang:1-alpine3.21-dev AS build-v2ray-plugin
WORKDIR /src
COPY external/v2ray-plugin/ .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /v2ray-plugin

FROM dhi.io/rust:1-alpine3.21-dev AS build-shadowsocks
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY external/shadowsocks-rust/ .
RUN cargo build --release --bin ssserver

FROM dhi.io/alpine-base:3.21
RUN apk add --no-cache ca-certificates
COPY --from=build-v2ray-plugin /v2ray-plugin /usr/local/bin/v2ray-plugin
COPY --from=build-shadowsocks /src/target/release/ssserver /usr/local/bin/ssserver

# Config is passed as base64-encoded SS_CONFIG env var, decoded to tmpfs at runtime
RUN cat <<-"EOF" > /entrypoint.sh
	#!/bin/sh
	set -eu
	echo "$SS_CONFIG" | base64 -d > /tmp/config.jsonc
	exec ssserver -c /tmp/config.jsonc
EOF
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
