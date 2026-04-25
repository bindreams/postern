# syntax=docker/dockerfile:1

FROM dhi.io/golang:1-alpine3.23-dev AS build-v2ray-plugin
WORKDIR /src
COPY external/v2ray-plugin/ .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /v2ray-plugin

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
COPY --from=build-v2ray-plugin /v2ray-plugin /usr/local/bin/v2ray-plugin
COPY --from=build-shadowsocks /src/target/release/ssserver /usr/local/bin/ssserver
COPY LICENSE.md /usr/share/licenses/postern/LICENSE.md
COPY external/v2ray-plugin/LICENSE /usr/share/licenses/v2ray-plugin/LICENSE
COPY external/shadowsocks-rust/LICENSE /usr/share/licenses/shadowsocks-rust/LICENSE

# Config is passed as base64-encoded SS_CONFIG env var, decoded to tmpfs at runtime.
# Inlined into CMD because the non-dev runtime is distroless + nonroot and can't
# accept a written entrypoint script in /.
CMD ["/bin/sh", "-c", "echo \"$SS_CONFIG\" | base64 -d > /tmp/config.jsonc && exec ssserver -c /tmp/config.jsonc"]
