# syntax=docker/dockerfile:1

FROM dhi.io/golang:1-alpine3.23-dev AS build-v2ray-plugin
WORKDIR /src
COPY external/v2ray-plugin/ .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /v2ray-plugin

FROM dhi.io/rust:1-alpine3.23-dev AS build-shadowsocks
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY external/shadowsocks-rust/ .
RUN cargo build --release --bin sslocal

FROM dhi.io/alpine-base:3.23-dev
# libgcc: sslocal links it dynamically; not in -dev by default.
# ca-certificates: the e2e CMD calls update-ca-certificates against a CA
# bind-mounted at runtime by the e2e_certs fixture (see e2e.compose.yaml).
RUN apk add --no-cache ca-certificates curl libgcc
COPY --from=build-v2ray-plugin /v2ray-plugin /usr/local/bin/v2ray-plugin
COPY --from=build-shadowsocks /src/target/release/sslocal /usr/local/bin/sslocal

# Trust setup happens in the compose `command:` at startup, not here, so the
# image is content-stable across cert regenerations.
CMD ["sleep", "infinity"]
