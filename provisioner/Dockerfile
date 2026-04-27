# syntax=docker/dockerfile:1

FROM dhi.io/golang:1-alpine3.23-dev AS go-build
WORKDIR /src/postern-dns
COPY provisioner/postern-dns/go.mod ./
# go.sum is generated on first build below (versions are pinned in go.mod;
# Renovate tracks upgrades). The Go toolchain verifies downloads against
# sum.golang.org regardless of whether a local go.sum is present.
RUN go mod download
COPY provisioner/postern-dns/main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/postern-dns ./...

FROM dhi.io/alpine-base:3.23

LABEL org.opencontainers.image.source="https://github.com/bindreams/postern"
LABEL org.opencontainers.image.url="https://github.com/bindreams/postern"
LABEL org.opencontainers.image.title="postern-provisioner"
LABEL org.opencontainers.image.description="Postern DKIM rotation + (planned) ACME DNS-01 cert renewal"
LABEL org.opencontainers.image.licenses="AGPL-3.0-or-later"

# Pin opendkim user/group to 110:110 so this container's `opendkim-genkey` writes
# keys with ownership the mta container (running as the same UID/GID) can read.
RUN addgroup -g 110 -S opendkim \
	&& adduser -u 110 -S -G opendkim -h /var/lib/opendkim opendkim \
	&& apk add --no-cache python3 py3-pip py3-dnspython opendkim-utils ca-certificates tzdata

COPY LICENSE.md /usr/share/licenses/postern/LICENSE.md
COPY portal/src/postern/mta /usr/lib/python3.13/site-packages/postern_mta
COPY --chmod=755 provisioner/entrypoint.py /usr/local/bin/entrypoint.py
COPY --from=go-build /out/postern-dns /usr/local/bin/postern-dns

USER opendkim
ENTRYPOINT ["python3", "/usr/local/bin/entrypoint.py"]
