# syntax=docker/dockerfile:1

FROM dhi.io/golang:1-alpine3.23-dev AS go-build
WORKDIR /src/postern-dns
# go.sum is committed alongside go.mod so the build is deterministic and the
# Go toolchain validates downloads against the recorded hashes (not just
# sum.golang.org). Renovate tracks both files.
COPY provisioner/postern-dns/go.mod provisioner/postern-dns/go.sum ./
RUN go mod download
COPY provisioner/postern-dns/main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/postern-dns ./...

FROM dhi.io/alpine-base:3.23-dev AS build
# All privileged setup happens in the -dev stage (the runtime stage at
# dhi.io/alpine-base:3.23 has no root user and cannot run apk/addgroup).
# Pin opendkim user/group to 110:110 so this container's `opendkim-genkey` writes
# keys with ownership the mta container (running as the same UID/GID) can read.
RUN mkdir -p /var/lib/opendkim \
	&& addgroup -g 110 -S opendkim \
	&& adduser -u 110 -S -G opendkim -h /var/lib/opendkim opendkim \
	&& chown opendkim:opendkim /var/lib/opendkim \
	&& apk add --no-cache python3 py3-pip py3-dnspython opendkim-utils ca-certificates tzdata

FROM dhi.io/alpine-base:3.23-dev

LABEL org.opencontainers.image.source="https://github.com/bindreams/postern"
LABEL org.opencontainers.image.url="https://github.com/bindreams/postern"
LABEL org.opencontainers.image.title="postern-provisioner"
LABEL org.opencontainers.image.description="Postern DKIM rotation + (planned) ACME DNS-01 cert renewal"
LABEL org.opencontainers.image.licenses="AGPL-3.0-or-later"

# Mass-copy package tree, /etc/passwd entries, and the opendkim home from the
# build stage. -dev runtime keeps busybox + apk available; we don't need them
# at runtime, but they're harmless and let `compose exec provisioner sh` work
# for diagnostics.
COPY --from=build /etc /etc
COPY --from=build /usr /usr
COPY --from=build --chown=110:110 /var/lib/opendkim /var/lib/opendkim

COPY LICENSE.md /usr/share/licenses/postern/LICENSE.md
COPY portal/src/postern/mta /usr/lib/python3.13/site-packages/postern_mta
COPY --chmod=755 provisioner/entrypoint.py /usr/local/bin/entrypoint.py
COPY --from=go-build /out/postern-dns /usr/local/bin/postern-dns

USER opendkim
ENTRYPOINT ["python3", "/usr/local/bin/entrypoint.py"]
