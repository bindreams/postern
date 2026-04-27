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

# Lego (ACME DNS-01 client). Pin a specific tag; Renovate's customManager regex
# in .github/renovate.json tracks upgrades.
RUN CGO_ENABLED=0 go install -trimpath -ldflags="-s -w" github.com/go-acme/lego/v4/cmd/lego@v4.19.2

FROM dhi.io/alpine-base:3.23

LABEL org.opencontainers.image.source="https://github.com/bindreams/postern"
LABEL org.opencontainers.image.url="https://github.com/bindreams/postern"
LABEL org.opencontainers.image.title="postern-provisioner"
LABEL org.opencontainers.image.description="Postern DKIM rotation + ACME DNS-01 cert renewal"
LABEL org.opencontainers.image.licenses="AGPL-3.0-or-later"

# Pin opendkim user/group to 110:110 so this container's `opendkim-genkey` writes
# keys with ownership the mta container (running as the same UID/GID) can read.
RUN addgroup -g 110 -S opendkim \
	&& adduser -u 110 -S -G opendkim -h /var/lib/opendkim opendkim \
	&& apk add --no-cache python3 py3-pip py3-dnspython py3-cryptography opendkim-utils ca-certificates tzdata

COPY LICENSE.md /usr/share/licenses/postern/LICENSE.md
# postern_mta -- legacy COPY consumed by entrypoint.py (existing DKIM rotation code).
COPY portal/src/postern/mta /usr/lib/python3.13/site-packages/postern_mta
# Full postern package -- gives `from postern.cert import ...` and `from postern.mta import ...`
# used by postern_provisioner.
COPY portal/src/postern /usr/lib/python3.13/site-packages/postern
# postern_provisioner -- cert state-machine driver, install logic, healthcheck.
COPY portal/src/postern_provisioner /usr/lib/python3.13/site-packages/postern_provisioner
COPY --chmod=755 provisioner/entrypoint.py /usr/local/bin/entrypoint.py
COPY --from=go-build /out/postern-dns /usr/local/bin/postern-dns
COPY --from=go-build /go/bin/lego /usr/local/bin/lego

# Healthcheck script: see postern_provisioner.healthcheck.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
	CMD ["python3", "-m", "postern_provisioner.healthcheck"]

USER opendkim
ENTRYPOINT ["python3", "/usr/local/bin/entrypoint.py"]
