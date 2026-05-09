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

# Lego (ACME DNS-01 client). Pin a specific tag; Renovate's customManager regex
# in .github/renovate.json tracks upgrades.
RUN CGO_ENABLED=0 go install -trimpath -ldflags="-s -w" github.com/go-acme/lego/v4/cmd/lego@v4.35.2

FROM dhi.io/alpine-base:3.23-dev AS build
# All privileged setup happens in the -dev stage (the runtime stage at
# dhi.io/alpine-base:3.23-dev shares the same image but the runtime user is
# opendkim, not root). Pin opendkim user/group to 110:110 so this container's
# `opendkim-genkey` writes keys with ownership the mta container (running as
# the same UID/GID) can read. py3-cryptography is required at runtime by
# postern.cert.inspect (used by the cert state machine).
RUN mkdir -p /var/lib/opendkim \
	&& addgroup -g 110 -S opendkim \
	&& adduser -u 110 -S -G opendkim -h /var/lib/opendkim opendkim \
	&& chown opendkim:opendkim /var/lib/opendkim \
	&& apk add --no-cache python3 py3-pip py3-dnspython py3-cryptography opendkim-utils ca-certificates tzdata

FROM dhi.io/alpine-base:3.23-dev

LABEL org.opencontainers.image.source="https://github.com/bindreams/postern"
LABEL org.opencontainers.image.url="https://github.com/bindreams/postern"
LABEL org.opencontainers.image.title="postern-provisioner"
LABEL org.opencontainers.image.description="Postern DKIM rotation + ACME DNS-01 cert renewal"
LABEL org.opencontainers.image.licenses="AGPL-3.0-or-later"

# Mass-copy package tree, /etc/passwd entries, and the opendkim home from the
# build stage. -dev runtime keeps busybox + apk available; we don't need them
# at runtime, but they're harmless and let `compose exec provisioner sh` work
# for diagnostics.
COPY --from=build /etc /etc
COPY --from=build /usr /usr
COPY --from=build --chown=110:110 /var/lib/opendkim /var/lib/opendkim

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

# PYTHONPATH so `python3` finds postern_mta regardless of which interpreter the
# runtime image's PATH resolves to. dhi.io/alpine-base:3.23-dev may ship its own
# /usr/local/bin/python with a different site-packages path; prepending the
# build stage's site-packages keeps the import working either way.
ENV PYTHONPATH=/usr/lib/python3.13/site-packages
USER opendkim
ENTRYPOINT ["python3", "/usr/local/bin/entrypoint.py"]
