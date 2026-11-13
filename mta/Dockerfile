# syntax=docker/dockerfile:1

# One Python minor for apk and for the site-packages path the first-party code is copied
# to. Alpine's live index can offer two minors at once, and an unpinned `python3` then
# either fails to solve or installs a minor the py3-* packages were not built for.
# Keep equal to the portal's Python (portal/Dockerfile); test_python_pin.py enforces it.
ARG PYTHON_MINOR=3.14

FROM dhi.io/alpine-base:3.23-dev AS build
ARG PYTHON_MINOR
# The runtime stage is the same -dev image; packages are installed here and copied across.
# The opendkim user is created here so /etc/passwd, /etc/group, and the
# opendkim home directory exist when we COPY across to the runtime stage.
# unbound-anchor's binary lives inside the `unbound` package -- no separate
# `unbound-anchor` package exists in Alpine 3.23.
# ca-certificates floor: first release distrusting the compromised eMudhra chain (#254).
# pip's vendored certifi still trusts that chain and overrides --cert; legacy-certs makes
# PIP_CERT the only anchor, and as env vars both reach pip's build-env subprocess.
# pip is removed after the install.
RUN mkdir -p /var/lib/opendkim \
	&& addgroup -g 110 -S opendkim \
	&& adduser -u 110 -S -G opendkim -h /var/lib/opendkim opendkim \
	&& chown opendkim:opendkim /var/lib/opendkim \
	&& apk add --no-cache \
		postfix postfix-doc \
		opendkim opendkim-utils \
		'ca-certificates>=20261020-r0' tzdata \
		"python3~${PYTHON_MINOR}" py3-pip py3-dnspython \
		unbound \
		postsrsd \
		netcat-openbsd \
	&& PIP_USE_DEPRECATED=legacy-certs PIP_CERT=/etc/ssl/certs/ca-certificates.crt pip install \
		--break-system-packages postfix-mta-sts-resolver \
	&& apk del --no-cache py3-pip

# Runtime stage: same -dev image, runs as root (Postfix master needs it); capabilities come from cap_add in compose.yaml.
FROM dhi.io/alpine-base:3.23-dev
ARG PYTHON_MINOR

LABEL org.opencontainers.image.source="https://github.com/bindreams/postern"
LABEL org.opencontainers.image.url="https://github.com/bindreams/postern"
LABEL org.opencontainers.image.title="postern-mta"
LABEL org.opencontainers.image.description="Postern MTA (Postfix + opendkim + Unbound + postsrsd + mta-sts-resolver)"
LABEL org.opencontainers.image.licenses="AGPL-3.0-or-later"

# Copy the package tree from the build stage. Mass-copy /etc, /usr, /var so we
# pick up postfix, opendkim, unbound, postsrsd, and the pip-installed
# postfix-mta-sts-resolver under /usr/lib/python${PYTHON_MINOR}.
COPY --from=build /etc /etc
COPY --from=build /usr /usr
COPY --from=build /var /var

COPY LICENSE.md /usr/share/licenses/postern/LICENSE.md
COPY portal/src/postern/mta /usr/lib/python${PYTHON_MINOR}/site-packages/postern_mta
COPY mta/etc /usr/local/share/mta-templates
COPY --chmod=755 mta/entrypoint.py /usr/local/bin/entrypoint.py

# Build-time import check (scripts/image-import-check.py), run with the bare `python3` the
# ENTRYPOINT uses: a minor mismatch between apk and the COPY targets otherwise only fails at
# container start. `-P` keeps / off sys.path; PYTHONDONTWRITEBYTECODE keeps bytecode out of
# the image. mta-sts-daemon is spawned as a subprocess, so its console script is run too.
RUN --mount=type=bind,source=scripts/image-import-check.py,target=/image-import-check.py <<-EOF
	set -eu
	export PYTHONDONTWRITEBYTECODE=1
	python3 -P /image-import-check.py "${PYTHON_MINOR}" /usr/local/bin/entrypoint.py \
		--first-party postern_mta \
		--third-party dns.resolver postfix_mta_sts_resolver.daemon
	mta-sts-daemon --help
EOF

# Postfix expects /var/spool/postfix and chroot tree to be in place at runtime.
# The compose file mounts a named volume there so the queue persists.
EXPOSE 25 587

ENTRYPOINT ["python3", "/usr/local/bin/entrypoint.py"]

# Build provenance. Last in the stage: a new revision invalidates only this layer.
ARG GIT_REVISION=""
LABEL org.opencontainers.image.revision="${GIT_REVISION}"
