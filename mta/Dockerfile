# syntax=docker/dockerfile:1

# One Python minor for apk and for the site-packages path the first-party code is copied
# to. Alpine's live index can offer two minors at once, and an unpinned `python3` then
# either fails to solve or installs a minor the py3-* packages were not built for (#266).
# Keep equal to the portal's Python (portal/Dockerfile); test_python_pin.py enforces it.
ARG PYTHON_MINOR=3.14

FROM dhi.io/alpine-base:3.23-dev AS build
ARG PYTHON_MINOR
# Packages are installed in this stage and copied into the runtime stage, which is the
# same -dev image (it has root and apk, but installs nothing).
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

# Runtime stage: the same -dev image as the build stage, not a locked-down one. Postfix's
# master needs root; the compose file leaves USER unset so the container runs as the
# image default (root). Capabilities (NET_BIND_SERVICE et al) are granted via cap_add in
# compose.yaml.
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

# Build-time import check, run with the same bare `python3` the ENTRYPOINT resolves from
# PATH: a Python minor that apk and the COPY targets disagree on builds fine and only fails
# at container start (#266). Imports every submodule of postern_mta, the mta-sts daemon
# module, and everything entrypoint.py and those packages import; see
# scripts/image-import-check.py. The container runs as root, and so does the check. -B and
# PYTHONDONTWRITEBYTECODE stop the checks writing bytecode into the image; bytecode that
# pip compiled at install time in the build stage is inherent and stays. The daemon is
# started as a subprocess, so its console script is run too.
RUN --mount=type=bind,source=scripts/image-import-check.py,target=/image-import-check.py \
	["python3", "-B", "/image-import-check.py", "/usr/local/bin/entrypoint.py", \
	"postern_mta", "postfix_mta_sts_resolver.daemon"]
RUN ["env", "PYTHONDONTWRITEBYTECODE=1", "mta-sts-daemon", "--help"]

# Postfix expects /var/spool/postfix and chroot tree to be in place at runtime.
# The compose file mounts a named volume there so the queue persists.
EXPOSE 25 587

ENTRYPOINT ["python3", "/usr/local/bin/entrypoint.py"]

# Build provenance. Last in the stage: a new revision invalidates only this layer.
ARG GIT_REVISION=""
LABEL org.opencontainers.image.revision="${GIT_REVISION}"
