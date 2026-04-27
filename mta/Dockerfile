# syntax=docker/dockerfile:1

FROM dhi.io/alpine-base:3.23-dev AS build
# All privileged setup happens in the -dev stage (the runtime stage at
# dhi.io/alpine-base:3.23 has no root user and cannot run apk/addgroup).
# The opendkim user is created here so /etc/passwd, /etc/group, and the
# opendkim home directory exist when we COPY across to the runtime stage.
# unbound-anchor's binary lives inside the `unbound` package -- no separate
# `unbound-anchor` package exists in Alpine 3.23.
RUN mkdir -p /var/lib/opendkim \
	&& addgroup -g 110 -S opendkim \
	&& adduser -u 110 -S -G opendkim -h /var/lib/opendkim opendkim \
	&& chown opendkim:opendkim /var/lib/opendkim \
	&& apk add --no-cache \
		postfix postfix-doc \
		opendkim opendkim-utils \
		ca-certificates tzdata \
		python3 py3-pip py3-dnspython \
		unbound \
		postsrsd \
		netcat-openbsd \
	&& pip install --no-deps --break-system-packages postfix-mta-sts-resolver

# Runtime stage: locked-down DHI image. Postfix's master needs root; the compose
# file leaves USER unset so the container runs as the image default. Capabilities
# (NET_BIND_SERVICE et al) are granted via cap_add in compose.yaml.
FROM dhi.io/alpine-base:3.23-dev

LABEL org.opencontainers.image.source="https://github.com/bindreams/postern"
LABEL org.opencontainers.image.url="https://github.com/bindreams/postern"
LABEL org.opencontainers.image.title="postern-mta"
LABEL org.opencontainers.image.description="Postern MTA (Postfix + opendkim + Unbound + postsrsd + mta-sts-resolver)"
LABEL org.opencontainers.image.licenses="AGPL-3.0-or-later"

# Copy the package tree from the build stage. Mass-copy /etc, /usr, /var so we
# pick up postfix, opendkim, unbound, postsrsd, and the pip-installed
# postfix-mta-sts-resolver under /usr/lib/python3.*.
COPY --from=build /etc /etc
COPY --from=build /usr /usr
COPY --from=build /var /var

COPY LICENSE.md /usr/share/licenses/postern/LICENSE.md
COPY portal/src/postern/mta /usr/lib/python3.13/site-packages/postern_mta
COPY mta/etc /usr/local/share/mta-templates
COPY --chmod=755 mta/entrypoint.py /usr/local/bin/entrypoint.py

# Postfix expects /var/spool/postfix and chroot tree to be in place at runtime.
# The compose file mounts a named volume there so the queue persists.
EXPOSE 25 587

ENTRYPOINT ["python3", "/usr/local/bin/entrypoint.py"]
