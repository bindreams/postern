# syntax=docker/dockerfile:1

FROM dhi.io/alpine-base:3.23-dev AS build
RUN apk add --no-cache \
		postfix postfix-doc \
		opendkim opendkim-utils \
		ca-certificates tzdata \
		python3 py3-pip py3-dnspython \
		unbound unbound-anchor \
		postsrsd \
		netcat-openbsd \
	&& pip install --no-deps --break-system-packages postfix-mta-sts-resolver

FROM dhi.io/alpine-base:3.23

LABEL org.opencontainers.image.source="https://github.com/bindreams/postern"
LABEL org.opencontainers.image.url="https://github.com/bindreams/postern"
LABEL org.opencontainers.image.title="postern-mta"
LABEL org.opencontainers.image.description="Postern MTA (Postfix + opendkim + Unbound + postsrsd + mta-sts-resolver)"
LABEL org.opencontainers.image.licenses="AGPL-3.0-or-later"

# Pin opendkim user/group to 110:110 so the provisioner (which runs as the same
# UID/GID) can write keys that this container reads. Both Dockerfiles must agree.
RUN addgroup -g 110 -S opendkim \
	&& adduser -u 110 -S -G opendkim -h /var/lib/opendkim opendkim

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
