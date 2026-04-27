# syntax=docker/dockerfile:1
FROM dhi.io/nginx:1-alpine3.23

# Add the existing nginx user to gid 110 (opendkim, shared with mta and provisioner).
# Required so nginx can read the wildcard cert's privkey.pem (mode 0640, group 110)
# written by the auto-renewal flow. The image is alpine-based (BusyBox), so addgroup
# is available. addgroup -g 110 is idempotent: alpine-base may or may not already
# have group 110.
USER root
RUN addgroup -g 110 opendkim 2>/dev/null || true \
	&& addgroup nginx opendkim
USER nginx

# DHI nginx is distroless and does NOT honor the docker-library /docker-entrypoint.d/
# convention -- its entrypoint runs nginx directly. To add the periodic-reload loop
# we ship our own ENTRYPOINT. nonroot can't `RUN cat > /...`, so we use a heredoc
# COPY (BuildKit performs COPY as root regardless of USER).
COPY --chmod=755 <<-"EOF" /usr/local/bin/nginx-entrypoint.sh
	#!/bin/sh
	# Periodically reload nginx to pick up renewed TLS certificates.
	# inotifywait does not work reliably across Docker bind mounts
	# (Let's Encrypt updates symlink targets, not the symlinks themselves).
	(while true; do sleep 21600; nginx -s reload; done) &
	exec nginx -g "daemon off;"
EOF

ENTRYPOINT ["/usr/local/bin/nginx-entrypoint.sh"]
