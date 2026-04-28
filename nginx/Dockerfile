# syntax=docker/dockerfile:1
FROM dhi.io/nginx:1-alpine3.23

# DHI nginx is distroless and does NOT honor the docker-library /docker-entrypoint.d/
# convention -- its entrypoint runs nginx directly. To add the periodic-reload loop
# we ship our own ENTRYPOINT. nonroot can't `RUN cat > /...`, so we use a heredoc
# COPY (BuildKit performs COPY as root regardless of USER).
#
# Note: this image has NO root user in /etc/passwd, so `USER root` + `RUN apk ...`
# is impossible. Modifying /etc/group at build time (e.g. to put nginx in
# gid 110 to read privkey.pem 0640) would require a multi-stage build that
# constructs /etc/group from scratch and COPYs it in. We instead make the
# privkey world-readable (provisioner writes 0644) -- the single-tenant trust
# boundary is "anyone with shell access in any container is already admin-
# equivalent", so 0644 is an acceptable degradation. See the install path in
# postern_provisioner.install for where this is enforced.
COPY --chmod=755 <<-"EOF" /usr/local/bin/nginx-entrypoint.sh
	#!/bin/sh
	# Periodically reload nginx to pick up renewed TLS certificates.
	# inotifywait does not work reliably across Docker bind mounts
	# (Let's Encrypt updates symlink targets, not the symlinks themselves).
	(while true; do sleep 21600; nginx -s reload; done) &
	exec nginx -g "daemon off;"
EOF

ENTRYPOINT ["/usr/local/bin/nginx-entrypoint.sh"]
