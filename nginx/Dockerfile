# syntax=docker/dockerfile:1
FROM dhi.io/nginx:1-alpine3.23

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
