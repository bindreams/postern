# syntax=docker/dockerfile:1
FROM dhi.io/nginx:mainline-alpine3.21

RUN cat <<-"EOF" > /docker-entrypoint.d/10-periodic-reload.sh
	#!/bin/sh
	# Periodically reload nginx to pick up renewed TLS certificates.
	# inotifywait does not work reliably across Docker bind mounts
	# (Let's Encrypt updates symlink targets, not the symlinks themselves).
	(while true; do sleep 21600; nginx -s reload; done) &
EOF
RUN chmod +x /docker-entrypoint.d/10-periodic-reload.sh
