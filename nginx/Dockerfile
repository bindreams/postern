# syntax=docker/dockerfile:1
FROM dhi.io/nginx:mainline-alpine3.21

# Use inotifywait to reload nginx on any changes to /etc/letsencrypt/live
RUN apk add --no-cache inotify-tools
RUN cat <<-"EOF" > /usr/local/bin/reload-nginx-on-cert-change
	#!/bin/sh
	set -eu

	inotifywait -me modify --format '%w' /etc/letsencrypt/live | while read -r filename; do
		echo "Detected change to $filename: reloading nginx" >&2
		nginx -s reload
	done
EOF
RUN chmod +x /usr/local/bin/reload-nginx-on-cert-change

RUN cat <<-"EOF" > /docker-entrypoint.d/10-reload-on-cert-change.envsh
	#!/bin/sh
	set -eu

	reload-nginx-on-cert-change &
EOF
RUN chmod +x /docker-entrypoint.d/10-reload-on-cert-change.envsh
