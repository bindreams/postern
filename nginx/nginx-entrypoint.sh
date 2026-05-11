#!/bin/sh
# Render nginx config templates from ${DOMAIN}, then exec nginx.
#
# Build step copies the source tree under nginx/etc/ to /etc/nginx/templates/
# (preserving directory layout). At container start, each *.tmpl file gets
# ${DOMAIN} substituted via sed and written to the same path under
# /etc/nginx/ with the .tmpl suffix stripped. Non-templated files (e.g.
# ssl.conf, ffdhe2048.txt) are copied verbatim.
#
# Writes are tolerant of read-only mounts: e2e tests bind-mount their own
# nginx.conf over /etc/nginx/nginx.conf to keep production divergences out
# of CI; that bind is read-only, so our render quietly skips it and lets
# the test fixture's file win. Production has no such bind and writes succeed.
#
# After rendering, the periodic-reload loop (every 6h) is started for
# LE cert renewals (Let's Encrypt rotates the symlink target, so nginx
# needs to re-read the cert chain; inotifywait doesn't catch symlink-flip
# reliably across Docker bind mounts).
set -eu

TEMPLATE_DIR=/etc/nginx/templates
TARGET_DIR=/etc/nginx

if [ ! -d "$TEMPLATE_DIR" ]; then
	echo "nginx-entrypoint: no templates at $TEMPLATE_DIR; starting nginx as-is" >&2
else
	if [ -z "${DOMAIN:-}" ]; then
		echo "nginx-entrypoint: DOMAIN must be set in env (templates at $TEMPLATE_DIR require it)" >&2
		exit 1
	fi

	# Render every file under $TEMPLATE_DIR, preserving directory layout.
	# *.tmpl files get ${DOMAIN} substituted; non-tmpl files are copied verbatim.
	find "$TEMPLATE_DIR" -type f | while read -r src; do
		rel=${src#"$TEMPLATE_DIR"/}
		case "$rel" in
			*.tmpl) dst="$TARGET_DIR/${rel%.tmpl}" ;;
			*) dst="$TARGET_DIR/$rel" ;;
		esac
		mkdir -p "$(dirname "$dst")" 2>/dev/null || true
		# Tolerate read-only mounts (e2e bind-mounts nginx.conf): write via a
		# temp + rename so a partial write never leaves a corrupt file, and a
		# failing rename is a no-op.
		tmp="$dst.tmp.$$"
		if [ "${rel##*.}" = "tmpl" ]; then
			sed "s|\${DOMAIN}|$DOMAIN|g" "$src" >"$tmp" 2>/dev/null || { rm -f "$tmp"; continue; }
		else
			cp "$src" "$tmp" 2>/dev/null || { rm -f "$tmp"; continue; }
		fi
		if mv -f "$tmp" "$dst" 2>/dev/null; then
			echo "nginx-entrypoint: rendered $dst" >&2
		else
			rm -f "$tmp"
			echo "nginx-entrypoint: skipped $dst (target read-only)" >&2
		fi
	done
fi

# Periodic reload to pick up renewed TLS certificates. inotifywait does
# not work reliably across Docker bind mounts (Let's Encrypt updates
# symlink targets, not the symlinks themselves).
(while true; do sleep 21600; nginx -s reload; done) &

exec nginx -g 'daemon off;'
