#!/bin/sh
# Render nginx config templates, then start nginx.
#
# The render step (templating nginx/etc/*.tmpl with ${DOMAIN} and the optional
# PROXY_PROTOCOL_* gating) lives in render.sh so it can be unit-tested without a
# container (portal/tests/test_nginx_render.py). Renders tolerate read-only
# mounts: the e2e suite bind-mounts its own nginx.conf and that write is skipped.
#
# After rendering, a periodic-reload loop (every 6h) picks up renewed TLS certs
# (Let's Encrypt rotates the symlink target; inotifywait doesn't catch the
# symlink-flip reliably across Docker bind mounts).
set -eu

# shellcheck source=/dev/null  # installed in the image at build time; not resolvable at lint time
. /usr/local/bin/render.sh
# shellcheck source=/dev/null
. /usr/local/bin/edge.sh

# render_templates returns non-zero on missing DOMAIN; set -e makes that fatal
# (intended -- nginx must not start with an unrendered config). Do not add `|| true`.
render_templates

# nginx's pidfile sits in the container's WRITABLE LAYER, not on a tmpfs, so a
# pidfile the previous container process left behind (host reboot, SIGKILL --
# a graceful stop unlinks it) is still here and still names a pid. Worse, the
# `exec` below makes the master's pid this script's own, and a restarted
# container's fresh pid namespace hands that same number back to the new
# entrypoint -- so any `nginx -s reload` issued before nginx writes a fresh
# pidfile SIGHUPs THIS shell, which has no trap, killing the container 129.
# Clearing it makes the container's state self-consistent on restart whoever
# holds that pid now; nginx writes its own the moment it starts. See issue #245.
rm -f /run/nginx.pid

(while true; do sleep 21600; nginx -s reload; done) &

# Edge real-IP / Cloudflare origin-pull watcher. No-op unless EDGE_PROFILE=
# cloudflare; FATAL (exit 1) under that profile if the image lacks inotifyd, so a
# broken image fails at deploy rather than silently logging every client as the
# CF edge IP. Arms the watch (inotifyd survives the exec below, like the 6h loop).
# The watcher does NOT reload at boot -- nginx is not up yet and its own startup
# read loads current ranges; see edge.sh's initial-reconcile comment for why a
# reload here is fatal rather than the benign no-op it was assumed to be.
edge_start_watcher || exit 1

exec nginx -g 'daemon off;'
