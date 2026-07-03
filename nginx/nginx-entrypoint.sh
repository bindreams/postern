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

(while true; do sleep 21600; nginx -s reload; done) &

# Edge real-IP / Cloudflare origin-pull watcher. No-op unless EDGE_PROFILE=
# cloudflare; FATAL (exit 1) under that profile if the image lacks inotifyd, so a
# broken image fails at deploy rather than silently logging every client as the
# CF edge IP. Arms the watch (inotifyd survives the exec below, like the 6h loop)
# and runs one initial reconcile. At cold boot the reconcile's reload is a benign
# no-op (master not up yet); nginx's own startup read loads current ranges.
edge_start_watcher || exit 1

exec nginx -g 'daemon off;'
