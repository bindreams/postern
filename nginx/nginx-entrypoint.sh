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

# /run is the image's writable layer, not a tmpfs, so a pidfile left behind by an
# ungraceful stop is still here naming a pid -- and the `exec` below made that pid
# this script's own, which a restarted container hands back to the new entrypoint.
# A reload racing nginx's startup then SIGHUPs THIS shell and kills the container
# 129 (#245; full mechanism in edge.sh's comment on the watch arm).
# Best-effort by design: absence is hygiene, not a startup precondition, and nginx
# rewrites the file anyway -- an unlink failure (an unwritable /run after a uid
# change, say) must not become the new reason nginx never boots.
# Residual: a reload landing between nginx's config read and its pidfile write now
# fails ENOENT instead of succeeding by accident, deferring that one range publish
# to the 6h loop. The pre-`exec` half of that same window was fatal.
rm -f /run/nginx.pid 2>/dev/null || :

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
