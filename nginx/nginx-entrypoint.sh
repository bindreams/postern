#!/bin/sh
# Render nginx config templates, then exec nginx.
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

. /usr/local/bin/render.sh

# render_templates returns non-zero on missing DOMAIN; set -e makes that fatal
# (intended -- nginx must not start with an unrendered config). Do not add `|| true`.
render_templates

(while true; do sleep 21600; nginx -s reload; done) &

exec nginx -g 'daemon off;'
