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
. /usr/local/bin/pidfile.sh
# shellcheck source=/dev/null
. /usr/local/bin/edge.sh

# Refuse to run a second time inside a container that is already serving. Every
# step below assumes it owns the container: it re-renders /etc/nginx underneath the
# live master, starts a SECOND reload loop and arms a SECOND inotifyd (both of which
# outlive this script and double every subsequent reload), and clears the pidfile
# the running master depends on -- after which nginx keeps serving and keeps
# reporting healthy while every `nginx -s reload` fails open(), so the next Let's
# Encrypt rotation silently never lands. `docker compose exec nginx
# /usr/local/bin/nginx-entrypoint.sh` is an ordinary way to debug a render problem,
# and it used to be harmless. Exit 0: nginx is running, which is the state the
# caller wanted; the message says why nothing happened.
running_master="$(nginx_master_pid || :)"
if [ -n "$running_master" ]; then
	echo "entrypoint: nginx master already running as pid $running_master; refusing to re-run inside a live container (nothing was changed)" >&2
	exit 0
fi

# render_templates returns non-zero on missing DOMAIN; set -e makes that fatal
# (intended -- nginx must not start with an unrendered config). Do not add `|| true`.
render_templates

# Past the guard above, any pidfile here is stale by definition. See pidfile.sh for
# why it outlives the container and why clearing it is what keeps a reload racing
# nginx's startup from SIGHUPing this shell (#245).
#
# Residual: nginx calls ngx_create_pidfile() before it rewrites its argv to
# `nginx: master process ...`, so there is a sub-millisecond window at master
# startup where the pidfile exists but the probe above cannot recognise the owner.
# A re-run landing inside it would clear a live master's pidfile. Measured at 0 hits
# in 120 launches against a hot-spin sampler -- below shell resolution -- so it is
# recorded, not defended.
clear_stale_pidfile

# `|| true` is load-bearing: `set -e` applies inside this subshell, so without it a
# single failed reload terminates the loop for the life of the container, silently.
# That would strand the TLS cert renewal this loop exists for, and would also void
# the "6h loop is the bounded backstop" promise edge.sh makes for a rejected edge
# config. Verified: `set -eu` kills the subshell on its first failing iteration.
(while true; do
	sleep 21600
	nginx -s reload || echo "entrypoint: 6h reload failed; retrying in 6h" >&2
done) &

# Edge real-IP / Cloudflare origin-pull watcher. No-op unless EDGE_PROFILE=
# cloudflare; FATAL (exit 1) under that profile if the image lacks inotifyd, so a
# broken image fails at deploy rather than silently logging every client as the
# CF edge IP. Arms the watch (inotifyd survives the exec below, like the 6h loop).
# The watcher does NOT reload at boot -- nginx is not up yet and its own startup
# read loads current ranges; see edge.sh's initial-reconcile comment for why a
# reload here is fatal rather than the benign no-op it was assumed to be.
edge_start_watcher || exit 1

exec nginx -g 'daemon off;'
