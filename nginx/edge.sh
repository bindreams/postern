#!/bin/sh
# Edge real-IP / Cloudflare origin-pull config watcher. Two roles from one file:
#   * SOURCED by nginx-entrypoint.sh -> defines edge_reload + edge_start_watcher.
#   * EXECUTED by inotifyd as its PROG -> the $0 guard at the bottom runs one
#     edge_reload (inotifyd invokes: PROG <events> <dir> <name>).
#
# Under EDGE_PROFILE=cloudflare the provisioner atomically RENAMES the current
# Cloudflare IP ranges into $EDGE_DIR as *.conf (an IN_MOVED_TO event, mask :y).
# nginx's own startup config-read loads whatever is present; this watcher applies
# every SUBSEQUENT change. Under any other profile the edge config is static
# (render.sh writes it once) so the watcher is a no-op.
#
# Unit-tested without a container by portal/tests/test_nginx_edge.py via the
# EDGE_NGINX / EDGE_INOTIFYD injection seams (same idea as render.sh's *_DIR).

EDGE_DIR="${EDGE_DIR:-/var/lib/postern-edge}"
EDGE_SELF="${EDGE_SELF:-/usr/local/bin/edge.sh}"
EDGE_NGINX="${EDGE_NGINX:-nginx}"
EDGE_INOTIFYD="${EDGE_INOTIFYD:-inotifyd}"

# edge_reload: validate, then reload. Also the inotifyd PROG body (via $0 guard).
# Never fatal (returns 0): a bad edge config must not crash a running nginx.
edge_reload() {
	if ! "$EDGE_NGINX" -t; then
		# A rejected config produces NO new inotify event, so this is not fixed
		# "on the next change" -- the entrypoint's 6h reload loop is the bounded
		# backstop that re-attempts it. Keep the last-validated config live.
		echo "edge: nginx -t rejected the edge config; keeping the last-validated config live -- a rejected config yields no new inotify event, so the entrypoint's 6h reload loop is the bounded backstop that re-attempts it." >&2
		return 0
	fi
	if ! "$EDGE_NGINX" -s reload; then
		# Reachable at cold boot (master not up yet) or a transient signal error.
		# The config already validated; nginx startup or the entrypoint's 6h
		# reload loop applies it. Non-fatal.
		echo "edge: nginx -s reload failed (master not up yet at boot, or transient); config validated -- nginx startup or the entrypoint's 6h reload loop will apply it." >&2
		return 0
	fi
	echo "edge: reloaded nginx after edge config change" >&2
	return 0
}

# edge_start_watcher: arm the inotifyd watch + run one initial reconcile. The
# entrypoint calls it as `edge_start_watcher || exit 1`.
edge_start_watcher() {
	[ "${EDGE_PROFILE:-none}" = "cloudflare" ] || return 0

	if ! command -v "$EDGE_INOTIFYD" >/dev/null 2>&1; then
		# FATAL: a broken image must fail at DEPLOY, not silently skip real-IP
		# recovery (which would log every client as the Cloudflare edge IP and
		# break the auth rate-limit bucket). Do NOT soften this to return 0.
		echo "edge: FATAL inotifyd missing under EDGE_PROFILE=cloudflare" >&2
		return 1
	fi

	mkdir -p "$EDGE_DIR" || {
		echo "edge: FATAL cannot create $EDGE_DIR (postern-edge volume not mounted?)" >&2
		return 1
	}

	# Arm the watch FIRST (IN_MOVED_TO only, :y) so nothing written after this
	# line is missed. The child survives the entrypoint's `exec nginx` (like the
	# 6h reload loop) and applies every subsequent range change.
	"$EDGE_INOTIFYD" "$EDGE_SELF" "$EDGE_DIR:y" &
	EDGE_WATCHER_PID=$!
	# Catch an IMMEDIATE arm failure (e.g. inotifyd exits at once on a bad dir).
	kill -0 "$EDGE_WATCHER_PID" 2>/dev/null || {
		echo "edge: FATAL inotifyd failed to arm on $EDGE_DIR" >&2
		return 1
	}
	# The child's later runtime death is NOT actively monitored: a liveness poll
	# would be sync-via-time (forbidden). Deploy-time failure modes are covered
	# above; a mid-life crash is an accepted residual (nginx keeps last-loaded ranges).

	# INITIAL RECONCILE: a *.conf may have landed before the watch was armed.
	# Apply it once, now, deterministically (no sleep/poll). If none exists yet,
	# warn -- nginx runs without recovered client IPs until the provisioner
	# publishes ranges and this watcher reloads.
	if ls "$EDGE_DIR"/*.conf >/dev/null 2>&1; then
		edge_reload
	else
		echo "edge: WARNING EDGE_PROFILE=cloudflare but no range files in $EDGE_DIR yet; real client IPs are NOT recovered until the provisioner publishes Cloudflare ranges and this watcher reloads." >&2
	fi
	return 0
}

# $0 guard: when inotifyd EXECs this file as its PROG, $0 is this script's own
# path -> run one reload. When sourced (entrypoint or tests), $0 is the caller
# (never */edge.sh) so only the function definitions above take effect.
case "$0" in
	*/edge.sh) edge_reload ;;
esac
