#!/bin/sh
# Stale-pidfile hygiene for the nginx entrypoint. Sourced by nginx-entrypoint.sh;
# unit-tested without a container via the PIDFILE / PROC_DIR seams (the same idea
# as render.sh's TEMPLATE_DIR and edge.sh's EDGE_NGINX).
#
# /run is the image's writable layer, not a tmpfs, so a pidfile left behind by an
# ungracefully stopped container (host reboot, SIGKILL -- a graceful stop makes
# nginx unlink it) is still present and still names a pid. The entrypoint ends in
# `exec nginx`, so the pid it records is the entrypoint SHELL's own, and a restarted
# container's fresh pid namespace hands that same number to the new shell. A reload
# racing nginx's startup then SIGHUPs the entrypoint, which has installed no
# handler, and tini reports 128+1=129. Assume that loop is TERMINAL: nginx never
# gets far enough to rewrite the pidfile, and the namespace reissues the same
# number every time. See issue #245.

PIDFILE="${PIDFILE:-/run/nginx.pid}"
PROC_DIR="${PROC_DIR:-/proc}"

# nginx_master_pid: echo the pid named by the pidfile IF it is a live nginx master,
# else nothing (returns 1).
#
# Liveness is the wrong question and must not be used here: at a genuine boot the
# recorded pid is this very shell, which is emphatically alive -- that is the whole
# bug. Only "is that pid an nginx master" separates a stale pidfile from one owned
# by a master that is already serving, and a master answers that itself by
# rewriting its argv to `nginx: master process ...` at startup.
nginx_master_pid() {
	pid="$(cat "$PIDFILE" 2>/dev/null || :)"
	# Non-numeric is treated as absent. `self` and `thread-self` are real /proc
	# entries, and the probe below reads grep's OWN argv through them -- which
	# contains the pattern -- so without this a pidfile holding either string would
	# preserve itself. Garbage must fail toward clearing, never toward keeping.
	case "$pid" in
		'' | *[!0-9]*) return 1 ;;
	esac
	# -s so an unreadable or missing entry is a silent miss (exit 2 -> clear), which
	# keeps every unexpected environment failing in the safe direction.
	grep -qs 'master process' "$PROC_DIR/$pid/cmdline" || return 1
	echo "$pid"
}

# clear_stale_pidfile: remove the pidfile, reporting which arm ran.
#
# Best-effort: absence is hygiene, not a startup precondition, and nginx rewrites
# the file anyway -- an unlink failure (an unwritable /run after a uid change, say)
# must not become the new reason nginx never boots. It is logged rather than
# swallowed, because a silent failure here is indistinguishable from success and
# leaves the container armed for #245.
clear_stale_pidfile() {
	[ -e "$PIDFILE" ] || return 0
	if rm -f "$PIDFILE" 2>/dev/null; then
		echo "pidfile: cleared stale $PIDFILE left by a previous container process" >&2
	else
		echo "pidfile: WARNING could not remove stale $PIDFILE; a reload racing nginx's startup may signal the wrong process" >&2
	fi
	return 0
}
