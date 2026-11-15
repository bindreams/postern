#!/usr/bin/env bash
# Raise every crate in ./Cargo.lock below its floor, then fail unless none is left below.
#
# A floor is the first release of a crate that fixes a RustSec advisory (cargo audit,
# 2026-11-15); rustls-webpki, webpki-roots and webpki-root-certs also stop trusting the
# compromised eMudhra chain (#254). The vendored lock is upstream's, so shadowsocks/Dockerfile
# and portal/tests/e2e/ssclient.Dockerfile run this in their cargo build stage, from the source
# root, before `cargo build`. A crate whose lock entry already meets its floor is not touched,
# so a subrepo pull that catches up needs no edit here; an entry here for a crate the lock
# dropped fails portal/tests/test_ssserver_crate_floors.py, not the build.
#
# Order matters: `cargo update --precise` on a crate can move or hold back the crates it depends
# on, so a dependency is raised before its dependent (zstd-sys and zstd-safe before zstd).
# Entries are `crate floor`; only the lock entries in the floor's semver series are compared
# (same major, or for 0.x the same major.minor), ignoring build metadata (`+zstd.1.5.7`).
set -euo pipefail
shopt -s inherit_errexit

floors=(
	"ctutils 0.4.4"
	"hickory-net 0.26.2"
	"hickory-proto 0.26.2"
	"hickory-resolver 0.26.2"
	"libz-sys 1.1.31"
	"quinn-proto 0.11.19"
	"quinn-udp 0.5.16"
	"rustix 1.1.6"
	"rustls 0.23.46"
	"rustls-webpki 0.103.16"
	"tokio 1.53.3"
	"webpki-root-certs 1.0.10"
	"webpki-roots 1.0.10"
	"zstd-sys 2.1.2"
	"zstd-safe 7.4.0"
	"zstd 0.13.4"
)

# Prints the locked version of every Cargo.lock entry of crate $1, one per line.
locked_versions() {
	awk -v name="$1" '
		$0 == "name = \"" name "\"" {
			getline
			if ($0 ~ /^version = ".*"$/) print substr($0, 12, length($0) - 12)
		}
	' Cargo.lock
}

# Prints the locked versions of crate $1 that are in the series of floor $2 and below it.
stale_versions() {
	local crate=$1 floor=$2 locked core lowest
	local -a locked_all floor_parts core_parts
	IFS=. read -ra floor_parts <<<"$floor"
	mapfile -t locked_all < <(locked_versions "$crate")
	for locked in "${locked_all[@]}"; do
		core=${locked%%+*}
		IFS=. read -ra core_parts <<<"$core"
		if [[ ${core_parts[0]} != "${floor_parts[0]}" ]]; then
			continue
		fi
		if [[ ${floor_parts[0]} == 0 && ${core_parts[1]} != "${floor_parts[1]}" ]]; then
			continue
		fi
		lowest=$(printf '%s\n%s\n' "$core" "$floor" | sort -V | sed -n 1p)
		if [[ $core != "$floor" && $lowest == "$core" ]]; then
			printf '%s\n' "$locked"
		fi
	done
}

for entry in "${floors[@]}"; do
	read -r crate floor <<<"$entry"
	stale=$(stale_versions "$crate" "$floor")
	for locked in $stale; do
		cargo update -p "$crate@$locked" --precise "$floor"
	done
done

failed=0
for entry in "${floors[@]}"; do
	read -r crate floor <<<"$entry"
	stale=$(stale_versions "$crate" "$floor")
	if [[ -n $stale ]]; then
		echo "crate-floors: $crate is locked at $stale, below its floor $floor" >&2
		failed=1
	fi
done
exit "$failed"
