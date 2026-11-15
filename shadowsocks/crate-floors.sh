#!/usr/bin/env bash
# Raise every crate in ./Cargo.lock below its floor, then fail unless none is left below.
#
# A floor is the first release of a crate that fixes a RustSec advisory; rustls-webpki,
# webpki-roots and webpki-root-certs also stop trusting the compromised eMudhra chain.
# Run from the source root before `cargo build`. A crate already at its floor is left alone.
#
# Order matters: `cargo update --precise` on a crate can move or hold back the crates it depends
# on, so a dependency is raised before its dependent (zstd-sys and zstd-safe before zstd).
# Entries are `crate floor`; only the lock entries in the floor's semver series are compared
# (same major, or for 0.x the same major.minor), ignoring build metadata (`+zstd.1.5.7`). A
# pre-release of the floor (`1.53.3-rc.1`) precedes it and is raised. Entries in another series
# are skipped with a notice on stderr. A floored crate with no lock entry fails the run.
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
# Notices for skipped entries go to stderr unless $report_skips is false.
stale_versions() {
	local crate=$1 floor=$2 locked_all locked core numeric lowest
	local -a floor_parts numeric_parts
	IFS=. read -ra floor_parts <<<"$floor"
	locked_all=$(locked_versions "$crate")
	if [[ -z $locked_all ]]; then
		echo "crate-floors: $crate has no entry in Cargo.lock, but a floor of $floor" >&2
		return 1
	fi
	while IFS= read -r locked; do
		core=${locked%%+*}
		numeric=${core%%-*}
		IFS=. read -ra numeric_parts <<<"$numeric"
		if [[ ${numeric_parts[0]} != "${floor_parts[0]}" ]] ||
			[[ ${floor_parts[0]} == 0 && ${numeric_parts[1]} != "${floor_parts[1]}" ]]; then
			if $report_skips; then
				echo "crate-floors: skipping $crate $locked: outside the series of its floor $floor" >&2
			fi
			continue
		fi
		lowest=$(printf '%s\n%s\n' "$numeric" "$floor" | sort -V | sed -n 1p)
		if [[ $numeric != "$floor" && $lowest == "$numeric" ]] || [[ $numeric == "$floor" && $core != "$numeric" ]]; then
			printf '%s\n' "$locked"
		fi
	done <<<"$locked_all"
}

if [[ ! -f Cargo.lock ]]; then
	echo "crate-floors: no Cargo.lock in $PWD" >&2
	exit 1
fi

report_skips=true
for entry in "${floors[@]}"; do
	read -r crate floor <<<"$entry"
	stale=$(stale_versions "$crate" "$floor")
	for locked in $stale; do
		cargo update -p "$crate@$locked" --precise "$floor"
	done
done

report_skips=false
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
