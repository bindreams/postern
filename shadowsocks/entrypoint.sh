#!/bin/sh
# /bin/sh in the dhi.io/alpine-base:3.23 runtime is busybox ash (1.37), not
# strict POSIX sh. shell=ash tells shellcheck so pipefail (busybox 1.32+) and
# any future ash-isms lint correctly instead of being warned as non-POSIX.
# shellcheck shell=ash
set -euo pipefail
: "${SS_CONFIG:?SS_CONFIG must be set and non-empty}"
echo "$SS_CONFIG" | base64 -d > /tmp/config.jsonc
exec ssserver -c /tmp/config.jsonc
