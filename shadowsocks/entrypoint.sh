#!/bin/sh
# /bin/sh in the dhi.io/debian-base:bookworm runtime is bash (Debian ships
# /usr/bin/bash symlinked as /usr/bin/sh on this image). shell=bash tells
# shellcheck so `pipefail` and other bashisms below lint correctly instead
# of being warned as non-POSIX.
# shellcheck shell=bash
set -euo pipefail
: "${SS_CONFIG:?SS_CONFIG must be set and non-empty}"
echo "$SS_CONFIG" | base64 -d > /tmp/config.jsonc
exec ssserver -c /tmp/config.jsonc
