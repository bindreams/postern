#!/bin/sh
# shellcheck shell=bash
# /bin/sh in the dhi.io/debian-base:trixie runtime is bash (Debian ships
# /usr/bin/bash symlinked as /usr/bin/sh on this image). The directive above
# tells shellcheck that pipefail and other bashisms below should lint as bash,
# not as strict POSIX sh.
set -euo pipefail
: "${SS_CONFIG:?SS_CONFIG must be set and non-empty}"
echo "$SS_CONFIG" | base64 -d > /tmp/config.jsonc
exec ssserver -c /tmp/config.jsonc
