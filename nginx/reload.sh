#!/usr/bin/env bash
# This is a cronjob. Create a symlink to this script in /etc/cron.daily
set -euxo pipefail
cd $(dirname $(realpath "$0"))

docker compose exec nginx nginx -s reload
