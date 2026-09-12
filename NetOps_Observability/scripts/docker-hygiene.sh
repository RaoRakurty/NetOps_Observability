#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

#
# Weekly Docker hygiene for the NetOps stack host (#96b).
#
# The stack-watchdog already auto-prunes the BUILD CACHE as an emergency valve
# at 90% disk; this script is the scheduled, wider pass that keeps the host
# from ever getting there. It removes only things Docker itself knows are
# unreferenced — it never touches running containers, tagged images in use,
# bind-mounted data/ directories, or any volume a container references.
#
#   * build cache   -> keep 2 GB of the hottest layers (fast rebuilds), drop the rest
#                      (this class hit 25.8 GB once and silently stopped log ingest, 2026-06-12)
#   * images        -> dangling layers + images unused by any container
#   * volumes       -> anonymous/unreferenced only (the stack's real state lives in
#                      bind mounts under data/, never in named volumes)
#
# Install (weekly, Sunday 04:10):
#   (crontab -l; echo '10 4 * * 0 /home/rao/Projects/NetOps_Observability/NetOps_Observability/scripts/docker-hygiene.sh >> /home/rao/Projects/NetOps_Observability/NetOps_Observability/scripts/docker-hygiene.log 2>&1') | crontab -
#
# Safe to run by hand at any time: ./docker-hygiene.sh

set -uo pipefail
export PATH="/usr/local/bin:/usr/bin:/bin:${PATH:-}"

echo "== docker-hygiene $(date -Is) =="
echo "-- before --"
docker system df

echo "-- builder prune (keep-storage ${KEEP_BUILD_CACHE:-2GB}) --"
docker builder prune -f --keep-storage "${KEEP_BUILD_CACHE:-2GB}"

echo "-- image prune (unused by any container AND older than a week) --"
docker image prune -af --filter "until=168h"

echo "-- volume prune (anonymous/unreferenced only) --"
docker volume prune -f

echo "-- after --"
docker system df
df -h / | tail -1
echo "== done $(date -Is) =="
