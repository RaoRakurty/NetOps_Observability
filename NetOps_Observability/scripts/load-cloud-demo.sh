#!/usr/bin/env bash
# load-cloud-demo.sh — load (or clear) the Cloud App Observability demo inventory
# (#81 P3F+1). Use this to populate App Observability with synthetic AWS/Azure
# resources UNTIL real cloud connectors provide data; clear it the moment real
# telemetry arrives. The demo data is stamped to the GLOBAL tenant, so it shows
# for the platform owner.
#
#   scripts/load-cloud-demo.sh load    # install demo fixtures + restart api (default)
#   scripts/load-cloud-demo.sh clear   # remove all fixtures + restart api
#
# The api's CLOUD_FIXTURES_DIR (=/data/cloud-fixtures) is bind-mounted from
# data/api/cloud-fixtures, which is root-owned by the container — so file ops run
# inside a throwaway busybox container (writes as root into the bind mount).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"           # repo nested root (…/NetOps_Observability)
COMPOSE="$ROOT/deployment/docker/docker-compose.yml"
SRC="$ROOT/deployment/docker/demo-fixtures/cloud"  # committed demo fixtures (source of truth)
TGT="$ROOT/data/api/cloud-fixtures"                # runtime dir the api loads at boot

mkdir -p "$TGT"

case "${1:-load}" in
  load)
    docker run --rm -v "$TGT":/target -v "$SRC":/src:ro busybox:latest sh -c \
      'rm -rf /target/* 2>/dev/null; cp /src/*.json /target/; echo "installed:"; ls -1 /target'
    docker compose -f "$COMPOSE" restart api
    echo "demo inventory loaded — open Monitor → App Observability (platform owner)."
    ;;
  clear)
    docker run --rm -v "$TGT":/target busybox:latest sh -c 'rm -rf /target/* 2>/dev/null; echo cleared'
    docker compose -f "$COMPOSE" restart api
    echo "demo inventory cleared."
    ;;
  *)
    echo "usage: $0 [load|clear]" >&2; exit 1 ;;
esac
