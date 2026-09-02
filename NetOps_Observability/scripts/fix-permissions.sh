#!/usr/bin/env bash
#
# fix-permissions.sh — chown each data/ subdirectory to the UID/GID
# the corresponding container runs as. Run once after the first
# install if you see "permission denied" panics in container logs
# (typical for prometheus, grafana, opensearch, clickhouse).
#
# Run from the project root or anywhere — paths are resolved relative
# to the script's parent directory.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATA="$ROOT/data"

if [[ ! -d "$DATA" ]]; then
    echo "no data/ directory at $DATA — run scripts/install.py first" >&2
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    echo "must be run as root (sudo bash $0)" >&2
    exit 1
fi

# service → "uid:gid"
declare -A OWNERS=(
    [grafana]="472:472"
    [opensearch]="1000:1000"
    [clickhouse]="101:101"
    [kafka]="1000:1000"
    [victoria]="1000:1000"
    # postgres, redis, and api handle their own ownership; not listed
)

for svc in "${!OWNERS[@]}"; do
    dir="$DATA/$svc"
    if [[ ! -d "$dir" ]]; then
        echo "  skip $svc (no $dir)"
        continue
    fi
    own="${OWNERS[$svc]}"
    chown -R "$own" "$dir"
    echo "  ok    $dir  -> $own"
done

# ---- api-owned trees ---------------------------------------------------------
# The api runs user-mapped as CORRELIX_UID:CORRELIX_GID (install.py writes both
# into .env) with cap_drop:ALL, so a root-owned bind-mount source is one it can
# NEVER write — the failure mode Docker manufactures by auto-creating a missing
# bind source as root. install.py:ensure_data_dirs pre-creates these with the
# same owner; this script is the repair path for a tree that drifted (a sudo
# install, a restore, a manual mkdir).
ENV_FILE="$ROOT/deployment/docker/.env"
if [[ -f "$ENV_FILE" ]]; then
    # grep -m1 finds nothing on a pre-CORRELIX_UID .env; that is not an error,
    # so tolerate the non-zero status HERE and fall back to the image default
    # (the same default docker-compose.yml interpolates).
    API_UID="$(grep -m1 '^CORRELIX_UID=' "$ENV_FILE" | cut -d= -f2- || true)"
    API_GID="$(grep -m1 '^CORRELIX_GID=' "$ENV_FILE" | cut -d= -f2- || true)"
else
    echo "  warn  no $ENV_FILE — using the image default uid for api-owned dirs" >&2
    API_UID=""; API_GID=""
fi
[[ "$API_UID" =~ ^[0-9]+$ ]] || API_UID=65532
[[ "$API_GID" =~ ^[0-9]+$ ]] || API_GID=65532

# dir → mode ("" = leave the mode alone, only fix ownership)
declare -A API_DIRS=(
    [tls]=""                 # minted SVIDs + mesh trust bundle
    [config-backups]="0700"  # sealed device-configuration blobs
    [pcap]="0700"            # sealed packet-capture blobs
)

for sub in "${!API_DIRS[@]}"; do
    dir="$DATA/$sub"
    if [[ ! -d "$dir" ]]; then
        echo "  skip $sub (no $dir)"
        continue
    fi
    chown -R "$API_UID:$API_GID" "$dir"
    mode="${API_DIRS[$sub]}"
    if [[ -n "$mode" ]]; then
        chmod "$mode" "$dir"
        echo "  ok    $dir  -> $API_UID:$API_GID (mode $mode)"
    else
        echo "  ok    $dir  -> $API_UID:$API_GID"
    fi
done

echo
echo "Done. If any container was previously restarting on permissions,"
echo "restart it now:  docker compose restart <service>"
