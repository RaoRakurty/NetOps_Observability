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
    [prometheus]="65534:65534"
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

echo
echo "Done. If any container was previously restarting on permissions,"
echo "restart it now:  docker compose restart <service>"
