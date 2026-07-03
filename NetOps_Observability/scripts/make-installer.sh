#!/usr/bin/env bash
#
# Build the Correlix offline installer bundle (#97 Phase 1).
#
# Produces a directory a client can install from with NOTHING but Docker +
# Compose v2 + zstd on the target host — no Node, no registry access, no PyPI:
#
#   dist/correlix-<version>/
#     correlix-source-<version>.tar.gz   source tree (compose, configs, installer)
#     correlix-images-<profile>-<version>.tar.zst   every image, prebuilt
#     SHA256SUMS                         integrity manifest
#     MANIFEST                           version, git sha, profile, image list
#     INSTALL.md                         client instructions
#
# Client install:
#   tar -xzf correlix-source-<version>.tar.gz && cd NetOps_Observability
#   python3 scripts/install.py --bundle ../correlix-images-<profile>-<version>.tar.zst
#
# Usage (from anywhere in the repo):
#   scripts/make-installer.sh [--core] [--out DIR]
#     --core   trimmed bundle: drops OpenSearch Dashboards, Grafana, cadvisor,
#              node-exporter (the in-app Logs view + boards cover them) — for
#              demo/eval VMs. Default is the full stack.
#     --out    output directory (default: <repo>/dist)
#
# Prereqs on the BUILD host: docker+compose v2, zstd, node/npm (frontend dist),
# git. The frontend dist/ and docs portal are built if missing (they are
# gitignored — the classic stale-dist trap — so the bundle never depends on a
# developer having built them recently: REBUILD_FRONTEND=1 forces both).
#
# ⚠️ LICENSING GATE (see docs/design/packaging-strategy.md §4): before any
# EXTERNAL distribution, resolve Redpanda (BSL — written OK or Kafka swap).
# Redis→Valkey done 2026-07-03; Grafana (AGPL) is omitted by --core. Internal/
# lab bundles are unaffected either way.

set -euo pipefail
export PATH="/usr/local/bin:/usr/bin:/bin:${PATH:-}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/dist"
PROFILE="full"
while [ $# -gt 0 ]; do
  case "$1" in
    --core) PROFILE="core"; shift ;;
    --out)  OUT="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

command -v zstd >/dev/null || { echo "zstd is required (apt-get install zstd)" >&2; exit 1; }
# date+sha, not `git describe` — the repo's tags are milestone markers, not
# release tags, and produce unusable bundle names. Product release tags
# (v-prefixed) win when present.
VERSION="$(git -C "$ROOT" describe --tags --match 'v[0-9]*' --always 2>/dev/null | grep -E '^v[0-9]' || true)"
[ -n "$VERSION" ] || VERSION="$(date +%Y.%m.%d)-g$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
GITSHA="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
BUNDLE_DIR="$OUT/correlix-$VERSION"
COMPOSE_DIR="$ROOT/deployment/docker"
mkdir -p "$BUNDLE_DIR"

echo "== correlix installer bundle $VERSION ($PROFILE) -> $BUNDLE_DIR"

# 1. Frontend dist + docs portal (gitignored build artifacts the frontend
#    image COPYs; without them `compose build frontend` fails or ships stale UI).
if [ ! -d "$ROOT/src/frontend/dist" ] || [ "${REBUILD_FRONTEND:-0}" = "1" ]; then
  echo "-- building frontend dist/"
  (cd "$ROOT/src/frontend" && npm ci --silent && npm run build)
fi

# 2. Build every application image at the pinned bases.
echo "-- docker compose build"
(cd "$COMPOSE_DIR" && docker compose --profile osd --profile prober build --quiet)

# 3. Resolve the exact image set for the bundle profile. `config --images`
#    honours pinned digests; profiles not enabled here (mock-*, sso, netbox,
#    seal, flowgen) stay out of the client bundle by construction.
echo "-- resolving image list"
IMAGES="$(cd "$COMPOSE_DIR" && docker compose --profile osd --profile prober config --images | sort -u)"
if [ "$PROFILE" = "core" ]; then
  IMAGES="$(printf '%s\n' "$IMAGES" | grep -vE 'opensearch-dashboards|grafana|cadvisor|node-exporter')"
fi
COUNT="$(printf '%s\n' "$IMAGES" | grep -c .)"
echo "   $COUNT images"

# 3b. Ensure every bundled image exists locally. App images were just built;
#     third-party ones are digest-pinned pulls that a dev host has but a fresh
#     CI runner does not — `docker save` hard-fails on any missing reference.
#     Pull AFTER the core filter so a trimmed bundle never downloads images it
#     won't ship.
for img in $IMAGES; do
  docker image inspect "$img" >/dev/null 2>&1 || { echo "-- pulling $img"; docker pull -q "$img"; }
done

# 4. Save + compress. zstd -3 multi-threaded: ~2x smaller than the raw save
#    at near-disk-speed compression.
IMG_OUT="$BUNDLE_DIR/correlix-images-$PROFILE-$VERSION.tar.zst"
echo "-- docker save -> $IMG_OUT"
# shellcheck disable=SC2086
docker save $IMAGES | zstd -q -T0 -3 -f -o "$IMG_OUT"

# 5. Source tree (dist/ and .env are gitignored and intentionally absent: the
#    client neither builds the frontend nor inherits our secrets — install.py
#    generates fresh secrets on their host).
SRC_OUT="$BUNDLE_DIR/correlix-source-$VERSION.tar.gz"
echo "-- git archive -> $SRC_OUT"
git -C "$ROOT" archive --format=tar.gz --prefix=NetOps_Observability/ -o "$SRC_OUT" HEAD

# 6. Manifest + checksums + client instructions.
{
  echo "product:  Correlix (NetOps Observability)"
  echo "version:  $VERSION"
  echo "git_sha:  $GITSHA"
  echo "profile:  $PROFILE"
  echo "built:    $(date -Is)"
  echo "images:"
  printf '%s\n' "$IMAGES" | sed 's/^/  - /'
} > "$BUNDLE_DIR/MANIFEST"

cat > "$BUNDLE_DIR/INSTALL.md" <<EOF
# Correlix offline install ($VERSION, $PROFILE profile)

Target host: Linux x86_64 · 4 vCPU / 16 GB RAM / 100 GB disk recommended
(2 vCPU / 8 GB / 40 GB minimum for evaluation) · Docker Engine + Compose v2
plugin · zstd. No other network or toolchain access is needed.

    sha256sum -c SHA256SUMS
    tar -xzf correlix-source-$VERSION.tar.gz
    cd NetOps_Observability
    python3 scripts/install.py --bundle ../correlix-images-$PROFILE-$VERSION.tar.zst

The installer generates fresh secrets on this host, loads the images, and
starts the stack on port 8000 (override: --port). First sign-in credentials
are printed at the end. Stop: \`cd deployment/docker && docker compose down\`.
EOF

(cd "$BUNDLE_DIR" && sha256sum ./*.tar.* MANIFEST INSTALL.md > SHA256SUMS)

echo "== done"
du -sh "$BUNDLE_DIR"/* | sed 's/^/   /'
