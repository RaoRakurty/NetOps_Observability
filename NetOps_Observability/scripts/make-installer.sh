#!/usr/bin/env bash
#
# Build the Correlix offline installer bundle (#97 Phase 1).
#
# Produces a directory a client can install from with NOTHING but Docker +
# Compose v2 + zstd on the target host — no Node, no registry access, no PyPI:
#
#   dist/correlix-<version>/
#     install-correlix.sh                THE customer entry point (one command)
#     correlix-source-<version>.tar.gz   source tree (compose, configs, installer)
#     correlix-images-core-<version>.tar.zst        base appliance images
#     correlix-addon-<name>-<version>.tar.zst       optional add-on packs
#     SHA256SUMS                         integrity manifest
#     MANIFEST                           version, git sha, profile, image list
#     README.md                          customer quickstart (run one command)
#     ADVANCED.md                        external-Kafka + advanced settings
#     TROUBLESHOOTING.md                 customer-safe fixes
#     LICENSES.md                        third-party distribution notices
#
# Client install (the whole thing):
#   ./install-correlix.sh
#
# Usage (from anywhere in the repo):
#   scripts/make-installer.sh [--core] [--out DIR]
#     --core   base appliance archive ONLY (skip the add-on packs) — smallest
#              possible bundle for demo/eval. Default builds base + all packs.
#     --out    output directory (default: <repo>/dist)
#
# Prereqs on the BUILD host: docker+compose v2, zstd, node/npm (frontend dist),
# git. The frontend dist/ and docs portal are built if missing (they are
# gitignored — the classic stale-dist trap — so the bundle never depends on a
# developer having built them recently: REBUILD_FRONTEND=1 forces both).
#
# LICENSING (see docs/design/packaging-strategy.md §4 + bundle LICENSES.md):
# gate CLOSED 2026-07-03 — bus = Apache Kafka (Apache-2.0, replaced Redpanda
# BSL), cache = Valkey (BSD-3, replaced Redis RSAL). Guards below hard-fail
# the build if a flagged image ever reappears in the bundle set.

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

# 1. Frontend dist + docs portal (gitignored build artifacts the frontend image
#    COPYs). ALWAYS rebuild for a bundle: dist/ is gitignored and long-lived, so
#    a "build only if missing" check silently ships a STALE UI whenever a dev's
#    dist predates their source edits — exactly what shipped four bundles' worth
#    of un-scrubbed UI on 2026-07-04. Correctness over the ~30s build cost.
#    (REBUILD_FRONTEND=0 can force-skip only if you KNOW dist is fresh.)
if [ "${REBUILD_FRONTEND:-1}" != "0" ]; then
  echo "-- building frontend dist/ (fresh)"
  (cd "$ROOT/src/frontend" && npm ci --silent && npm run build)
fi

# The customer BASE = the appliance every install gets (embedded Apache Kafka
# bus + prober + all always-on services). Optional capability ships as ADD-ON
# PACKS — a small image archive per pack, enabled post-install with
# `./install-correlix.sh enable <addon>` (which flips the compose profile).
# Lab/dev profiles (mock-*, sso, netbox, seal, flowgen) stay out of client
# bundles by construction.
BASE_PROFILES=(--profile embedded-bus --profile prober)
ADDONS="log-search-ui:osd self-monitoring:self-monitoring"   # name:profile
[ "$PROFILE" = "core" ] && ADDONS=""   # --core: base appliance only, no packs

# 2. Build every application image at the pinned bases (all profiles, so
#    add-on packs can be cut from the same build).
echo "-- docker compose build"
# A CI runner has no .env; compose interpolation needs the :?-guarded vars.
export KAFKA_CLUSTER_ID="${KAFKA_CLUSTER_ID:-bundle-resolve-only-000000}"
(cd "$COMPOSE_DIR" && docker compose "${BASE_PROFILES[@]}" --profile osd --profile self-monitoring build --quiet)

# 3. Resolve the image sets. `config --images` honours pinned digests; an
#    add-on pack's set = (base + its profile) minus base.
echo "-- resolving image list"
IMAGES="$(cd "$COMPOSE_DIR" && docker compose "${BASE_PROFILES[@]}" config --images | sort -u)"
COUNT="$(printf '%s\n' "$IMAGES" | grep -c .)"
echo "   $COUNT base images"

# 3a. LICENSING GUARDS (#97): a customer bundle must never ship Redpanda (BSL)
#     and must ship Apache Kafka (bus) + Valkey (cache). Redis (RSAL) and
#     Prometheus are REMOVED components — permanently out of the product —
#     and must never reappear in any bundle. Hard build failures.
if printf '%s\n' "$IMAGES" | grep -qi 'redpanda'; then
  echo "FATAL: redpanda image in bundle set — BSL-licensed, not redistributable" >&2; exit 1
fi
if printf '%s\n' "$IMAGES" | grep -Eqi 'redis|prometheus'; then
  echo "FATAL: redis/prometheus image in bundle set — removed components (#97) must not ship" >&2; exit 1
fi
printf '%s\n' "$IMAGES" | grep -q '^apache/kafka:' \
  || { echo "FATAL: apache/kafka missing from bundle image set" >&2; exit 1; }
printf '%s\n' "$IMAGES" | grep -q '^valkey/valkey:' \
  || { echo "FATAL: valkey missing from bundle image set" >&2; exit 1; }
echo "   licensing guards passed (kafka+valkey in; redpanda/redis/prometheus out)"

# 3b. Ensure every bundled image exists locally. App images were just built;
#     third-party ones are digest-pinned pulls that a dev host has but a fresh
#     CI runner does not — `docker save` hard-fails on any missing reference.
#     Pull AFTER the core filter so a trimmed bundle never downloads images it
#     won't ship.
for img in $IMAGES; do
  docker image inspect "$img" >/dev/null 2>&1 || { echo "-- pulling $img"; docker pull -q "$img"; }
  # Pulls by digest don't create the plain tag, and we SAVE by tag (a digest
  # ref saves untagged — see §4). Ensure the tag exists locally; metadata-only.
  case "$img" in *@sha256:*) docker tag "$img" "${img%%@*}" ;; esac
done

# 4. Save + compress. zstd -3 multi-threaded: ~2x smaller than the raw save
#    at near-disk-speed compression. Bundle keeps the historical "core" name
#    for the base archive (install-correlix.sh globs correlix-images-*.tar.zst).
#
#    CRITICAL: save by TAG, never by tag@digest — `docker save ref@sha256:...`
#    exports the image UNTAGGED (empty RepoTags), so a virgin host loads
#    anonymous images and compose can't match anything (second virgin-host
#    finding, 2026-07-04). On this build host the tag resolves to the exact
#    digest-pinned image we just built/pulled, so the bytes are identical.
strip_digests() { sed 's/@sha256:[0-9a-f]*$//' | sort -u; }

# verify_archive_tags <archive.tar.zst> — every image in the archive must
# carry a RepoTag, or a fresh host cannot use it. Build-time hard failure.
verify_archive_tags() {
  zstd -dc "$1" | tar -xOf - manifest.json | python3 -c '
import json,sys
ms=json.load(sys.stdin)
bad=[m.get("Config","?") for m in ms if not m.get("RepoTags")]
if bad:
    print(f"FATAL: {len(bad)} untagged image(s) in archive — virgin hosts cannot use them", file=sys.stderr)
    sys.exit(1)
print(f"   archive tag check: {len(ms)} images, all tagged")'
}

IMG_OUT="$BUNDLE_DIR/correlix-images-core-$VERSION.tar.zst"
echo "-- docker save (base) -> $IMG_OUT"
SAVE_REFS="$(printf '%s\n' "$IMAGES" | strip_digests)"
# shellcheck disable=SC2086
docker save $SAVE_REFS | zstd -q -T0 -3 -f -o "$IMG_OUT"
verify_archive_tags "$IMG_OUT"

# 4b. Add-on packs: per pack, the images its profile adds on top of base.
ADDON_MANIFEST=""
for spec in $ADDONS; do
  name="${spec%%:*}"; prof="${spec##*:}"
  PACK_IMAGES="$(cd "$COMPOSE_DIR" && docker compose "${BASE_PROFILES[@]}" --profile "$prof" config --images | sort -u | comm -13 <(printf '%s\n' "$IMAGES") -)"
  [ -n "$PACK_IMAGES" ] || { echo "FATAL: addon $name resolved no images" >&2; exit 1; }
  if printf '%s\n' "$PACK_IMAGES" | grep -Eqi 'redpanda|redis|prometheus'; then
    echo "FATAL: forbidden image (redpanda/redis/prometheus — removed components) in addon $name" >&2; exit 1
  fi
  for img in $PACK_IMAGES; do
    docker image inspect "$img" >/dev/null 2>&1 || { echo "-- pulling $img"; docker pull -q "$img"; }
    case "$img" in *@sha256:*) docker tag "$img" "${img%%@*}" ;; esac
  done
  PACK_OUT="$BUNDLE_DIR/correlix-addon-$name-$VERSION.tar.zst"
  echo "-- docker save (addon $name) -> $PACK_OUT"
  PACK_REFS="$(printf '%s\n' "$PACK_IMAGES" | strip_digests)"
  # shellcheck disable=SC2086
  docker save $PACK_REFS | zstd -q -T0 -3 -f -o "$PACK_OUT"
  verify_archive_tags "$PACK_OUT"
  ADDON_MANIFEST="$ADDON_MANIFEST$(printf 'addon %s (profile %s):\n' "$name" "$prof"; printf '%s\n' "$PACK_IMAGES" | sed 's/^/  - /')
"
done

# 5. Source tree (dist/ and .env are gitignored and intentionally absent: the
#    client neither builds the frontend nor inherits our secrets — install.py
#    generates fresh secrets on their host).
SRC_OUT="$BUNDLE_DIR/correlix-source-$VERSION.tar.gz"
echo "-- git archive -> $SRC_OUT"
git -C "$ROOT" archive --format=tar.gz --prefix=NetOps_Observability/ -o "$SRC_OUT" HEAD

# 5b. Lab-leak guard (audit 2026-07-20): the tarball is git-archive-of-HEAD, so
#     a single mistaken commit can ship lab infrastructure to a customer. Fail
#     the build if any lab marker appears in the archive's paths or contents.
LAB_MARKERS='10\.70\.245\.120|rao123|correlix-faultlab|healthchecks\.io|hc-ping|ntfy\.sh|8d0f8a4e-c36e'
LAB_PATHS='scripts/lab/|scripts/bundle-autoupdate|scripts/stack-watchdog|scripts/host-hygiene|docs/GTM_PLAN|docs/TRACKER|mock-servicenow/|mock-nms/|brand-samples/'
if tar -tzf "$SRC_OUT" | grep -qE "$LAB_PATHS"; then
  echo "FATAL: lab-only path leaked into the customer source archive:" >&2
  tar -tzf "$SRC_OUT" | grep -E "$LAB_PATHS" | head >&2
  exit 1
fi
if tar -xzOf "$SRC_OUT" 2>/dev/null | grep -qaE "$LAB_MARKERS"; then
  echo "FATAL: lab identifier leaked into customer source archive contents:" >&2
  for f in $(tar -tzf "$SRC_OUT" | grep -v '/$'); do
    tar -xzOf "$SRC_OUT" "$f" 2>/dev/null | grep -qaE "$LAB_MARKERS" && echo "  $f" >&2
  done
  exit 1
fi
echo "-- lab-leak guard: clean"

# 6. Manifest + checksums + client instructions.
{
  echo "product:  Correlix (NetOps Observability)"
  echo "version:  $VERSION"
  echo "git_sha:  $GITSHA"
  echo "profile:  core"
  echo "built:    $(date -Is)"
  echo "images:"
  printf '%s\n' "$IMAGES" | sed 's/^/  - /'
  [ -n "$ADDON_MANIFEST" ] && printf '%s' "$ADDON_MANIFEST"
} > "$BUNDLE_DIR/MANIFEST"

# 7. The appliance installer + customer docs. install-correlix.sh at the
#    bundle root is THE customer entry point — one command, no choices.
cp "$ROOT/scripts/install-correlix.sh" "$BUNDLE_DIR/install-correlix.sh"
cp "$ROOT/scripts/prepare-host.sh" "$BUNDLE_DIR/prepare-host.sh"
chmod +x "$BUNDLE_DIR/install-correlix.sh" "$BUNDLE_DIR/prepare-host.sh"

cat > "$BUNDLE_DIR/README.md" <<EOF
# Correlix — Quick Start ($VERSION)

1. Prepare the host (installs Docker, Compose v2, zstd, kernel settings —
   one time, needs your package mirror):

       sudo ./prepare-host.sh

   then log out and back in. (Hosts that already run Docker can skip this;
   the installer verifies everything either way.)
2. Extract this bundle (you have, if you can read this).
3. Run the setup console and choose Install (or just let it run —
   scripted/non-interactive runs install directly):

       ./install-correlix.sh

4. Open the UI URL printed at the end.
5. Sign in with the generated credentials shown on screen.

That's it. The installer checks your host, verifies the bundle, loads the
software, starts everything, waits until it's healthy, and prints where to go.

Host guidance: Linux x86_64 · 4 vCPU / 16 GB RAM / 100 GB disk recommended
(2 vCPU / 8 GB / 40 GB minimum for evaluation). No internet access needed.

Day-to-day:

    ./install-correlix.sh status            service health
    ./install-correlix.sh logs [service]    recent logs
    ./install-correlix.sh stop | start      stop/start (data kept)
    ./install-correlix.sh uninstall         remove (add --purge to delete data)
    ./install-correlix.sh reset-demo-data   fresh evaluation state, same login

Optional add-ons (not started by default; enable any time):

    ./install-correlix.sh enable log-search-ui     power-user log forensics UI
    ./install-correlix.sh enable self-monitoring   Grafana + container/host metrics

Something not working? See TROUBLESHOOTING.md.
Larger deployments and advanced configuration: ADVANCED.md.
Third-party license information: LICENSES.md.
EOF

cat > "$BUNDLE_DIR/ADVANCED.md" <<EOF
# Correlix — Advanced Configuration

Most installations should use the default \`./install-correlix.sh\` and never
read this file.

## Event bus modes

Correlix moves telemetry internally over a Kafka-compatible event bus.

1. **Embedded (default).** The bundle includes Apache Kafka (Apache-2.0),
   run as a single-node service inside the appliance. It is internal-only
   (never exposed on a host port), sized for evaluation and small
   deployments, and needs no configuration.

2. **External Kafka-compatible broker (enterprise).** Point Correlix at a
   broker cluster you operate instead of starting the embedded one:

       ./install-correlix.sh install --external-kafka \\
           --broker-urls broker1:9092,broker2:9092

   Requirements: Kafka-compatible API (Apache Kafka 3.x/4.x or compatible),
   reachable from this host's Docker network, PLAINTEXT listener (TLS/SASL
   support: contact us). Correlix creates/uses topics under the \`netops.\`
   prefix. All services resolve the bus through the single BROKER_URLS
   setting in \`NetOps_Observability/deployment/docker/.env\`.

## Host preparation & preflight

- \`sudo ./prepare-host.sh\` — one-time host setup: Docker Engine + Compose v2
  (Docker official repo), zstd/python3, docker daemon baseline (live-restore,
  log caps, no-new-privileges), dedicated \`correlix\` service account, kernel
  settings (incl. \`vm.max_map_count\` the log store requires), time sync,
  unattended security updates. Add \`--firewall\` for a UFW profile scoped to
  Correlix's ports.
- \`sudo ./prepare-host.sh --check\` — read-only audit (PASS/FIX per item);
  the installer runs this automatically and REFUSES to install on an
  unready host.
- Supported platforms: Ubuntu 22.04+ / Debian 12, x86_64. Other Linux may
  work (set \`CORRELIX_SKIP_OS_CHECK=1\` to bypass the gate) but is not
  validated.

## Other settings

- UI port: \`./install-correlix.sh install --ui-port 9443\`
- All tunables live in \`NetOps_Observability/deployment/docker/.env\`
  (generated at install; treat it as a secret).
EOF

cat > "$BUNDLE_DIR/TROUBLESHOOTING.md" <<EOF
# Correlix — Troubleshooting

**The installer said a check failed.** The message names the fix (install
Docker, free a port, more RAM/disk). Re-running \`./install-correlix.sh\` is
always safe.

**A service shows "not running" or "unhealthy" in status.**
Look at its logs: \`./install-correlix.sh logs <service>\` — then
\`./install-correlix.sh stop && ./install-correlix.sh start\`. Most one-off
startup issues clear on a restart.

**The UI URL doesn't load.** Check the Web Front Door and Correlix UI rows in
\`./install-correlix.sh status\`; confirm the port isn't firewalled
(\`curl http://localhost:<port>/\` from the host itself).

**I lost the admin password.** It's stored in
\`NetOps_Observability/deployment/docker/.env\` (ADMIN_INITIAL_PASSWORD) —
valid until you change it in Settings.

**I want a clean slate.** \`./install-correlix.sh reset-demo-data\` wipes
collected data but keeps your URL and login.

**Slow on small hosts.** 8 GB RAM is the evaluation floor; give the VM
16 GB / 4 vCPU for real use.
EOF

cat > "$BUNDLE_DIR/LICENSES.md" <<EOF
# Correlix $VERSION — Third-party distribution notices

Correlix bundles the following third-party components as container images.
Exact pinned versions/digests: see MANIFEST.

| Component | Role | License | Distribution status |
|---|---|---|---|
| Apache Kafka | embedded event bus | Apache-2.0 | included — allowed with notices (this file + upstream NOTICE inside the image) |
| Valkey | cache | BSD-3-Clause | included — allowed |
| PostgreSQL | app database | PostgreSQL License | included — allowed |
| OpenSearch | log search | Apache-2.0 | included — allowed |
| OpenSearch Dashboards (log-search-ui add-on) | log forensics UI | Apache-2.0 | add-on pack — allowed |
| ClickHouse | analytics store | Apache-2.0 | included — allowed |
| VictoriaMetrics | metrics store | Apache-2.0 | included — allowed |

| Vector | telemetry pipeline | MPL-2.0 | included — allowed |
| goflow2 | flow receiver | BSD-3-Clause | included — allowed |
| syslog-ng | syslog receiver | GPL-3.0 (unmodified) | included — allowed |
| gnmic | gNMI collector | Apache-2.0 | included — allowed |
| nginx | web front door | BSD-2-Clause | included — allowed |
| Grafana (self-monitoring add-on) | self-observability | AGPL-3.0 | add-on pack, unmodified — allowed with source availability obligations |
| cadvisor / node-exporter (self-monitoring add-on) | container/host metrics | Apache-2.0 | add-on pack — allowed |

Resolved licensing history:

| Component | Status |
|---|---|
| Redis | **removed** — replaced by Valkey (BSD-3-Clause). Redis ≥7.4 is RSALv2/SSPL-licensed and is not distributed with Correlix. Closed. |
| Redpanda | **removed from customer distribution** — the event bus is Apache Kafka. Redpanda (BSL) is not shipped in any Correlix bundle. |

Correlix application code and this bundle's install tooling are proprietary
to Correlix.
EOF

# Customer-doc licensing guard: nothing customer-facing mentions Redpanda
# outside LICENSES.md's "not shipped" statement.
if grep -qi 'redpanda' "$BUNDLE_DIR/README.md" "$BUNDLE_DIR/ADVANCED.md" "$BUNDLE_DIR/TROUBLESHOOTING.md"; then
  echo "FATAL: customer-facing bundle docs mention redpanda" >&2; exit 1
fi

(cd "$BUNDLE_DIR" && sha256sum ./*.tar.* ./*.md MANIFEST install-correlix.sh prepare-host.sh > SHA256SUMS)

# TODO(#97, owner-gated): GPG-sign SHA256SUMS with the product signing key —
#   gpg --batch --detach-sign --armor -o SHA256SUMS.asc SHA256SUMS
# install-correlix.sh should verify SHA256SUMS.asc when present. The key is
# owner-held; NEVER generate or embed a signing key in this script or CI.

echo "== done"
du -sh "$BUNDLE_DIR"/* | sed 's/^/   /'
