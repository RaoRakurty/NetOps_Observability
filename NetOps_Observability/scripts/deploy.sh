#!/usr/bin/env bash
# deploy.sh — self-healing deploy for the NetOps_Observability stack.
#
# WHY THIS EXISTS: the frontend image (Dockerfile.frontend) ships a PRE-BUILT
# src/frontend/dist/. If you rebuild the container without rebuilding dist first,
# it silently serves the OLD bundle ("stale frontend"). This script removes that
# whole class of error by making the deploy ATOMIC and VERIFIED:
#
#   1. build the frontend bundle FRESH (fail-fast — never ship a broken build)
#   2. record the currently-running images (the rollback target)
#   3. rebuild + recreate the requested services
#   4. HEALTH GATE   — the app + API must answer on :8000
#   5. FRESHNESS GATE — the SERVED bundle hash must equal the JUST-BUILT hash
#                       (this is the check that catches "stale frontend")
#   6. on ANY failure → SELF-HEAL: roll the services back to the previous images
#                       and confirm the stack is healthy again (safe mode)
#
# Usage:  scripts/deploy.sh [service ...]      (default: frontend api)
#         scripts/deploy.sh api                (backend only — skips dist build)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DC=(docker compose -f "$ROOT/deployment/docker/docker-compose.yml")
PROJECT="netops"                                   # compose project → image prefix
BASE_URL="${DEPLOY_BASE_URL:-http://localhost:8000}"
SERVICES=("${@:-}"); [ -z "${SERVICES[*]}" ] && SERVICES=(frontend api)

c_b="\033[1m"; c_r="\033[31m"; c_g="\033[32m"; c_y="\033[33m"; c_0="\033[0m"
log()  { printf "${c_b}[deploy]${c_0} %s\n" "$*"; }
warn() { printf "${c_y}[deploy]${c_0} %s\n" "$*"; }
ok()   { printf "${c_g}[deploy] %s${c_0}\n" "$*"; }
die()  { printf "${c_r}[deploy] FAIL:${c_0} %s\n" "$*" >&2; }

has() { local x; for x in "${SERVICES[@]}"; do [ "$x" = "$1" ] && return 0; done; return 1; }

# App + API must both answer. Returns 0 when healthy.
health() {
  curl -fsS -o /dev/null --max-time 5 "$BASE_URL/" \
    && curl -fsS -o /dev/null --max-time 5 "$BASE_URL/api/auth/methods"
}
wait_health() {
  local i; for i in $(seq 1 "${1:-30}"); do health && return 0; sleep 2; done; return 1
}
served_bundle() { curl -fsS --max-time 5 "$BASE_URL/" | grep -oE 'index-[A-Za-z0-9_-]+\.js' | head -1; }

# ── rollback (safe mode) ──────────────────────────────────────────────────────
declare -A OLD_IMG
rollback() {
  die "$1"
  warn "rolling back to the previous build (safe mode)…"
  local s restored=0
  for s in "${SERVICES[@]}"; do
    if [ -n "${OLD_IMG[$s]:-}" ]; then
      docker tag "${OLD_IMG[$s]}" "${PROJECT}-${s}:latest" >/dev/null 2>&1 \
        && "${DC[@]}" up -d --no-build "$s" >/dev/null 2>&1 \
        && { restored=1; warn "  restored $s → ${OLD_IMG[$s]:7:12}"; }
    else
      warn "  no prior image recorded for $s (was it running before?)"
    fi
  done
  if [ "$restored" = 1 ] && wait_health 20; then
    die "deploy aborted — STACK ROLLED BACK and healthy on the previous build."
    exit 1
  fi
  die "ROLLBACK FAILED OR STACK STILL UNHEALTHY — manual intervention required."
  exit 2
}

log "target services: ${SERVICES[*]}"

# 1. fresh frontend build (fail-fast, BEFORE touching the running stack)
BUILT_HASH=""
if has frontend; then
  log "building frontend bundle (fresh)…"
  if ! ( cd "$ROOT/src/frontend" && npm run build ); then
    die "frontend build failed — running stack left UNTOUCHED."; exit 1
  fi
  BUILT_HASH="$(basename "$(ls -t "$ROOT"/src/frontend/dist/assets/index-*.js | head -1)")"
  log "built bundle: $BUILT_HASH"
fi

# 2. record current images for rollback
for s in "${SERVICES[@]}"; do
  cid="$("${DC[@]}" ps -q "$s" 2>/dev/null || true)"
  [ -n "$cid" ] && OLD_IMG[$s]="$(docker inspect -f '{{.Image}}' "$cid" 2>/dev/null || true)"
done

# 3. rebuild + recreate
log "rebuilding + recreating containers…"
"${DC[@]}" up -d --build "${SERVICES[@]}" || rollback "compose build/up failed"

# 4. health gate
log "health gate…"
wait_health 30 || rollback "stack did not become healthy after deploy"

# 5. freshness gate — the anti-stale-frontend check
if [ -n "$BUILT_HASH" ]; then
  SERVED="$(served_bundle)"
  if [ "$SERVED" != "$BUILT_HASH" ]; then
    rollback "STALE FRONTEND — serving '$SERVED' but built '$BUILT_HASH' (dist not picked up)"
  fi
  ok "freshness verified — serving the just-built bundle ($SERVED)"
fi

ok "deploy succeeded ✅  (${SERVICES[*]})"
