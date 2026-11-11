#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

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
# MOUNTED CONFIG (2026-11-10): compose recreates a container only when its image
# or compose definition changed, so a service whose only change is a bind-mounted
# config file (vector-aggregator's VRL, syslog-ng's conf, vmalert's rules) kept
# running the OLD config after a deploy — seen three times on the lab, once for
# 7 h. After step 3 this script recreates every NAMED service whose mounted config
# changed and that compose left running, waits for it to be running/healthy, and
# runs the normal health gate over it. Fingerprints of the last successful deploy
# live in data/.deploy/config-fingerprints.json (scripts/mounted_config.py holds
# the rule for which mounts count; scripts/lib/mounted-config.sh the mechanics).
#   Decision: an explicit service list is a scope the operator chose, so by
#   default ONLY named services are recreated. Every OTHER running service whose
#   mounted config changed is WARNED about by name (it still runs the old config)
#   and keeps its old fingerprint, so the warning repeats until it is applied.
#   --reload-changed-config recreates those too. (update.sh, the customer path,
#   always recreates every changed service.) The first deploy with no fingerprint
#   record recreates nothing extra: it records a baseline and says so.
#
# .ENV MIGRATION (2026-11-11): before anything is built or recreated, an installed
# stack's deployment/docker/.env gains the keys this tree introduced, through the
# installer's own migration (`python3 scripts/install.py --migrate-env`, the same
# step update.sh runs). Only missing keys are appended, never a value changed;
# .env is backed up 0600 first; names only are printed. See step 2a.
#
# Usage:  scripts/deploy.sh [--reload-changed-config] [service ...]
#                                              (default services: frontend api)
#         scripts/deploy.sh api                (backend only — skips dist build)
#         scripts/deploy.sh --reload-changed-config api
#                                              (api + every running service whose
#                                               mounted config changed)
# Exit:   0 deployed · 1 aborted (stack untouched, or rolled back and healthy)
#         2 manual intervention required · 3 deployed and healthy, but the
#         mounted-config fingerprint record could not be written
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_DIR="$ROOT/deployment/docker"
# Compose runs FROM the compose directory with NO -f: only then does it read that
# directory's .env COMPOSE_FILE chain (compose.tls.yml, the offline-images
# override, …). An explicit -f keeps the .env VARIABLES but drops every overlay —
# on a TLS install that recreated services half-plaintext (verify-full DSN, no
# cert mounts), the api crash-looped, the site answered 502, and the rollback
# used the same -f so it could not recover either (2026-10-04, lab).
dc() { ( cd "$COMPOSE_DIR" && docker compose "$@" ); }
PROJECT="netops"                                   # compose project → image prefix
BASE_URL="${DEPLOY_BASE_URL:-http://localhost:8000}"

c_b="\033[1m"; c_r="\033[31m"; c_g="\033[32m"; c_y="\033[33m"; c_0="\033[0m"
log()  { printf "${c_b}[deploy]${c_0} %s\n" "$*"; }
warn() { printf "${c_y}[deploy]${c_0} %s\n" "$*"; }
ok()   { printf "${c_g}[deploy] %s${c_0}\n" "$*"; }
die()  { printf "${c_r}[deploy] FAIL:${c_0} %s\n" "$*" >&2; }

RELOAD_CHANGED_CONFIG=0
SERVICES=()
for arg in "$@"; do
  case "$arg" in
    --reload-changed-config) RELOAD_CHANGED_CONFIG=1 ;;
    -h|--help) sed -n '5,/^set -uo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    -*) die "unknown flag: $arg (see --help)"; exit 2 ;;
    *) SERVICES+=("$arg") ;;
  esac
done
[ "${#SERVICES[@]}" -eq 0 ] && SERVICES=(frontend api)

# SC1091: a plain `shellcheck deploy.sh` (no -x) cannot follow the helper; it is
# checked on its own, and `shellcheck -x` follows it through source-path.
# shellcheck source-path=SCRIPTDIR source=lib/mounted-config.sh disable=SC1091
if ! . "$ROOT/scripts/lib/mounted-config.sh"; then
  die "cannot load $ROOT/scripts/lib/mounted-config.sh — incomplete install tree"; exit 1
fi
mc_init "$ROOT" "$COMPOSE_DIR"
trap mc_cleanup EXIT
CFG_RELOADED=()   # recreated by this run for a mounted-config change
CFG_UNAPPLIED=()  # a mounted-config recreate that failed

has() { local x; for x in "${SERVICES[@]}"; do [ "$x" = "$1" ] && return 0; done; return 1; }

# App + API must both answer. Returns 0 when healthy.
health() {
  curl -fsS -o /dev/null --max-time 5 "$BASE_URL/" \
    && curl -fsS -o /dev/null --max-time 5 "$BASE_URL/api/auth/methods"
}
wait_health() {
  local _; for _ in $(seq 1 "${1:-30}"); do health && return 0; sleep 2; done; return 1
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
        && dc up -d --no-build --no-deps "$s" >/dev/null 2>&1 \
        && { restored=1; warn "  restored $s → ${OLD_IMG[$s]:7:12}"; }
    else
      warn "  no prior image recorded for $s (was it running before?)"
    fi
  done
  # A mounted-config change cannot be rolled back by re-tagging an image: the new
  # config IS the source tree on disk. Name every such service so nobody reads
  # "rolled back" as "everything is on the previous build".
  local unnamed=()
  for s in "${CFG_RELOADED[@]}" "${CFG_UNAPPLIED[@]}"; do has "$s" || unnamed+=("$s"); done
  if [ "${#unnamed[@]}" -gt 0 ]; then
    warn "  NOT rolled back (touched for a mounted-config change; the config on disk is the new one): ${unnamed[*]}"
  fi
  if [ "${#CFG_UNAPPLIED[@]}" -gt 0 ]; then
    if [ "$restored" = 1 ] && wait_health 20; then
      warn "  the app answers on $BASE_URL again"
    fi
    die "MOUNTED CONFIG COULD NOT BE APPLIED to: ${CFG_UNAPPLIED[*]} — they may be down or crash-looping on the new config. Inspect: (cd $COMPOSE_DIR && docker compose ps && docker compose logs --tail 100 ${CFG_UNAPPLIED[*]}); fix or revert those config files, then re-run scripts/deploy.sh ${CFG_UNAPPLIED[*]}. Manual intervention required."
    exit 2
  fi
  if [ "$restored" = 1 ] && wait_health 20; then
    die "deploy aborted — STACK ROLLED BACK and healthy on the previous build."
    exit 1
  fi
  die "ROLLBACK FAILED OR STACK STILL UNHEALTHY — manual intervention required."
  exit 2
}

# ── key custody ordering (2026-11-09) ─────────────────────────────────────────
# The api applies key modes at every boot, and this script recreates ONLY the
# named services. On the first deploy after the custody change, recreating the api
# alone would tighten the keys while every reader still runs without group_add:
# nothing breaks at once, because they hold their keys in memory, but the next
# restart or certificate reload of that reader fails, and the store stays down.
# So the readers are recreated first, while their keys are still readable either
# way. Only a container with no group_add counts, so this runs once per install.
# Keep the list equal to the "group" rows of deployment/docker/tls-key-readers.json
# (tests/test_tls_key_custody.py pins it).
CUSTODY_READERS=(opensearch kafka redis correlation prober cloud-ingest nginx)
custody_converge() {
  has api || return 0
  local cfg s cid ga stale=()
  # Fail closed: a config this script cannot render is not evidence of plaintext,
  # and guessing wrong here is exactly the ordering this function exists for. The
  # rendered config holds interpolated values, so only its error tail is shown.
  if ! cfg="$(dc config 2>&1)"; then
    die "cannot render the compose config to check key custody: $(printf '%s' "$cfg" | tail -n 3) — running stack left UNTOUCHED."
    exit 1
  fi
  case "$cfg" in *"group_add:"*) ;; *) return 0 ;; esac   # plaintext: no group readers
  for s in "${CUSTODY_READERS[@]}"; do
    # Same idiom as step 2: a service outside the active profiles has no
    # container, and `ps -q` erroring on it means the same thing here.
    cid="$(dc ps -q "$s" 2>/dev/null || true)"
    [ -n "$cid" ] || continue
    if ! ga="$(docker inspect -f '{{json .HostConfig.GroupAdd}}' "$cid" 2>&1)"; then
      die "cannot inspect $s to check its key access ($ga) — running stack left UNTOUCHED."
      exit 1
    fi
    case "$ga" in null|'[]') stale+=("$s") ;; esac
  done
  [ "${#stale[@]}" -gt 0 ] || return 0
  warn "key custody: recreating ${stale[*]} with group access BEFORE the api tightens its keys"
  local x
  for x in "${stale[@]}"; do
    if [ "$x" = opensearch ]; then
      # opensearch-security-init shares this image and needs its group-readable home.
      if ! dc build opensearch; then
        die "opensearch image build failed — running stack left UNTOUCHED."; exit 1
      fi
    fi
  done
  if ! dc up -d --no-deps --no-build --wait --wait-timeout 300 "${stale[@]}"; then
    die "could not bring ${stale[*]} up with group access. The api was NOT recreated, so no key was tightened."
    exit 1
  fi
}

log "target services: ${SERVICES[*]}"

# 1. fresh frontend build (fail-fast, BEFORE touching the running stack)
BUILT_HASH=""
if has frontend; then
  log "building frontend bundle (fresh)…"
  if ! ( cd "$ROOT/src/frontend" && npm run build ); then
    die "frontend build failed — running stack left UNTOUCHED."; exit 1
  fi
  # shellcheck disable=SC2012 # vite names its bundles index-<hash>.js ([A-Za-z0-9_-]); ls -t is the newest-first pick
  BUILT_HASH="$(basename "$(ls -t "$ROOT"/src/frontend/dist/assets/index-*.js | head -1)")"
  log "built bundle: $BUILT_HASH"
fi

# 2. record current images for rollback
for s in "${SERVICES[@]}"; do
  cid="$(dc ps -q "$s" 2>/dev/null || true)"
  [ -n "$cid" ] && OLD_IMG[$s]="$(docker inspect -f '{{.Image}}' "$cid" 2>/dev/null || true)"
done

# 2b. render the service credential files (tracker 367 layer 1). The compose
# files mount data/secrets/<group>/<identity>/ into every client and vmauth; a
# container recreated without its file refuses to start or fails every
# authenticated call. install.py and update.sh render them; this deploy path
# must too, or the first `deploy.sh api` after the 367 upgrade takes metrics
# down. The SAME renderer (one definition of names, owners, modes), BEFORE the
# running stack is touched — a failure here leaves it untouched.
# No .env = no installed stack (a plaintext dev checkout): nothing mounts a
# credential file, so there is nothing to render — said out loud, not skipped
# silently. With a .env (every install), a render failure aborts the deploy.
# Tracker 384: an old-form .env (a password in DATABASE_URL) is moved to its
# file-backed key first, in the same step. Idempotent; no manual step.
#
# 2a (2026-11-11) runs first, in the same branch: `install.py --migrate-env`,
# the installer's own .env migration (the same one update.sh runs), so a key a
# newer release introduced (CX_PLATFORM_ADDRESSES, …) reaches .env on the
# operator path too instead of being added by hand. Decision: yes on deploy.sh
# as well — a deploy of a new tree IS an upgrade of that install, and without
# it the recreated services start with the compose fallback for every new key.
# Same guarantees as on update.sh: it takes the install lock, appends only
# missing keys (an existing value is never changed), backs .env up 0600 first
# (.env.pre-migrate-<stamp>, only when it changes anything), prints key names
# only, and is idempotent — a deploy with nothing new changes nothing. It edits
# deployment/docker/.env in place, so the COMPOSE_FILE overlay chain that .env
# carries is kept as it is. A failure aborts here, BEFORE the stack is touched.
if [ ! -f "$COMPOSE_DIR/.env" ]; then
  warn "no $COMPOSE_DIR/.env — not an installed stack; .env not migrated, service credential files not rendered"
else
  log "adding the .env keys this release introduced (install.py --migrate-env)…"
  if ! ( cd "$ROOT" && python3 scripts/install.py --migrate-env ); then
    die ".env migration failed (see the [fail ] line above) — running stack left UNTOUCHED."; exit 1
  fi
  log "rendering service credential files…"
  if ! ( cd "$ROOT" && python3 - <<'PY'
import importlib.util, pathlib
spec = importlib.util.spec_from_file_location("install", "scripts/install.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
root = pathlib.Path(".").resolve()
mod.migrate_env_credentials(root / "deployment" / "docker" / ".env")
mod.render_service_secrets(root)
mod.prepare_tls_custody(root)
PY
  ); then
    die "rendering service credential files failed — running stack left UNTOUCHED."; exit 1
  fi
fi

# 2c. snapshot the running containers and fingerprint every service's mounted
# config, BEFORE the stack is touched (custody_converge may recreate readers).
# A deploy that cannot tell stale config from fresh aborts here, untouched.
if ! mc_begin; then
  die "$MC_ERROR — running stack left UNTOUCHED."; exit 1
fi

# 3. build ONLY the named services, then recreate ONLY them. `up --build`
# also rebuilds (and, on a new image, recreates) every dependency with a build
# section — deploying the api rebuilt secrets-seal from scratch (a ~35-minute
# apt install on a cold build cache, past the deploy timeout) and could restart
# the TPM custody sidecar, whose unclean stops cause dictionary-attack lockouts.
# A build failure happens BEFORE the running stack is touched.
log "building ${SERVICES[*]}…"
if ! dc build "${SERVICES[@]}"; then
  die "image build failed — running stack left UNTOUCHED."; exit 1
fi
custody_converge
log "recreating ${SERVICES[*]} (dependencies left running)…"
dc up -d --no-deps "${SERVICES[@]}" || rollback "compose up failed"

# 3b. mounted-config reload — see the header. A plan failure is a failure like
# any other: the deploy cannot vouch for what the services are running.
if [ "$RELOAD_CHANGED_CONFIG" = 1 ]; then
  mc_plan || rollback "$MC_ERROR"
else
  mc_plan "${SERVICES[@]}" || rollback "$MC_ERROR"
fi
if [ "$MC_FIRST_RUN" = 1 ]; then
  log "mounted config: no fingerprint record yet ($MC_STATE_FILE) — recording a baseline; nothing is recreated for config on this first run"
fi
if [ -n "$MC_STATE_PROBLEM" ]; then
  warn "mounted config: the fingerprint record is unusable ($MC_STATE_PROBLEM) — treating EVERY service with mounted config as changed"
fi
if [ "${#MC_BASELINE[@]}" -gt 0 ]; then
  log "mounted config: first fingerprint recorded for ${MC_BASELINE[*]} (not recreated)"
fi
if [ "${#MC_RECREATED[@]}" -gt 0 ]; then
  log "mounted config changed for ${MC_RECREATED[*]} — already recreated by this deploy"
fi
if [ "${#MC_NOT_RUNNING[@]}" -gt 0 ]; then
  log "mounted config changed for ${MC_NOT_RUNNING[*]} — not running; its next start reads the new config"
fi
if [ "${#MC_RESTART[@]}" -gt 0 ]; then
  warn "recreating ${MC_RESTART[*]} — MOUNTED CONFIG CHANGED and compose left them running on the old one"
  if ! mc_recreate "${MC_RESTART[@]}"; then
    CFG_UNAPPLIED=("${MC_RESTART[@]}")
    rollback "mounted-config reload failed: $MC_ERROR"
  fi
  CFG_RELOADED=("${MC_RESTART[@]}")
  ok "recreated because their mounted config changed: ${CFG_RELOADED[*]}"
fi
STALE_MSG=""
if [ "${#MC_STALE[@]}" -gt 0 ]; then
  STALE_MSG="MOUNTED CONFIG CHANGED for running service(s) NOT in this deploy: ${MC_STALE[*]} — they are STILL RUNNING THE OLD CONFIG. Apply with: scripts/deploy.sh --reload-changed-config ${SERVICES[*]}   (or: scripts/deploy.sh ${MC_STALE[*]})"
  warn "$STALE_MSG"
fi

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

# 6. record the mounted-config fingerprints — ONLY now, after every gate passed.
if ! mc_commit; then
  die "the deploy is LIVE and healthy, but $MC_ERROR. The next deploy compares against the previous record and may recreate config-changed services again."
  exit 3
fi
log "$MC_COMMIT_MSG"

ok "deploy succeeded ✅  (${SERVICES[*]}${CFG_RELOADED[*]:+; recreated for mounted config: ${CFG_RELOADED[*]}})"
if [ -n "$STALE_MSG" ]; then
  warn "$STALE_MSG"
fi
