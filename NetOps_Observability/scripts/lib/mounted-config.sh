# shellcheck shell=bash
# shellcheck disable=SC2034 # the MC_* results are read by the sourcing script
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

# mounted-config.sh — sourced by scripts/deploy.sh and scripts/update.sh.
#
# Recreates running services whose bind-mounted CONFIG changed although compose
# did not recreate them (compose only looks at the image and the compose
# definition, never at the content of a mounted file). Which mounts count as
# config, and every decision, live in scripts/mounted_config.py — read its
# docstring. This file only runs the bounded docker calls and hands their output
# over.
#
# Contract — call in this order:
#   mc_init ROOT COMPOSE_DIR   once, before anything else
#   mc_begin                   BEFORE the stack is touched: snapshot the running
#                              containers and fingerprint the mounted config
#   mc_plan [service ...]      AFTER the normal recreate step. Fills MC_RESTART
#                              (to recreate), MC_STALE (changed but out of scope:
#                              warn), MC_RECREATED, MC_NOT_RUNNING, MC_BASELINE,
#                              MC_FIRST_RUN (1 = no state file yet) and
#                              MC_STATE_PROBLEM. Named services = the in-scope set;
#                              none = every service is in scope.
#   mc_recreate service ...    force-recreate (no deps, no build) and WAIT until
#                              running/healthy — a restart is not enough: a FILE
#                              bind mount replaced by a release (new inode) stays
#                              pinned to the old inode until the container is new
#   mc_commit                  ONLY after the run succeeded: record fingerprints
#   mc_cleanup                 from the caller's EXIT trap
#
# Nothing here exits or prints success: every function returns non-zero with the
# reason in MC_ERROR, and the CALLER decides fatality and wording (deploy.sh rolls
# back, update.sh fails loud). Compose runs from the compose directory with NO -f
# so the install's .env COMPOSE_FILE overlay chain applies (see deploy.sh dc()).
# The rendered compose config holds interpolated secrets: it is piped straight
# into the fingerprinter, never written to disk or printed — only error tails are.

mc_init() {
  MC_ROOT="$1"
  MC_COMPOSE_DIR="$2"
  MC_PY="$MC_ROOT/scripts/mounted_config.py"
  MC_STATE_FILE="${CORRELIX_DEPLOY_STATE_DIR:-$MC_ROOT/data/.deploy}/config-fingerprints.json"
  MC_CALL_TIMEOUT="${MC_CALL_TIMEOUT:-120}"
  MC_WAIT_TIMEOUT="${MC_WAIT_TIMEOUT:-300}"
  MC_WORK=""
  MC_ERROR=""
  MC_COMMIT_MSG=""
  MC_RESTART=(); MC_STALE=(); MC_RECREATED=(); MC_NOT_RUNNING=(); MC_BASELINE=()
  MC_FIRST_RUN=0
  MC_STATE_PROBLEM=""
}

mc_cleanup() {
  if [ -n "${MC_WORK:-}" ] && [ -d "$MC_WORK" ]; then
    rm -rf -- "$MC_WORK"
  fi
}

mc_compose() { ( cd "$MC_COMPOSE_DIR" && timeout "$MC_CALL_TIMEOUT" docker compose "$@" ); }

# _mc_tail FILE — the last lines of a captured stderr, on one line. tail's own
# stderr is dropped because its only failure here is a missing capture file (a
# stage whose redirection never happened); the caller always reports every
# stage's tail, so the stage that did fail is still named.
_mc_tail() { tail -n 3 "$1" 2>/dev/null | tr '\n' ' '; }

# mc_snapshot NAME — running containers per service → $MC_WORK/NAME.json
mc_snapshot() {
  local name="$1"
  if [ -z "${MC_WORK:-}" ] || [ ! -d "$MC_WORK" ]; then
    MC_ERROR="mc_begin did not run (no work directory)"
    return 1
  fi
  if ! mc_compose ps --format json 2>"$MC_WORK/ps.err" \
      | python3 "$MC_PY" snapshot >"$MC_WORK/$name.json" 2>"$MC_WORK/snap.err"; then
    MC_ERROR="cannot list the running containers: $(_mc_tail "$MC_WORK/ps.err") $(_mc_tail "$MC_WORK/snap.err")"
    return 1
  fi
}

mc_begin() {
  if [ ! -f "$MC_PY" ]; then
    MC_ERROR="$MC_PY is missing — the install tree is incomplete"
    return 1
  fi
  if ! MC_WORK="$(mktemp -d "${TMPDIR:-/tmp}/correlix-mounted-config.XXXXXX")"; then
    MC_WORK=""
    MC_ERROR="cannot create a temporary directory"
    return 1
  fi
  mc_snapshot before || return 1
  if ! mc_compose config --format json 2>"$MC_WORK/config.err" \
      | python3 "$MC_PY" fingerprint --root "$MC_ROOT" >"$MC_WORK/fp.json" 2>"$MC_WORK/fp.err"; then
    MC_ERROR="cannot fingerprint the mounted config: $(_mc_tail "$MC_WORK/config.err") $(_mc_tail "$MC_WORK/fp.err")"
    return 1
  fi
}

mc_plan() {
  local named=() verb rest out
  MC_RESTART=(); MC_STALE=(); MC_RECREATED=(); MC_NOT_RUNNING=(); MC_BASELINE=()
  MC_FIRST_RUN=0; MC_STATE_PROBLEM=""
  mc_snapshot after || return 1
  if [ "$#" -gt 0 ]; then
    named=(--named "$(IFS=,; printf '%s' "$*")")
  fi
  if ! out="$(python3 "$MC_PY" plan --state "$MC_STATE_FILE" --fingerprints "$MC_WORK/fp.json" \
      --before "$MC_WORK/before.json" --after "$MC_WORK/after.json" "${named[@]}" 2>"$MC_WORK/plan.err")"; then
    MC_ERROR="cannot plan the mounted-config reload: $(_mc_tail "$MC_WORK/plan.err")"
    return 1
  fi
  while IFS=' ' read -r verb rest; do
    case "$verb" in
      '') ;;
      first-run)        MC_FIRST_RUN=1 ;;
      state-unreadable) MC_STATE_PROBLEM="$rest" ;;
      restart)          MC_RESTART+=("$rest") ;;
      stale)            MC_STALE+=("$rest") ;;
      recreated)        MC_RECREATED+=("$rest") ;;
      not-running)      MC_NOT_RUNNING+=("$rest") ;;
      baseline)         MC_BASELINE+=("$rest") ;;
      *) MC_ERROR="mounted_config.py plan said something unknown: $verb $rest"; return 1 ;;
    esac
  done <<<"$out"
}

mc_recreate() {
  [ "$#" -gt 0 ] || return 0
  if ! ( cd "$MC_COMPOSE_DIR" && timeout "$((MC_WAIT_TIMEOUT + 120))" docker compose up -d \
      --force-recreate --no-deps --no-build --wait --wait-timeout "$MC_WAIT_TIMEOUT" "$@" ); then
    MC_ERROR="recreating $* did not reach running/healthy within ${MC_WAIT_TIMEOUT}s (see the compose output above; docker compose ps; docker compose logs <service>)"
    return 1
  fi
}

mc_commit() {
  local out
  mc_snapshot final || return 1
  if ! out="$(python3 "$MC_PY" save --state "$MC_STATE_FILE" --fingerprints "$MC_WORK/fp.json" \
      --before "$MC_WORK/before.json" --after "$MC_WORK/final.json" 2>"$MC_WORK/save.err")"; then
    MC_ERROR="cannot record the mounted-config fingerprints: $(_mc_tail "$MC_WORK/save.err")"
    return 1
  fi
  MC_COMMIT_MSG="$out"
}
