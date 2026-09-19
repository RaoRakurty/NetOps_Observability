#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

#
# install-correlix.sh — the one-command Correlix appliance installer (#97).
#
# A first-time customer runs exactly one thing and thinks about nothing else:
#
#     ./install-correlix.sh
#
# In an interactive terminal with no arguments this asks ONE question first —
# graphical installer or terminal? The graphical path serves the setup wizard
# on a management address you pick, over HTTPS, behind a one-time token
# (`gui`). The terminal path is the SETUP CONSOLE: numbered menu navigation
# over every operation — prepare host, install, health, logs, add-ons,
# stop/start, reset, uninstall (`console`). In a pipeline/script it installs
# non-interactively. Explicit subcommands below always work.
#
# Everything under the hood (Apache Kafka event bus, Valkey cache, PostgreSQL,
# OpenSearch, ClickHouse, VictoriaMetrics, the Correlix services) is embedded,
# configured with generated credentials, and started automatically. No broker
# choices, no topic names, no compose internals.
#
# Commands (no argument = install):
#     ./install-correlix.sh install [--ui-port N] [--config profile.json]
#     ./install-correlix.sh gui                 graphical installer (browser)
#     ./install-correlix.sh console             terminal setup console
#     ./install-correlix.sh status
#     ./install-correlix.sh logs [service]
#     ./install-correlix.sh stop
#     ./install-correlix.sh start
#     ./install-correlix.sh uninstall [--purge]
#         Removes Correlix. Host preparation (prepare-host.sh: kernel
#         settings, Docker daemon configuration, firewall rules, the service
#         user) is kept by design — uninstall does not undo host hardening
#         (owner decision 2026-09-15). --purge also removes the data, the
#         configuration (.env and every backup of it), install logs and the
#         bundle's images.
#     ./install-correlix.sh upgrade [--from DIR] [--backup-dir DIR] [--backup-file FILE]
#         Run from a NEW bundle folder: verified backup of the current
#         install, settings and data carried over, install, stability check,
#         automatic rollback on failure. Exit 4 = failed and rolled back,
#         5 = rollback failed too (the backup path and restore steps are shown).
#     ./install-correlix.sh cleanup-old-images [--confirm]
#         After a successful upgrade: list (with --confirm: remove) the
#         previous version's images that nothing uses any more.
#     ./install-correlix.sh reset-demo-data
#     ./install-correlix.sh enable  <add-on>    log-search-ui | self-monitoring | sso
#     ./install-correlix.sh disable <add-on>
#     ./install-correlix.sh support-bundle [--out DIR] [--since 24h] [--no-logs]
#         Collect a REDACTED diagnostic bundle (compose state, container logs,
#         health, store/bus summaries) as one .tar.zst to send to support.
#         Secrets are stripped; read its MANIFEST before sending.
#     ./install-correlix.sh doctor [--json]
#         Read-only health report: host speed, installer lock, setup wizard,
#         every container's state and log verdict, disk against the OpenSearch
#         watermarks, missing .env settings (names only). Changes nothing.
#         Exit 0 healthy, 1 problems found, 2 could not assess.
#
# Advanced (documented in ADVANCED.md, hidden from the quickstart):
#     --external-kafka --broker-urls host1:9092[,host2:9092]
#         Use a customer-provided Kafka-compatible broker instead of the
#         embedded one (enterprise deployments).
#     --lab
#         Internal/developer mode: source-checkout install with the full dev
#         profile set. Not part of customer distribution and intentionally
#         undocumented in customer docs.
#     install --config profile.json
#         Unattended install from an exported installation profile (Profile
#         JSON v1, produced by the graphical installer). Expands to the
#         existing flags, fully non-interactive; unknown keys are a hard
#         error. Add --print-flags to print the expanded install.py argument
#         list and exit (contract/debug aid).
#
# The script runs in two contexts and detects which:
#   * BUNDLE ROOT (offline customer install): next to correlix-images-*.tar.zst
#     (possibly split into .partNN), correlix-source-*.tar.gz, SHA256SUMS.
#   * SOURCE CHECKOUT (developer): placed in scripts/ of the repo.

set -euo pipefail
export PATH="/usr/local/bin:/usr/bin:/bin:${PATH:-}"

# ---------- output helpers (customer-facing: calm, no stack traces) ----------
BOLD=$'\033[1m'; GREEN=$'\033[32m'; RED=$'\033[31m'; YELLOW=$'\033[33m'; DIM=$'\033[2m'; RST=$'\033[0m'
[ -t 1 ] || BOLD='' GREEN='' RED='' YELLOW='' DIM='' RST=''
say()  { printf '%s\n' "$*"; }
ok()   { printf '%s✔%s %s\n' "$GREEN" "$RST" "$*"; }
warn() { printf '%s!%s %s\n' "$YELLOW" "$RST" "$*"; }
die()  { printf '\n%sERROR:%s %s\n' "$RED$BOLD" "$RST" "$1"; [ -n "${2:-}" ] && printf '%s\n' "$2"; exit 1; }

# ---------- locate ourselves -------------------------------------------------
# Resolve symlinks so the PATH alias (/usr/local/bin/install-correlix, made
# by prepare-host.sh) still finds the real bundle directory.
HERE="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
if [ -f "$HERE/../deployment/docker/docker-compose.yml" ]; then
  MODE="source"; ROOT="$(cd "$HERE/.." && pwd)"; BUNDLE_DIR=""
elif compgen -G "$HERE/correlix-source-*.tar.gz" >/dev/null; then
  MODE="bundle"; BUNDLE_DIR="$HERE"; ROOT="$HERE/NetOps_Observability"
elif [ -f "$HERE/NetOps_Observability/deployment/docker/docker-compose.yml" ]; then
  MODE="bundle"; BUNDLE_DIR="$HERE"; ROOT="$HERE/NetOps_Observability"
else
  die "Cannot find a Correlix bundle or source tree next to this script." \
      "Run it from the extracted bundle directory (the one containing SHA256SUMS)."
fi
COMPOSE_DIR="$ROOT/deployment/docker"
ENV_FILE="$COMPOSE_DIR/.env"

compose() { (cd "$COMPOSE_DIR" && docker compose "$@"); }
# Read-only compose queries, bounded (§16.3): a wedged daemon must not hang the
# health gate. Never used for up/down/stop, whose legitimate duration is long.
# How slow is this host? install.py's host profile (data/.host-profile.json)
# carries budget_factor 1 (fast/normal), 2 (slow) or 3 (very slow). Every
# bounded wait below is multiplied by it: on the 2026-09-16 .123 install the
# stack was healthy and the gate still failed, because fixed 60 s / 7 min
# budgets are not enough on a disk whose p99 write is ~2.8 s.
host_budget_factor() {
  local f="" prof="$ROOT/data/.host-profile.json"
  [ -f "$prof" ] || { printf '1'; return 0; }
  f=$(python3 - "$prof" <<'PYEOF' 2>/dev/null
import json, sys
try:
    v = float(json.load(open(sys.argv[1])).get("budget_factor", 1))
except Exception:
    v = 1.0
print(int(max(1, min(4, round(v)))))
PYEOF
)
  case "$f" in ''|*[!0-9]*) f=1 ;; esac
  printf '%s' "$f"
}
scaled_s() { printf '%s' "$(( $1 * $(host_budget_factor) ))"; }

# Read-only compose queries, bounded (§16.3): a wedged daemon must not hang the
# health gate. Never used for up/down/stop, whose legitimate duration is long.
# The failure REASON is kept in COMPOSE_Q_ERR — swallowing it (§16.1) is what
# made the .123 gate say only "could not list this install's containers".
compose_q_errfile() {
  local f="${TMPDIR:-/tmp}/correlix-compose-err.$$"
  : > "$f" 2>/dev/null || { printf '%s' ""; return 0; }
  printf '%s' "$f"
}
compose_q_err() { cat "${TMPDIR:-/tmp}/correlix-compose-err.$$" 2>/dev/null; }
compose_q() {
  local rc f="${TMPDIR:-/tmp}/correlix-compose-err.$$"
  (cd "$COMPOSE_DIR" && timeout "$(scaled_s 60)" docker compose "$@") 2>"${f:-/dev/null}"; rc=$?
  if [ "$rc" -ne 0 ] && [ -n "$f" ]; then
    # Keep the last two lines; a timeout has no output of its own to explain it.
    printf '%s' "$(tail -2 "$f" 2>/dev/null)" > "$f"
    [ "$rc" -eq 124 ] && printf 'timed out after %ss: docker compose %s' "$(scaled_s 60)" "$*" > "$f"
  fi
  return "$rc"
}
env_get() { sed -n "s/^$1=//p" "$ENV_FILE" 2>/dev/null | head -1; }
utc_now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# ---------- process exit: lock records + log flush ---------------------------
# One EXIT handler per process (the setup console runs each command in its own
# subshell, which gets its own). It clears the lock records this process wrote,
# hands stdout back to the terminal so the log filter sees EOF, waits (bounded)
# for the filter to drain, and only THEN prints anything that must reach the
# terminal but never the log (the initial admin password, FMEA row 6).
LOCK_FILES_HELD=""
LOG_FILTER_PID=""
TERMINAL_EPILOGUE=""
on_exit() {
  local rc=$? f pid state i
  # Cleanup must run every step and then exit with the status the script was
  # already leaving with — errexit inside the trap would replace that status
  # with the first failed probe below (e.g. the filter exiting between the
  # /proc test and the read).
  set +e
  for f in $LOCK_FILES_HELD; do
    # Only a record this process wrote is cleared; a leftover record is what
    # lets the next run say "the previous install did not finish".
    if [ "$(sed -n 's/^pid=//p' "$f" 2>/dev/null | head -1)" = "$BASHPID" ]; then
      : > "$f"
    fi
  done
  # compose_q's stderr scratch file is this process's own (pid-suffixed), so it
  # goes with the run rather than accumulating in /tmp.
  rm -f "${TMPDIR:-/tmp}/correlix-compose-err.$$" 2>/dev/null
  if [ -n "$LOG_FILTER_PID" ]; then
    exec 1>&5 2>&6
    pid="$LOG_FILTER_PID"
    for i in $(seq 1 100); do
      [ -r "/proc/$pid/stat" ] || break
      # Gone between the test and the read = exited.
      state=$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null) || break
      [ "$state" = "Z" ] && break
      [ "$i" -eq 100 ] && printf 'note: the install log writer is still flushing (pid %s)\n' "$pid" >&2
      sleep 0.1
    done
    # Reaps the exited filter. Its status is not ours to report: a log-write
    # failure was already announced on the terminal by the filter itself.
    wait "$pid" 2>/dev/null || true
  fi
  if [ -n "$TERMINAL_EPILOGUE" ]; then
    printf '%s\n' "$TERMINAL_EPILOGUE"
  fi
  exit "$rc"
}

# ---------- single-writer lock (FMEA row 12, design §4.2) --------------------
# Every state-changing command holds `flock -n` on deployment/docker/.install.lock
# for its whole run: the wizard and a terminal, two wizard tabs, or a cron
# update.sh must never interleave `.env` surgery and compose operations.
#
# CONTRACT with install.py (owned there): this script opens the lock on fd 9,
# takes `flock -n 9`, and exports CORRELIX_INSTALL_LOCK_FD=9. install.py
# re-flocks the INHERITED fd (same open file description, so it succeeds)
# instead of opening the file again. Do not change the fd number.
#
# The lock itself dies with its holder (flock semantics). The pid/command/
# start-time record written into the file is diagnostics: a refusal quotes it,
# and a record whose pid is gone means the previous run ended without cleaning
# up, which is said out loud before taking over.
INSTALL_LOCK_FILE="$COMPOSE_DIR/.install.lock"
LOCK_REFUSED_RC=3
INSTALL_LOCK_HELD=0

lock_field() { sed -n "s/^$2=//p" "$1" 2>/dev/null | head -1; }

# take_lock FD FILE COMMAND — returns with the lock held, or exits 3.
take_lock() {
  local fd="$1" file="$2" what="$3" old_umask old_pid old_cmd old_started
  command -v flock >/dev/null 2>&1 || die "flock (util-linux) is missing — cannot guarantee a single installer run." \
    "Install util-linux, then re-run."
  old_umask=$(umask)
  umask 077
  case "$fd" in
    # 7: the PREVIOUS install's lock, held by `upgrade` for its whole run.
    7) exec 7<>"$file" ;;
    8) exec 8<>"$file" ;;
    9) exec 9<>"$file" ;;
    *) umask "$old_umask"; die "internal error: unsupported lock descriptor $fd" ;;
  esac
  umask "$old_umask"
  old_pid=$(lock_field "$file" pid)
  old_cmd=$(lock_field "$file" command)
  old_started=$(lock_field "$file" started_utc)
  if ! flock -n "$fd"; then
    local who="pid ${old_pid:-unknown}, command '${old_cmd:-unknown}', started ${old_started:-unknown}"
    local why="It is still running."
    if [ -n "$old_pid" ] && [ ! -d "/proc/$old_pid" ]; then
      why="That process has exited, but a program it started still holds the lock (find it with: fuser -v '$file')."
    fi
    printf '\n%sERROR:%s another Correlix installer operation is in progress on this host (%s).\n' "$RED$BOLD" "$RST" "$who"
    printf '%s\n' "$why" \
      "Running two at once would corrupt the configuration. Wait for it to finish, then re-run:" \
      "  ./install-correlix.sh $what" \
      "Lock file: $file"
    cx_result fail
    exit "$LOCK_REFUSED_RC"
  fi
  if [ -n "$old_pid" ] && [ "$old_pid" != "$BASHPID" ]; then
    if [ ! -d "/proc/$old_pid" ]; then
      warn "stale lock record: the previous '${old_cmd:-?}' (pid $old_pid, started ${old_started:-?}) is no longer running and did not finish cleanly — taking over."
    else
      warn "lock record named pid $old_pid ('${old_cmd:-?}'), which no longer holds the lock — taking over."
    fi
  fi
  printf 'pid=%s\ncommand=%s\nstarted_utc=%s\n' "$BASHPID" "$what" "$(utc_now)" > "$file"
  LOCK_FILES_HELD="$LOCK_FILES_HELD $file"
  trap on_exit EXIT
}

# The install lock. Needs deployment/docker/, which a first-run bundle does not
# have until verify_bundle extracted it — cmd_install calls this again after.
acquire_install_lock() {
  [ "$INSTALL_LOCK_HELD" = 1 ] && return 0
  [ -d "$COMPOSE_DIR" ] || return 0
  take_lock 9 "$INSTALL_LOCK_FILE" "$1"
  INSTALL_LOCK_HELD=1
  export CORRELIX_INSTALL_LOCK_FD=9
}

# Bundle installs also serialise the archive join and source extraction, which
# happen before deployment/docker/ exists. Always taken BEFORE the install lock
# (one order, so two installers can only ever refuse, never deadlock).
acquire_bundle_lock() {
  [ "$MODE" = "bundle" ] || return 0
  take_lock 8 "$BUNDLE_DIR/.install-bundle.lock" "$1"
}

# ---------- GUI progress markers (design gui-installer-2026-08.md §6, P0) ----
# Same `@CX@ {json}` stdout line format install.py emits; activated by
# CORRELIX_PROGRESS_JSON=1 (exported by the GUI — install.py inherits it and
# emits its own stages). This script owns the stages install.py cannot see:
# preflight, verify-health, verify-login — plus the terminal result line.
# Callers pass only fixed, quote-free constant strings, so no JSON escaping
# machinery is needed here; never pass user-controlled text.
cx_stage() { # id title status [message]
  [ "${CORRELIX_PROGRESS_JSON:-0}" = "1" ] || return 0
  if [ -n "${4:-}" ]; then
    printf '@CX@ {"kind":"stage","id":"%s","title":"%s","status":"%s","message":"%s"}\n' \
      "$1" "$2" "$3" "$4"
  else
    printf '@CX@ {"kind":"stage","id":"%s","title":"%s","status":"%s"}\n' "$1" "$2" "$3"
  fi
}
cx_result() { # "ok" url admin_user | "fail"
  [ "${CORRELIX_PROGRESS_JSON:-0}" = "1" ] || return 0
  if [ "$1" = "ok" ]; then
    printf '@CX@ {"kind":"result","status":"ok","url":"%s","admin_user":"%s"}\n' "$2" "$3"
  else
    printf '@CX@ {"kind":"result","status":"fail"}\n'
  fi
}

# ---------- args ---------------------------------------------------------
CMD="install"
UI_PORT=8000
EXTERNAL_KAFKA=0
BROKER_URLS_ARG="${BROKER_URLS:-}"
LAB=0
PURGE=0
LOG_SVC=""
CONFIG_FILE=""
PRINT_FLAGS=0
# upgrade / cleanup-old-images options (rejected for every other subcommand).
UPGRADE_FROM=""
UPGRADE_BACKUP_DIR=""
UPGRADE_BACKUP_FILE=""
CONFIRM=0
# support-bundle passthrough (rejected for every other subcommand).
SB_ARGS=()
DOCTOR_JSON=0
if [ $# -gt 0 ]; then
  case "$1" in
    install|status|logs|stop|start|uninstall|reset-demo-data|enable|disable|menu|console|gui|support-bundle|upgrade|cleanup-old-images|doctor) CMD="$1"; shift ;;
    -*) : ;;  # bare options → install
    *) die "Unknown command: $1" "Commands: install upgrade cleanup-old-images status logs stop start uninstall reset-demo-data enable disable support-bundle doctor gui console menu" ;;
  esac
elif [ -t 0 ] && [ -t 1 ]; then
  # No arguments in an interactive terminal → the setup console (menu
  # navigation). Pipelines/automation with no args still default to install.
  CMD="menu"
fi
# enable/disable take the add-on name as their positional argument.
ADDON_ARG=""
if { [ "$CMD" = "enable" ] || [ "$CMD" = "disable" ]; } && [ $# -gt 0 ] && [ "${1#-}" = "$1" ]; then
  ADDON_ARG="$1"; shift
fi
while [ $# -gt 0 ]; do
  case "$1" in
    --ui-port)        UI_PORT="${2:?--ui-port needs a number}"; shift 2 ;;
    --external-kafka) EXTERNAL_KAFKA=1; shift ;;
    --broker-urls)    BROKER_URLS_ARG="${2:?--broker-urls needs host:port[,host:port]}"; shift 2 ;;
    --config)         CONFIG_FILE="${2:?--config needs a profile.json path}"; shift 2 ;;
    --print-flags)    PRINT_FLAGS=1; shift ;;
    --out|--since)    [ "$CMD" = "support-bundle" ] || die "Unknown option: $1" "$1 is only valid for: ./install-correlix.sh support-bundle"
                      SB_ARGS+=("$1" "${2:?$1 needs a value}"); shift 2 ;;
    --no-logs)        [ "$CMD" = "support-bundle" ] || die "Unknown option: $1" "--no-logs is only valid for: ./install-correlix.sh support-bundle"
                      SB_ARGS+=("$1"); shift ;;
    --json)           [ "$CMD" = "doctor" ] || die "Unknown option: $1" "--json is only valid for: ./install-correlix.sh doctor"
                      DOCTOR_JSON=1; shift ;;
    --lab)            LAB=1; shift ;;
    --purge)          PURGE=1; shift ;;
    -h|--help)        sed -n '5,/^# Advanced (documented/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    --from)           [ "$CMD" = "upgrade" ] || die "Unknown option: $1" "--from is only valid for: ./install-correlix.sh upgrade"
                      UPGRADE_FROM="${2:?--from needs the previous install folder}"; shift 2 ;;
    --backup-dir)     [ "$CMD" = "upgrade" ] || die "Unknown option: $1" "--backup-dir is only valid for: ./install-correlix.sh upgrade"
                      UPGRADE_BACKUP_DIR="${2:?--backup-dir needs a directory}"; shift 2 ;;
    --backup-file)    [ "$CMD" = "upgrade" ] || die "Unknown option: $1" "--backup-file is only valid for: ./install-correlix.sh upgrade"
                      UPGRADE_BACKUP_FILE="${2:?--backup-file needs a backup.sh artifact}"; shift 2 ;;
    --confirm)        [ "$CMD" = "cleanup-old-images" ] || die "Unknown option: $1" "--confirm is only valid for: ./install-correlix.sh cleanup-old-images"
                      CONFIRM=1; shift ;;
    *) if [ "$CMD" = "logs" ] && [ -z "$LOG_SVC" ]; then LOG_SVC="$1"; shift
       else die "Unknown option: $1" "See ./install-correlix.sh --help"; fi ;;
  esac
done

# ---------- preflight checks (install only) ----------------------------------
port_in_use() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && { exec 3>&-; return 0; } || return 1; }

# Device-facing host ports published by docker-compose.yml, as
# "port/proto[:ENV_VAR]" — the env var (where one exists) is what moves the
# port, and is quoted back to the customer in the failure. Keep in sync with
# the `ports:` blocks of syslog-ng, goflow2 and api; pinned by
# tests/test_ingest_contract.py::test_installer_checks_every_published_port.
STACK_INGEST_PORTS="514/tcp 514/udp 5514/tcp:SYSLOG_PORT 5514/udp:SYSLOG_PORT \
2055/udp:NETFLOW_PORT 4739/udp:IPFIX_PORT 6343/udp:SFLOW_PORT \
162/udp:SNMP_TRAP_PORT 11019/tcp:BMP_PORT"

# Report each STACK_INGEST_PORTS entry already bound on this host, and stop the
# install naming them. UDP cannot be probed by connecting, so this reads the
# kernel's listening table via `ss` (iproute2). No `ss` -> say so and continue
# rather than pretend the ports were checked (§16.1: never a silent skip).
check_ingest_ports() {
  if ! command -v ss >/dev/null 2>&1; then
    warn "'ss' (iproute2) is not installed — cannot verify the device-facing ports are free."
    warn "If a collector fails to start, check for another service on 514/5514, 2055/4739/6343, 162 or 11019."
    return 0
  fi
  local listening busy="" entry port proto var move
  # -H no header, -l listening, -n numeric, -t tcp, -u udp. Fold every local
  # address down to "proto:port" so 0.0.0.0:514, [::]:514 and 127.0.0.1:514
  # all match. A non-zero ss here is a real failure, not noise.
  if ! listening=$(ss -Hlntu 2>&1); then
    warn "could not read the listening-socket table (ss: $listening) — skipping the port check."
    return 0
  fi
  listening=$(printf '%s\n' "$listening" \
    | awk '{ n=$1; a=$5; sub(/.*:/, "", a); if (a ~ /^[0-9]+$/) print n ":" a }' \
    | sort -u)
  for entry in $STACK_INGEST_PORTS; do
    var="${entry#*:}"; [ "$var" = "$entry" ] && var=""
    entry="${entry%%:*}"
    port="${entry%%/*}"; proto="${entry##*/}"
    if printf '%s\n' "$listening" | grep -qx "$proto:$port"; then
      # `move` is built with an `if`, not `$([ -n "$var" ] && printf ...)`: an
      # assignment takes the status of its LAST command substitution, so the
      # entries with no mover variable (514/tcp, 514/udp) made this assignment
      # return 1 and `set -e` killed the installer here — before `die` printed
      # the one diagnostic this check exists to give. It only ever survived
      # because the sole call site nests it inside `if ! ( preflight )`, which
      # suspends errexit; the report must not depend on that.
      move=""
      if [ -n "$var" ]; then
        move=" (move it with $var=<port> in the environment)"
      fi
      busy="$busy
  $port/$proto — $(port_purpose "$port")$move"
    fi
  done
  [ -n "$busy" ] || return 0
  die "Another service already listens on port(s) Correlix must publish:$busy" \
    "Docker would fail to bind them part-way through the install. Stop the
service holding each port (find it with 'sudo ss -lntup'), or set the
environment variable listed above to a free port, then re-run the
installer — it is idempotent."
}

# Plain-language purpose per published port, so the failure says what the port
# is FOR rather than making the customer look it up.
port_purpose() {
  case "$1" in
    514|5514)   echo "syslog from your devices" ;;
    2055)       echo "NetFlow" ;;
    4739)       echo "IPFIX" ;;
    6343)       echo "sFlow" ;;
    162)        echo "SNMP traps" ;;
    11019)      echo "BGP Monitoring Protocol (BMP)" ;;
    *)          echo "device telemetry" ;;
  esac
}

# ---------- host checks (FMEA 2026-09-15 §3.12; rows 3, 10, 15) -------------
# Each check prints a pass (ok) or a warning (warn, the install continues), or
# stops the install with a named remedy (die) — die ONLY for a genuine blocker.
# A check that cannot measure says so by name and continues (§16.1).

# Compose added the `!override` merge tag, which compose.tls.yml uses, in
# 2.24.4 (Docker docs, "Merge and override" reference). An older plugin
# rejects the TLS layout late, part-way through the install.
COMPOSE_MIN_VERSION="2.24.4"
# Unpacked image size per byte of .tar.zst when MANIFEST does not record it:
# measured on the 2026-09-15 lab install (containerd image store) — 1.9 GB of
# archives became 11.8 GB of images, 6.2x. An ESTIMATE, and printed as one.
IMAGE_UNPACK_RATIO_X10=62
DISK_PROJECTION_WARN_PCT=80   # keeps a shared data/ under OpenSearch's 85 % low watermark
INODE_FAIL_PCT=5
INODE_WARN_PCT=10

# version_ge A B — true when dotted version A >= B.
version_ge() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" = "$2" ]; }

# The closest directory that exists: what a not-yet-created path will live on.
nearest_existing_dir() {
  local p="$1"
  while [ -n "$p" ] && [ "$p" != "/" ] && [ ! -d "$p" ]; do p=$(dirname -- "$p"); done
  printf '%s' "${p:-/}"
}

gib() { awk -v b="$1" 'BEGIN { printf "%.1f GB", b / 1073741824 }'; }

# Rootless Docker cannot publish the privileged ports the stack needs (443,
# 514, 162); it used to surface as a bind failure mid-install (H9).
check_rootless_docker() {
  local out
  if ! out=$(timeout 15 docker info --format '{{json .SecurityOptions}}' 2>&1); then
    warn "could not read Docker's security options ($(printf '%s' "$out" | tail -1)) — rootless mode not checked."
    return 0
  fi
  case "$out" in
    *name=rootless*)
      die "Docker is running in rootless mode." \
        "Correlix publishes privileged ports (443, 514, 162) that rootless Docker cannot bind.
Use the system Docker service instead (sudo ./prepare-host.sh installs and enables it),
make sure DOCKER_HOST does not point at a rootless socket, then re-run the installer." ;;
  esac
  ok "docker: rootful daemon"
}

check_compose_version() {
  local out v
  if ! out=$(timeout 15 docker compose version --short 2>&1); then
    warn "could not read the Docker Compose version ($(printf '%s' "$out" | tail -1)) — minimum $COMPOSE_MIN_VERSION not checked."
    return 0
  fi
  v=$(printf '%s\n' "$out" | head -1 | tr -d '[:space:]')
  v=${v#v}
  case "$v" in
    [0-9]*.[0-9]*) ;;
    *) warn "could not read the Docker Compose version ('$v') — minimum $COMPOSE_MIN_VERSION not checked."
       return 0 ;;
  esac
  if ! version_ge "${v%%[-+]*}" "$COMPOSE_MIN_VERSION"; then
    die "Docker Compose $v is too old; Correlix needs $COMPOSE_MIN_VERSION or newer." \
      "The TLS layout uses the '!override' merge tag, added in Compose $COMPOSE_MIN_VERSION.
Upgrade the plugin (Debian/Ubuntu: sudo apt-get install --only-upgrade docker-compose-plugin),
then re-run the installer."
  fi
  ok "docker compose $v"
}

# check_inode_headroom LABEL PATH — a filesystem out of inodes fails every
# write with "no space left on device" while df -h still shows free space (H7).
check_inode_headroom() {
  local label="$1" path out total free pct
  path=$(nearest_existing_dir "$2")
  if ! out=$(timeout 15 df -Pi -- "$path" 2>&1); then
    warn "could not read inode usage of $path ($(printf '%s' "$out" | tail -1)) — inode headroom not checked."
    return 0
  fi
  read -r _ total _ free _ <<< "$(printf '%s\n' "$out" | tail -1)"
  case "$total$free" in
    ''|*[!0-9]*)
      warn "unexpected inode report for $path — inode headroom not checked."
      return 0 ;;
  esac
  if [ "$total" -eq 0 ]; then
    ok "$label: no fixed inode limit ($path)"
    return 0
  fi
  pct=$(( free * 100 / total ))
  if [ "$pct" -lt "$INODE_FAIL_PCT" ]; then
    die "Only $pct % of inodes (file slots) are free on the filesystem holding $path ($label)." \
      "Correlix's stores create many small files. Find what uses them:
  sudo du --inodes -x -d 3 $path | sort -n | tail
remove what is not needed, then re-run the installer."
  elif [ "$pct" -lt "$INODE_WARN_PCT" ]; then
    warn "$label: only $pct % of inodes free on $path — the stores create many files; keep an eye on it."
  else
    ok "$label: $pct % inodes free"
  fi
}

# check_image_disk_projection DOCKER_ROOT — the image bundle unpacks to several
# times its compressed size in Docker's store (FMEA row 10). The unpacked size
# is MANIFEST's `images_unpacked_bytes:` when the bundle records it, otherwise
# the labelled estimate above. Fails only when even the compressed archives
# cannot fit (images never unpack smaller); anything built on the estimate is
# a warning.
check_image_disk_projection() {
  if [ "$MODE" != "bundle" ] || [ -z "$BUNDLE_DIR" ]; then
    ok "disk projection: source install — images are built on this host, there is no image bundle to size"
    return 0
  fi
  local droot zst=0 f sz unpacked="" label out size used avail after note=""
  droot=$(nearest_existing_dir "$1")
  for f in "$BUNDLE_DIR"/correlix-images-*.tar.zst "$BUNDLE_DIR"/correlix-images-*.tar.zst.part[0-9][0-9] \
           "$BUNDLE_DIR"/correlix-addon-*.tar.zst; do
    [ -f "$f" ] || continue
    # A joined archive and its .partNN pieces are the same bytes: count one.
    case "$f" in
      *.part[0-9][0-9]) if [ -f "${f%.part[0-9][0-9]}" ]; then continue; fi ;;
    esac
    if ! sz=$(stat -c %s -- "$f" 2>&1); then
      warn "could not read the size of ${f##*/} ($sz) — disk projection skipped."
      return 0
    fi
    zst=$(( zst + sz ))
  done
  if [ -f "$BUNDLE_DIR/MANIFEST" ]; then
    unpacked=$(sed -n 's/^images_unpacked_bytes:[[:space:]]*\([0-9][0-9]*\)[[:space:]]*$/\1/p' "$BUNDLE_DIR/MANIFEST" | head -1)
  fi
  if [ -n "$unpacked" ]; then
    label="$(gib "$unpacked") unpacked (from MANIFEST)"
  elif [ "$zst" -gt 0 ]; then
    unpacked=$(( zst * IMAGE_UNPACK_RATIO_X10 / 10 ))
    label="about $(gib "$unpacked") unpacked (ESTIMATE: 6.2x the $(gib "$zst") of image archives, the ratio measured on a 2026-09-15 install)"
  else
    warn "no image archives found next to the installer — disk projection skipped."
    return 0
  fi
  if ! out=$(timeout 15 df -PB1 -- "$droot" 2>&1); then
    warn "could not read the free space of $droot ($(printf '%s' "$out" | tail -1)) — disk projection skipped."
    return 0
  fi
  read -r _ size used avail _ <<< "$(printf '%s\n' "$out" | tail -1)"
  case "$size$used$avail" in
    ''|*[!0-9]*)
      warn "unexpected free-space report for $droot — disk projection skipped."
      return 0 ;;
  esac
  if [ -f "$ENV_FILE" ]; then
    note=" (Images from an earlier install may already be loaded; this counts them again.)"
  fi
  if [ "$zst" -gt 0 ] && [ "$avail" -lt "$zst" ]; then
    die "The image bundle cannot fit: Docker's filesystem ($droot) has $(gib "$avail") free, and the compressed images alone are $(gib "$zst")." \
      "Images unpack to $label. Free space there (see 'df -h $droot' and 'docker system df'), then re-run the installer."
  fi
  if [ "$size" -le 0 ]; then
    warn "Docker's filesystem ($droot) reports no size — disk projection skipped."
    return 0
  fi
  after=$(( (used + unpacked) * 100 / size ))
  if [ "$unpacked" -gt "$avail" ]; then
    warn "disk projection: the images may not fit — they need $label, and Docker's filesystem ($droot) has $(gib "$avail") free.$note"
  elif [ "$after" -gt "$DISK_PROJECTION_WARN_PCT" ]; then
    warn "disk projection: after loading the images Docker's filesystem ($droot) would be about $after % full ($label); OpenSearch stops placing data at 85-90 % when data/ shares it.$note"
  else
    ok "disk projection: images need $label; Docker's filesystem would be about $after % full"
  fi
}

# run_host_profile [DOCKER_ROOT] — measure how fast this host is (FMEA row 3,
# design §4.3) and save data/.host-profile.json for the installer's time
# budgets. Bounded (the probe caps itself at 5 s per filesystem, 30 s overall)
# and never fatal: a host that cannot be measured installs with the standard
# budgets, and says so. A very slow host is warned about, never refused (owner
# decision, FMEA §7 Q1). Without DOCKER_ROOT the profiler asks Docker itself.
run_host_profile() {
  local profiler="$ROOT/scripts/host_profile.py" out rc=0 first klass verdict saved
  local dargs=()
  if [ ! -f "$profiler" ]; then
    say "host speed: measured after the bundle is unpacked"
    return 0
  fi
  if [ -n "${1:-}" ]; then
    dargs=(--docker-root "$1")
  fi
  out=$(timeout 30 python3 -B "$profiler" probe --data-dir "$ROOT/data" ${dargs[@]+"${dargs[@]}"} \
          --write "$ROOT/data/.host-profile.json" 2>&1) || rc=$?
  first=$(printf '%s\n' "$out" | head -1)
  klass=${first%%$'\t'*}
  verdict=${first#*$'\t'}
  verdict=${verdict#*$'\t'}
  case "$rc" in
    0|3)
      case "$klass" in
        fast|normal) ok "host speed: $verdict" ;;
        slow)        warn "host speed: $verdict" ;;
        very-slow)   warn "$verdict" ;;
        *)           warn "host speed: unexpected answer from the profiler: $first" ;;
      esac
      if [ "$rc" = 3 ]; then
        # grep exits 1 when the profiler printed no reason line; the fallback
        # text then stands in for it.
        saved=$(printf '%s\n' "$out" | grep -m1 '^not saved:') || saved="not saved"
        warn "host speed profile $saved — the installer uses its standard time budgets."
      fi ;;
    2)   warn "host speed could not be measured: $verdict The install continues with standard time budgets." ;;
    124) warn "host speed measurement did not finish within 30 s (itself a sign of very slow storage) — the install continues with standard time budgets." ;;
    *)   warn "host speed measurement failed (exit $rc): $(printf '%s\n' "$out" | tail -1) — the install continues with standard time budgets." ;;
  esac
  printf '%s\n' "$out" | sed -n 's/^note: /    note: /p'
}

preflight() {
  say "${BOLD}Checking this host...${RST}"

  # --- platform gates (hard stops) -------------------------------------
  [ "$(uname -m)" = "x86_64" ] || die "Unsupported CPU architecture: $(uname -m). Correlix requires x86_64."
  if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    case "${ID:-}" in
      ubuntu) dpkg --compare-versions "${VERSION_ID:-0}" ge 22.04 2>/dev/null \
        || die "Ubuntu ${VERSION_ID:-?} is too old. Correlix requires Ubuntu 22.04 LTS or newer." ;;
      debian) [ "${VERSION_ID%%.*}" -ge 12 ] 2>/dev/null \
        || die "Debian ${VERSION_ID:-?} is too old. Correlix requires Debian 12 or newer." ;;
      *) [ "${CORRELIX_SKIP_OS_CHECK:-0}" = 1 ] \
        || die "Unsupported OS: ${PRETTY_NAME:-unknown}. Supported: Ubuntu 22.04+/Debian 12." \
          "Other Linux distributions may work but are not validated; see ADVANCED.md." ;;
    esac
  fi
  local cpus; cpus=$(nproc 2>/dev/null || echo 0)
  if [ "$cpus" -lt 2 ]; then die "This host has $cpus vCPU; Correlix needs at least 2 (4 recommended)."
  elif [ "$cpus" -lt 4 ]; then warn "$cpus vCPU — fine for evaluation; 4 vCPU recommended."
  else ok "cpu: $cpus vCPU"; fi
  command -v python3 >/dev/null || die "python3 is missing." \
    "Prepare the host first:  sudo ./prepare-host.sh"

  # --- host readiness audit (hard gate) --------------------------------
  # prepare-host.sh --check is the single source of truth for prerequisites
  # (Docker best-practice config, kernel settings, packages, time sync).
  # If it reports anything unfixed, the install STOPS — no partial installs
  # on an unready host.
  local prep=""
  if [ -x "$HERE/prepare-host.sh" ]; then prep="$HERE/prepare-host.sh"
  elif [ -x "$ROOT/scripts/prepare-host.sh" ]; then prep="$ROOT/scripts/prepare-host.sh"; fi
  if [ -n "$prep" ]; then
    if ! bash "$prep" --check; then
      die "This host is not ready for Correlix (see FIX items above)." \
        "Prepare it with one command, then re-run the installer:
  sudo ./prepare-host.sh"
    fi
  fi

  command -v docker >/dev/null || die "Docker is not installed." \
    "Prepare the host first:  sudo ./prepare-host.sh"
  docker info >/dev/null 2>&1 || die "The Docker daemon is not running (or you lack permission to use it)." \
    "Start it (e.g. 'sudo systemctl start docker') or add your user to the docker group, then re-run."
  docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required ('docker compose' plugin)." \
    "Install the compose plugin: https://docs.docker.com/compose/install/linux/"
  check_rootless_docker
  check_compose_version
  # Installing from THIS folder must not adopt another folder's stack (FMEA
  # S7). Before the UI-port check: that port is usually held by the other stack.
  check_existing_install
  if [ "$MODE" = "bundle" ]; then
    command -v zstd >/dev/null || die "zstd is required to unpack the image bundle." \
      "Install it (Debian/Ubuntu: sudo apt-get install zstd · RHEL: sudo dnf install zstd) and re-run."
  fi

  local mem_kb mem_gb
  mem_kb=$(awk '/MemTotal/{print $2}' /proc/meminfo 2>/dev/null || echo 0)
  mem_gb=$((mem_kb / 1024 / 1024))
  if [ "$mem_gb" -lt 6 ]; then
    die "This host has ${mem_gb} GB RAM; Correlix needs at least 8 GB (16 GB recommended)."
  elif [ "$mem_gb" -lt 15 ]; then
    warn "${mem_gb} GB RAM detected — fine for evaluation; 16 GB is recommended for production."
  else
    ok "memory: ${mem_gb} GB"
  fi

  local free_gb droot
  if ! droot=$(timeout 15 docker info -f '{{.DockerRootDir}}' 2>&1) || [ "${droot#/}" = "$droot" ]; then
    warn "could not read Docker's data root ($(printf '%s' "${droot:-no answer}" | tail -1)) — assuming /var/lib/docker."
    droot=/var/lib/docker
  fi
  free_gb=$(df -BG --output=avail "$droot" 2>/dev/null | tail -1 | tr -dc '0-9')
  free_gb=${free_gb:-0}
  if [ "$free_gb" -lt 20 ]; then
    die "Only ${free_gb} GB free disk for Docker; Correlix needs at least 40 GB (100 GB recommended)."
  elif [ "$free_gb" -lt 40 ]; then
    warn "${free_gb} GB free disk — enough to start an evaluation; 100 GB is recommended."
  else
    ok "disk: ${free_gb} GB free"
  fi
  check_image_disk_projection "$droot"
  check_inode_headroom "Docker data root" "$droot"
  check_inode_headroom "data directory" "$ROOT/data"

  if [ ! -f "$ENV_FILE" ] && port_in_use "$UI_PORT"; then
    die "Port $UI_PORT is already in use. Correlix's web UI needs this port." \
      "Either stop the service using it, or install on another port:
  ./install-correlix.sh install --ui-port 9443"
  fi

  # ...and every OTHER host port the stack publishes. Only the UI port used to
  # be checked, so a busy device-facing port (a host rsyslog on 514, an
  # snmptrapd on 162, another collector on 2055) surfaced ten minutes into the
  # install as docker's "Bind for 0.0.0.0:514 failed: port is already
  # allocated" — precisely the late, confusing failure this gate exists to
  # prevent (fresh-install acceptance, 2026-09-06). Fresh installs only: an
  # existing install's OWN listeners are not a conflict.
  [ -f "$ENV_FILE" ] || check_ingest_ports

  # OpenSearch (the log-search store) needs this kernel setting; without it
  # the store crash-loops after an otherwise clean install. Self-heal when we
  # can do so silently, otherwise tell the customer the exact fix.
  local mmc; mmc=$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)
  if [ "$mmc" -lt 262144 ]; then
    if sudo -n sysctl -w vm.max_map_count=262144 >/dev/null 2>&1; then
      echo "vm.max_map_count=262144" | sudo -n tee /etc/sysctl.d/99-correlix.conf >/dev/null 2>&1 || true
      ok "kernel setting vm.max_map_count raised to 262144"
    else
      die "Kernel setting vm.max_map_count is $mmc; Correlix needs 262144." \
        "Run the host preparation script (installs/fixes everything at once):
  sudo ./prepare-host.sh
or apply just this setting:
  sudo sysctl -w vm.max_map_count=262144
  echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-correlix.conf
then re-run ./install-correlix.sh"
    fi
  fi
  run_host_profile "$droot"
  ok "docker + compose ready"
}

# Release-signature check (#97 owner-gated signing). Called by verify_bundle
# only AFTER SHA256SUMS itself verified and only when SHA256SUMS.asc exists.
# Outcomes, most to least trusted:
#   GOODSIG   → ok (bundle provenance proven)
#   NO_PUBKEY → warn-and-continue: the customer has not imported the Correlix
#               release public key, so the signature cannot be checked — say
#               exactly how to import it. Checksums already verified.
#   otherwise → die: a BAD/forged signature over verified checksums means the
#               .asc does not belong to this bundle. Never install.
# gpg not installed → warn-and-continue for the same reason as NO_PUBKEY: the
# host cannot check what it cannot run, and the checksum gate already passed.
verify_release_signature() {
  if ! command -v gpg >/dev/null 2>&1; then
    warn "SHA256SUMS.asc is present but gpg is not installed — release signature NOT verified (checksums OK)."
    warn "To verify it: install gnupg, import the Correlix release public key, and re-run."
    return 0
  fi
  say "Verifying release signature..."
  local status rc=0
  # --status-fd 1 puts gpg's machine-readable verdict lines on stdout; the
  # human chatter on stderr is discarded because the verdict below is acted on
  # and reported in our own words (gpg's wording varies across versions).
  status=$(gpg --batch --status-fd 1 --verify SHA256SUMS.asc SHA256SUMS 2>/dev/null) || rc=$?
  if [ "$rc" -eq 0 ] && printf '%s\n' "$status" | grep -q '^\[GNUPG:\] GOODSIG '; then
    ok "release signature verified (SHA256SUMS.asc)"
  elif printf '%s\n' "$status" | grep -q '^\[GNUPG:\] NO_PUBKEY '; then
    warn "release signature present but the Correlix release PUBLIC KEY is not in your keyring — signature NOT verified (checksums OK)."
    warn "To verify: obtain the Correlix release public key from your Correlix contact"
    warn "(its fingerprint is recorded in MANIFEST as 'signing-key'), then:"
    warn "  gpg --import <correlix-release-key.asc>   and re-run this installer."
  else
    die "Release signature verification FAILED (SHA256SUMS.asc is not a good signature over SHA256SUMS)." \
      "The bundle may have been tampered with. Do not install. Re-download from the official source and contact Correlix support."
  fi
}

# The expected sha256 of one bundle member from SHA256SUMS, or nothing.
sums_entry() {
  [ -f SHA256SUMS ] || return 0
  awk -v a="$1" -v b="./$1" '$2 == a || $2 == b || $2 == "*" a || $2 == "*" b { print $1; exit }' SHA256SUMS
}

# Join a split image archive through a .partial and an atomic rename (FMEA S9).
# A crash, SIGKILL or full disk mid-join used to leave a truncated file under
# the FINAL name, which every re-run then trusted — and whose checksum failure
# told the operator to re-download a bundle that was fine. Runs in BUNDLE_DIR.
join_image_parts() {
  local joined="$1" partial="$1.partial" want got
  say "Joining image archive parts..."
  if ! cat "$joined".part* > "$partial"; then
    rm -f "$partial"
    die "Could not join the image archive pieces into $joined." \
      "Check free disk space in $BUNDLE_DIR (df -h $BUNDLE_DIR), then re-run — the join starts over."
  fi
  want=$(sums_entry "$joined")
  if [ -n "$want" ]; then
    got=$(sha256sum "$partial" | awk '{print $1}')
    if [ "$got" != "$want" ]; then
      rm -f "$partial"
      die "The joined image archive does not match SHA256SUMS ($joined)." \
        "At least one of the $joined.partNN pieces is incomplete or corrupted. Re-download the pieces and try again."
    fi
  fi
  mv -f "$partial" "$joined"
}

# Extract the source tree through a staging directory and an atomic rename
# (FMEA S11). A half-extracted tree under the final name used to make every
# re-run skip extraction and install from an incomplete tree.
extract_source_tree() {
  [ -n "$BUNDLE_DIR" ] || die "internal error: extract_source_tree outside a bundle"
  local stage="$BUNDLE_DIR/NetOps_Observability.partial" out
  local tarballs=()
  mapfile -t tarballs < <(compgen -G "$BUNDLE_DIR/correlix-source-*.tar.gz")
  if [ "${#tarballs[@]}" -ne 1 ]; then
    die "Expected exactly one correlix-source-<version>.tar.gz in $BUNDLE_DIR, found ${#tarballs[@]}." \
      "Keep only the source archive that belongs to this bundle, then re-run."
  fi
  if [ -e "$stage" ]; then
    warn "removing $stage left by an interrupted extraction — it is redone, never trusted"
    rm -rf "$stage"
  fi
  mkdir "$stage"
  say "Extracting Correlix..."
  if ! out=$(tar -xzf "${tarballs[0]}" -C "$stage" 2>&1); then
    rm -rf "$stage"
    die "Could not extract ${tarballs[0]##*/}: $(printf '%s' "$out" | tail -3)" \
      "Check free disk space in $BUNDLE_DIR (df -h $BUNDLE_DIR), then re-run — extraction starts over."
  fi
  if [ ! -f "$stage/NetOps_Observability/deployment/docker/docker-compose.yml" ]; then
    rm -rf "$stage"
    die "${tarballs[0]##*/} is not a Correlix source archive (no deployment/docker/docker-compose.yml inside)." \
      "Re-download the bundle and try again."
  fi
  mv "$stage/NetOps_Observability" "$ROOT"
  rm -rf "$stage"
}

verify_bundle() {
  cd "$BUNDLE_DIR"
  # Re-join a split image archive (release assets are capped at 2 GiB/file).
  local part0 joined want got
  # `|| true`: compgen exits 1 when nothing matches, which is the normal
  # unsplit-bundle case; an empty result is handled right below.
  part0=$(compgen -G "correlix-images-*.tar.zst.part00" | head -1 || true)
  if [ -n "$part0" ]; then
    joined="${part0%.part00}"
    if [ -e "$joined.partial" ]; then
      warn "removing $joined.partial left by an interrupted join — it is rebuilt, never trusted"
      rm -f "$joined.partial"
    fi
    if [ ! -f "$joined" ]; then
      join_image_parts "$joined"
    else
      want=$(sums_entry "$joined")
      if [ -n "$want" ]; then
        got=$(sha256sum "$joined" | awk '{print $1}')
        if [ "$got" != "$want" ]; then
          warn "$joined does not match SHA256SUMS (an interrupted join by an older installer?) — rebuilding it once from its pieces"
          rm -f "$joined"
          join_image_parts "$joined"
        fi
      fi
    fi
  fi
  if [ -f SHA256SUMS ]; then
    say "Verifying bundle integrity..."
    # Only verify the members that exist (a joined archive replaces its parts).
    if ! sha256sum -c --ignore-missing SHA256SUMS >/dev/null 2>&1; then
      die "Bundle integrity check failed (SHA256SUMS mismatch)." \
        "The download is incomplete or corrupted. Re-download the bundle and try again."
    fi
    ok "bundle integrity verified"
    # Owner-gated release signature (#97): a signed bundle ships SHA256SUMS.asc
    # next to SHA256SUMS; a checksum-only bundle ships neither — that absence
    # keeps today's behavior exactly.
    if [ -f SHA256SUMS.asc ]; then
      verify_release_signature
    fi
  fi
  if [ ! -d "$ROOT" ]; then
    extract_source_tree
  fi
}

# Post-install credential self-test: verify the admin password we are about to
# print actually authenticates (QA 2026-07-21 found a live appliance whose
# documented .env credential had drifted from the stored hash — every runbook
# built on it then fails). Non-fatal: the stack is up either way; we just
# refuse to print credentials we know are wrong without saying so.
verify_admin_login() {
  local pw code payload
  pw=$(env_get ADMIN_INITIAL_PASSWORD) || return 0
  [ -n "$pw" ] || return 0
  # JSON-escape backslash + double-quote (generated passwords can hold both).
  payload=$(printf '{"username":"admin","password":"%s"}' \
    "$(printf '%s' "$pw" | sed 's/\\/\\\\/g; s/"/\\"/g')")
  # The body rides stdin, not argv: an argv is readable by every local user
  # through /proc for as long as curl runs.
  code=$(printf '%s' "$payload" | curl -s -o /dev/null -w '%{http_code}' -m 10 \
    -H 'Content-Type: application/json' --data-binary @- \
    "http://localhost:${UI_PORT}/api/auth/login" 2>/dev/null) || return 0
  if [ "$code" = "200" ]; then
    ok "admin credential verified (login self-test passed)"
  else
    warn "the admin password in .env did NOT authenticate (HTTP $code)."
    warn "If this is an upgrade of a system whose password was changed in the UI,"
    warn "that is expected — sign in with the current password. Otherwise reset it:"
    warn "  see ADMIN_RESET_PASSWORD in ADVANCED.md"
  fi
}

# ---------- health + stability gate (FMEA row 5, design §4.7) ----------------
# "Healthy" used to be two samples of State 25 s apart. A JVM restarting every
# 20 s reads `running` in both (keycloak: RestartCount=106 on .123 while every
# sample said running), and most services have no healthcheck at all. Success
# now means STABLE: nothing restarted, nothing (re)started, nothing unhealthy
# across a whole window, and every one-shot `*-init` step exited 0.

# One line per container of this compose project (running or not):
#   id|service|restart_count|started_at|status|health|exit_code
# health is "none" for a service without a healthcheck.
SNAPSHOT_ERR=""
container_snapshot() {
  local ids out rc
  SNAPSHOT_ERR=""
  if ! ids=$(compose_q ps -aq); then
    SNAPSHOT_ERR="docker compose ps: $(compose_q_err)"
    [ "$SNAPSHOT_ERR" = "docker compose ps: " ] && SNAPSHOT_ERR="docker compose ps failed with no output"
    return 1
  fi
  if [ -z "$ids" ]; then
    SNAPSHOT_ERR="docker compose ps listed no containers for this install (wrong directory, or the stack was removed)"
    return 1
  fi
  # shellcheck disable=SC2086  # deliberate word-split of the container id list
  out=$(timeout "$(scaled_s 60)" docker inspect --format \
    '{{.Id}}|{{index .Config.Labels "com.docker.compose.service"}}|{{.RestartCount}}|{{.State.StartedAt}}|{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|{{.State.ExitCode}}' \
    $ids 2>&1); rc=$?
  if [ "$rc" -ne 0 ]; then
    SNAPSHOT_ERR="docker inspect (exit $rc): $(printf '%s' "$out" | tail -2)"
    return 1
  fi
  printf '%s\n' "$out"
}

# The window, from CORRELIX_STABILITY_WINDOW_S: default 60 s, clamped to
# 10..900 so neither a typo nor a huge value turns the gate into nothing or into
# a hang. Warnings go to stderr — stdout is the value.
stability_window_s() {
  local w="${CORRELIX_STABILITY_WINDOW_S:-60}"
  case "$w" in
    ''|*[!0-9]*)
      warn "CORRELIX_STABILITY_WINDOW_S='$w' is not a whole number of seconds — using 60." >&2
      w=60 ;;
  esac
  w=$((10#$w))
  if [ "$w" -lt 10 ]; then
    warn "CORRELIX_STABILITY_WINDOW_S=$w is too short to see a crash loop — using 10." >&2
    w=10
  elif [ "$w" -gt 900 ]; then
    warn "CORRELIX_STABILITY_WINDOW_S=$w is capped at 900." >&2
    w=900
  fi
  printf '%s' "$w"
}

# Hide any log line that looks like it carries a credential before it is shown.
redact_log_lines() {
  sed -E '/passw|secret|token|api[-_]?key|credential|bearer/I s/.*/[line hidden: it may contain a credential]/'
}

# Name one problem container and show its recent (redacted) log lines.
report_container() { # id service reason
  local out
  warn "$2: $3"
  if out=$(timeout 15 docker logs --tail 20 "$1" 2>&1 </dev/null); then
    if [ -n "$out" ]; then
      say "    last log lines of $2 (lines that may hold a credential are hidden):"
      printf '%s\n' "$out" | redact_log_lines | sed 's/^/      /'
    fi
  else
    say "    (could not read the logs of $2: $(printf '%s' "$out" | redact_log_lines | tail -1))"
  fi
}

report_containers() { # "id|service|reason" lines
  local id svc reason
  while IFS='|' read -r id svc reason; do
    [ -n "$id" ] || continue
    report_container "$id" "$svc" "$reason"
  done <<< "$1"
}

stability_gate() {
  local w t0 t1 problems
  w=$(stability_window_s)
  say "All services are up — confirming they stay up for ${w}s (a crash-looping service looks healthy between restarts)..."
  if ! t0=$(container_snapshot); then
    warn "could not read this install's container state for the stability check (docker compose ps / docker inspect failed)."
    return 1
  fi
  sleep "$w"
  if ! t1=$(container_snapshot); then
    warn "could not read this install's container state at the end of the stability window."
    return 1
  fi
  problems=$(awk -F'|' -v w="$w" '
    NR == FNR { rc[$1] = $3; st[$1] = $4; name[$1] = $2; next }
    {
      seen[$1] = 1
      if ($2 ~ /-init$/) {
        if ($5 != "exited") print $1 "|" $2 "|one-shot setup step is still " $5 " after the window"
        else if ($7 != "0") print $1 "|" $2 "|one-shot setup step exited with code " $7 " (it must exit 0)"
        next
      }
      if (!($1 in rc))        { print $1 "|" $2 "|container was created during the " w "s window"; next }
      if ($3 + 0 > rc[$1] + 0) { print $1 "|" $2 "|restarted " ($3 - rc[$1]) " time(s) during the " w "s window (crash loop)"; next }
      if ($4 != st[$1])       { print $1 "|" $2 "|restarted during the " w "s window (started " st[$1] ", then " $4 ")"; next }
      if ($5 != "running")    { print $1 "|" $2 "|is " $5 ", not running"; next }
      if ($6 == "unhealthy")  { print $1 "|" $2 "|is unhealthy at the end of the window"; next }
    }
    END { for (id in rc) if (!(id in seen)) print id "|" name[id] "|container disappeared during the window" }
  ' <(printf '%s\n' "$t0") <(printf '%s\n' "$t1"))
  if [ -z "$problems" ]; then
    ok "stable: no service restarted or went unhealthy during the ${w}s window"
    return 0
  fi
  warn "the stack is NOT stable, so the install is not reported as successful:"
  report_containers "$problems"
  return 1
}

wait_healthy() {
  say "Waiting for services to become healthy (this can take a few minutes)..."
  local budget; budget=$(scaled_s 420)
  local deadline=$(( $(date +%s) + budget )) snap="" failed notready ready=0 lasterr=""
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if snap=$(container_snapshot); then
      # A one-shot that already failed will not improve by waiting.
      failed=$(printf '%s\n' "$snap" | awk -F'|' '$2 ~ /-init$/ && $5 == "exited" && $7 != "0" {
        print $1 "|" $2 "|one-shot setup step exited with code " $7 " (it must exit 0)" }')
      if [ -n "$failed" ]; then
        report_containers "$failed"
        return 1
      fi
      notready=$(printf '%s\n' "$snap" | awk -F'|' '
        $2 ~ /-init$/ { if ($5 != "exited") print $1 "|" $2 "|one-shot setup step is still " $5; next }
        $5 != "running"      { print $1 "|" $2 "|is " $5 ", not running"; next }
        $6 == "unhealthy"    { print $1 "|" $2 "|is unhealthy"; next }
        $6 == "starting"     { print $1 "|" $2 "|is still starting" }')
      if [ -z "$notready" ] && curl -fsS -m 5 -o /dev/null "http://127.0.0.1:${UI_PORT}/" 2>/dev/null; then
        ready=1
        break
      fi
    else
      lasterr="$SNAPSHOT_ERR"
      snap=""
    fi
    sleep 10
  done
  if [ "$ready" != 1 ]; then
    warn "services did not all become ready within $((budget / 60)) minutes:"
    if [ -z "$snap" ]; then
      warn "could not read this install's container state: ${lasterr:-docker compose ps / docker inspect failed}"
      warn "the stack itself may be fine — check with: ./install-correlix.sh status"
    elif [ -n "$notready" ]; then
      report_containers "$notready"
    else
      warn "every container is up, but the web UI did not answer on http://127.0.0.1:${UI_PORT}/"
    fi
    return 1
  fi
  stability_gate
}

# Is this install running the TLS/mTLS variant? .env's COMPOSE_FILE chain is
# the single on-disk statement of it (install.py writes compose.tls.yml into it
# at TLS phase B), so this and install.py cannot disagree.
tls_active() {
  case "$(env_get COMPOSE_FILE)" in *compose.tls.yml*) return 0 ;; *) return 1 ;; esac
}

# The URL to hand the operator. Under TLS the ingress is 443 and the plaintext
# port is bound to loopback (compose.tls.yml), so http://<host>:8000 is not
# merely second-best — off the appliance it does not answer at all. Printing it
# there is the defect the fresh-install acceptance hit (2026-09-06, DEFECT-7);
# the graphical path was fixed in d31245c7 and this is the terminal path.
# Pinned by tests/test_install_tls_ingress.py.
dashboard_url() {
  local host ip
  ip=$(hostname -I 2>/dev/null | awk '{print $1}') ; host=${ip:-localhost}
  if tls_active; then printf 'https://%s/' "$host"
  else printf 'http://%s:%s' "$host" "$UI_PORT"; fi
}

ADMIN_CREDENTIAL_FILE="$ROOT/data/initial-admin-credential.txt"

# Write the initial admin credential to a 0600 file, atomically. It lives under
# data/ so it is kept with the install's data on a plain uninstall and removed
# by --purge. Returns non-zero (with the reason on stderr) if it cannot.
write_admin_credential() { # url user password
  local dir tmp
  dir=$(dirname "$ADMIN_CREDENTIAL_FILE")
  mkdir -p "$dir" || return 1
  tmp="$ADMIN_CREDENTIAL_FILE.tmp.$$"
  # printf is a builtin: the password never appears in a process argv.
  if ! ( umask 077 && printf '%s\n' \
      "# Correlix initial administrator credential, generated for this install." \
      "# Sign in, change the password in Settings, then delete this file." \
      "url=$1" "username=$2" "password=$3" > "$tmp" ); then
    rm -f "$tmp"
    return 1
  fi
  mv -f "$tmp" "$ADMIN_CREDENTIAL_FILE"
}

print_success() {
  local url user pw
  url=$(dashboard_url)
  user=$(env_get ADMIN_USERNAME); user=${user:-admin}
  pw=$(env_get ADMIN_INITIAL_PASSWORD)
  say ""
  say "${GREEN}${BOLD}────────────────────────────────────────────────${RST}"
  say "${GREEN}${BOLD}  Correlix is installed and running${RST}"
  say "${GREEN}${BOLD}────────────────────────────────────────────────${RST}"
  say ""
  say "  Open the UI:   ${BOLD}${url}${RST}"
  say "  Sign in as:    ${BOLD}${user}${RST}"
  # The generated password never goes through say(): stdout is the tee'd
  # install log, the wizard's log ring and its SSE replay (FMEA row 6). It is
  # written to a 0600 file whose PATH is printed, and — for an operator at a
  # real terminal only — shown on that terminal after the log has closed. The
  # wizard reads it from .env itself. The pointer line deliberately does not
  # start with "Password:" (the wizard's banner scrape would take the next word).
  if [ -n "$pw" ]; then
    if write_admin_credential "$url" "$user" "$pw"; then
      say "  Initial password saved to: ${BOLD}${ADMIN_CREDENTIAL_FILE}${RST}"
      say "                 ${DIM}(readable only by you — change the password in Settings, then delete the file)${RST}"
    else
      warn "could not write $ADMIN_CREDENTIAL_FILE — the initial password is ADMIN_INITIAL_PASSWORD in $ENV_FILE"
    fi
    if [ "${CORRELIX_PROGRESS_JSON:-0}" != "1" ] && [ -n "$LOG_FILTER_PID" ] && [ -t 5 ]; then
      TERMINAL_EPILOGUE=$(printf '\n  Password:      %s%s%s\n                 %s(shown on this terminal only; it is not in the log)%s' \
        "$BOLD" "$pw" "$RST" "$DIM" "$RST")
    fi
  fi
  say ""
  say "  Useful commands:"
  say "    ./install-correlix.sh status     service health"
  say "    ./install-correlix.sh logs       recent logs"
  say "    ./install-correlix.sh stop       stop (keeps your data)"
  say ""
}

print_failure() {
  say ""
  say "${RED}${BOLD}Installation did not complete cleanly.${RST}"
  say ""
  say "  What to do next:"
  say "    1. See which service is unhappy:   ./install-correlix.sh status"
  say "    2. Look at its logs:               ./install-correlix.sh logs <service>"
  say "    3. Check TROUBLESHOOTING.md for the most common fixes."
  say "    4. Re-running ./install-correlix.sh is safe — the installer is idempotent."
  say ""
}

# ---------- friendly status --------------------------------------------------
friendly_status() {
  [ -f "$ENV_FILE" ] || die "Correlix is not installed here yet." "Run: ./install-correlix.sh"
  say "${BOLD}Correlix service health${RST}"
  compose ps --format '{{.Service}}|{{.State}}|{{.Health}}' 2>/dev/null | sort | while IFS='|' read -r svc state health; do
    local label
    case "$svc" in
      kafka)             label="Event Bus (Apache Kafka)" ;;
      kafka-init)        continue ;;  # one-shot; exited 0 is normal
      redis)             label="Cache (Valkey)" ;;
      postgres)          label="App Database (PostgreSQL)" ;;
      clickhouse)        label="Analytics Store (ClickHouse)" ;;
      opensearch)        label="Log Search (OpenSearch)" ;;
      opensearch-dashboards) label="Log Search UI" ;;
      victoria)          label="Metrics Store" ;;
      prometheus)        label="Metrics Scrape" ;;
      grafana)           label="Self-Observability" ;;
      api)               label="Correlix API" ;;
      frontend)          label="Correlix UI" ;;
      nginx)             label="Web Front Door" ;;
      correlation)       label="Correlation Engine" ;;
      vector-aggregator) label="Telemetry Pipeline (ingest)" ;;
      vector-router)     label="Telemetry Pipeline (storage)" ;;
      syslog-ng)         label="Syslog Receiver" ;;
      goflow2)           label="Flow Receiver" ;;
      gnmic)             label="gNMI Collector" ;;
      prober)            label="Active Measurement" ;;
      cadvisor)          label="Container Monitor" ;;
      node-exporter)     label="Host Metrics" ;;
      *)                 label="$svc" ;;
    esac
    local verdict="$GREEN✔ healthy$RST"
    if [ "$state" != "running" ]; then verdict="$RED✘ not running$RST"
    elif [ "$health" = "unhealthy" ]; then verdict="$RED✘ unhealthy$RST"
    elif [ "$health" = "starting" ]; then verdict="$YELLOW… starting$RST"
    fi
    printf '  %-34s %b\n' "$label" "$verdict"
  done
  local port; port=$(env_get BASE_PORT); port=${port:-8000}
  say ""
  say "  UI: http://localhost:${port}"
}

# ---------- installation profile (Profile JSON v1, GUI contract) ---------
# `install --config FILE` expands an exported profile to the existing flags.
# Fail-closed: unknown top-level keys (and unknown add-ons) are hard errors;
# every value is validated BEFORE anything touches the host. The validator is
# a bounded python3 helper (python3 is already a hard prerequisite) that only
# ever emits CFG_* lines whose values are restricted to shell-safe charsets.
CFG_PORT="" CFG_TLS="" CFG_RETENTION="" CFG_ADDONS=""
CFG_BROKER_URLS="" CFG_SNMP_CIDRS="" CFG_SIZING=""
CFG_ADMIN_USER="" CFG_STORE_BACKEND=""
CONFIG_ADDON_PROFILES=""

load_config() {
  local file="$1" out line
  [ -f "$file" ] || die "Config file not found: $file"
  if ! out=$(python3 - "$file" <<'PYCFG'
import ipaddress, json, re, sys

def bad(msg):
    print(f"profile config: {msg}", file=sys.stderr)
    sys.exit(1)

try:
    with open(sys.argv[1]) as f:
        doc = json.load(f)
except (OSError, ValueError) as e:
    bad(f"cannot parse JSON: {e}")
if not isinstance(doc, dict):
    bad("top level must be a JSON object")

ALLOWED = {"version", "port", "tls", "admin_user", "store_backend",
           "retention_profile", "addons", "external_kafka", "discovery", "sizing"}
unknown = sorted(set(doc) - ALLOWED)
if unknown:
    bad("unknown top-level key(s): " + ", ".join(unknown))
if doc.get("version") != 1:
    bad("missing or unsupported \"version\" (this installer expects 1)")

port = doc.get("port", 8000)
if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
    bad(f"\"port\" must be an integer 1-65535, got {port!r}")

tls = doc.get("tls", "no")
if tls not in ("yes", "no"):
    bad(f"\"tls\" must be \"yes\" or \"no\", got {tls!r}")

# The initial Correlix administrator login. Narrow on purpose: it is written
# verbatim into .env as ADMIN_USERNAME, so it must be a plain identifier.
admin_user = doc.get("admin_user", "admin")
if not isinstance(admin_user, str) or not re.fullmatch(r"[a-z][a-z0-9._-]{2,31}", admin_user):
    bad(f"\"admin_user\" must be 3-32 chars, lowercase letter first, then letters/digits/._-, got {admin_user!r}")

# Application-state backend. PostgreSQL is the default for fresh installs
# (tracker 245); "file" is the explicit compatibility choice. "memory" is never
# a shipped install and is not offered here.
store_backend = doc.get("store_backend", "postgres")
if store_backend not in ("postgres", "file"):
    bad(f"\"store_backend\" must be postgres or file, got {store_backend!r}")

retention = doc.get("retention_profile", "production")
if retention not in ("lab", "demo", "production", "extended"):
    bad(f"\"retention_profile\" must be lab|demo|production|extended, got {retention!r}")

addons = doc.get("addons") or []
if not isinstance(addons, list) or any(
        not isinstance(a, str) or not re.fullmatch(r"[a-z0-9-]+", a) for a in addons):
    bad("\"addons\" must be a list of add-on names (lowercase, digits, dashes)")

broker = ""
ek = doc.get("external_kafka")
if ek is not None:
    if not isinstance(ek, dict) or set(ek) != {"broker_urls"}:
        bad("\"external_kafka\" must be null or {\"broker_urls\": \"host:port[,host:port]\"}")
    broker = ek["broker_urls"]
    if not isinstance(broker, str) or not re.fullmatch(r"[A-Za-z0-9_.:,\[\]-]+", broker):
        bad(f"\"external_kafka.broker_urls\" is not a valid broker list: {broker!r}")

cidrs = ""
disc = doc.get("discovery")
if disc is not None:
    if not isinstance(disc, dict) or not set(disc) <= {"enabled", "cidrs"}:
        bad("\"discovery\" must be {\"enabled\": bool, \"cidrs\": [\"CIDR\", ...]}")
    if not isinstance(disc.get("enabled", False), bool):
        bad("\"discovery.enabled\" must be true or false")
    if disc.get("enabled"):
        ranges = disc.get("cidrs") or []
        if not isinstance(ranges, list) or not ranges:
            bad("\"discovery.enabled\" is true but \"discovery.cidrs\" is empty")
        for c in ranges:
            try:
                ipaddress.ip_network(c, strict=False)
            except ValueError:
                bad(f"\"discovery.cidrs\" entry is not a valid CIDR: {c!r}")
        cidrs = ",".join(ranges)

sizing = doc.get("sizing") or {}
if not isinstance(sizing, dict) or not set(sizing) <= {"profile"}:
    bad("\"sizing\" must be {\"profile\": \"auto|demo|small|medium|large\"}")
sizing_profile = sizing.get("profile", "auto")
if sizing_profile not in ("auto", "demo", "small", "medium", "large"):
    bad(f"\"sizing.profile\" must be auto|demo|small|medium|large, got {sizing_profile!r}")

print(f"CFG_PORT={port}")
print(f"CFG_TLS={tls}")
print(f"CFG_RETENTION={retention}")
print(f"CFG_ADDONS={','.join(addons)}")
print(f"CFG_BROKER_URLS={broker}")
print(f"CFG_SNMP_CIDRS={cidrs}")
print(f"CFG_SIZING={sizing_profile}")
print(f"CFG_ADMIN_USER={admin_user}")
print(f"CFG_STORE_BACKEND={store_backend}")
PYCFG
  ); then
    die "Invalid installation profile: $file" \
      "Fix the config (see the message above) and re-run. Unknown keys are rejected on purpose."
  fi
  while IFS= read -r line; do
    case "$line" in
      CFG_PORT=*)        CFG_PORT="${line#CFG_PORT=}" ;;
      CFG_TLS=*)         CFG_TLS="${line#CFG_TLS=}" ;;
      CFG_RETENTION=*)   CFG_RETENTION="${line#CFG_RETENTION=}" ;;
      CFG_ADDONS=*)      CFG_ADDONS="${line#CFG_ADDONS=}" ;;
      CFG_BROKER_URLS=*) CFG_BROKER_URLS="${line#CFG_BROKER_URLS=}" ;;
      CFG_SNMP_CIDRS=*)  CFG_SNMP_CIDRS="${line#CFG_SNMP_CIDRS=}" ;;
      CFG_SIZING=*)      CFG_SIZING="${line#CFG_SIZING=}" ;;
      CFG_ADMIN_USER=*)  CFG_ADMIN_USER="${line#CFG_ADMIN_USER=}" ;;
      CFG_STORE_BACKEND=*) CFG_STORE_BACKEND="${line#CFG_STORE_BACKEND=}" ;;
      *) die "Unexpected config-parser output: $line" ;;
    esac
  done <<< "$out"
  UI_PORT="$CFG_PORT"
  if [ -n "$CFG_BROKER_URLS" ]; then
    EXTERNAL_KAFKA=1
    BROKER_URLS_ARG="$CFG_BROKER_URLS"
  fi
  # Add-ons map through the SAME registry `enable` uses — an add-on unknown to
  # the registry is a hard error, not a silently dropped profile entry.
  CONFIG_ADDON_PROFILES=""
  if [ -n "$CFG_ADDONS" ]; then
    local a spec prof
    for a in ${CFG_ADDONS//,/ }; do
      spec=$(addon_spec "$a")
      [ -n "$spec" ] || die "Unknown add-on in config: '$a'" "$ADDON_HELP"
      prof="${spec%%|*}"
      case ",$CONFIG_ADDON_PROFILES," in
        *",$prof,"*) ;;
        *) CONFIG_ADDON_PROFILES="${CONFIG_ADDON_PROFILES:+$CONFIG_ADDON_PROFILES,}$prof" ;;
      esac
    done
  fi
}

# ---------- install.py argument assembly ---------------------------------
# Fills the global INSTALL_ARGS array (bash functions cannot return arrays).
# Config mode is fully non-interactive: --tls comes from the profile and
# --bootstrap-docker no guarantees no prompt can ever block the run.
INSTALL_ARGS=()
assemble_install_args() {
  INSTALL_ARGS=(--port "$UI_PORT")
  # Bundle installs start as the BASE appliance (add-ons come later via
  # `enable`); source checkouts get the developer default incl. dashboards +
  # self-monitoring.
  local profiles="embedded-bus,prober,osd,self-monitoring"
  local images=""
  if [ "$MODE" = "bundle" ]; then
    images=$(compgen -G "$BUNDLE_DIR/correlix-images-*.tar.zst" | head -1 || true)
    [ -n "$images" ] || die "Image archive not found in the bundle." \
      "Expected correlix-images-core-<version>.tar.zst (or its .partNN pieces) next to this script."
    INSTALL_ARGS+=(--bundle "$images")
    profiles="embedded-bus,prober"
  fi
  if [ -n "$CONFIG_FILE" ]; then
    # The profile owns the add-on set: base appliance + exactly the addons
    # listed (mapped to compose profiles via the registry in load_config).
    profiles="embedded-bus,prober${CONFIG_ADDON_PROFILES:+,$CONFIG_ADDON_PROFILES}"
  fi
  if [ "$EXTERNAL_KAFKA" = 1 ]; then
    [ -n "$BROKER_URLS_ARG" ] || die "External Kafka mode needs your broker endpoints." \
      "Provide them like this:
  ./install-correlix.sh install --external-kafka --broker-urls broker1:9092,broker2:9092
(or set the BROKER_URLS environment variable). See ADVANCED.md."
    INSTALL_ARGS+=(--broker-urls "$BROKER_URLS_ARG")
    say "Using your external Kafka-compatible broker: $BROKER_URLS_ARG"
  elif [ -n "$BROKER_URLS_ARG" ] && [ "$BROKER_URLS_ARG" != "kafka:9092" ]; then
    warn "BROKER_URLS is set but --external-kafka was not given — ignoring it and using the embedded bus."
  fi
  [ "$LAB" = 1 ] && say "${DIM}(lab mode: developer profiles; internal use only)${RST}"
  INSTALL_ARGS+=(--profiles "$profiles")
  # #101: correlation history retention profile (hot TTLs + cold export
  # cadence). Appliance default is production (180/90/90 days); override via
  # CORR_RETENTION_PROFILE=lab|demo|production|extended before running, or
  # the profile config's retention_profile in config mode.
  if [ -n "$CONFIG_FILE" ]; then
    INSTALL_ARGS+=(--retention-profile "$CFG_RETENTION")
  elif [ -n "${CORR_RETENTION_PROFILE:-}" ]; then
    INSTALL_ARGS+=(--retention-profile "$CORR_RETENTION_PROFILE")
  fi
  # #102: host/workload-derived resource sizing (scripts/resource_planner.py).
  # Fresh customer installs size to the detected host by default; drop a
  # correlix-sizing.yaml next to this script to declare workload inputs
  # (devices, flows/s, EPS, retention, users, tenants). The planner REFUSES
  # with a sizing report when the workload cannot safely fit — that is the
  # feature, not a bug. Opt out with CORRELIX_NO_SIZING=1 (lab-tier defaults).
  if [ "${CORRELIX_NO_SIZING:-0}" != 1 ]; then
    if [ -n "$CONFIG_FILE" ] && [ "$CFG_SIZING" != "auto" ]; then
      INSTALL_ARGS+=(--plan-resources "$CFG_SIZING")
    else
      INSTALL_ARGS+=(--plan-resources)
    fi
    if [ -f "$HERE/correlix-sizing.yaml" ]; then
      INSTALL_ARGS+=(--sizing-file "$HERE/correlix-sizing.yaml")
      say "Resource sizing: detected host + correlix-sizing.yaml workload inputs."
    else
      say "Resource sizing: detected host resources (auto profile)."
      say "${DIM}(declare your workload in correlix-sizing.yaml for workload-aware sizing — see docs/RESOURCE_SIZING.md)${RST}"
    fi
  fi
  if [ -n "$CONFIG_FILE" ]; then
    # install.py owns .env authoring, so these two ride the environment rather
    # than becoming flags: they are values it writes once into the template,
    # not decisions it makes. Both are already validated above.
    [ -n "$CFG_ADMIN_USER" ] && export CORRELIX_ADMIN_USERNAME="$CFG_ADMIN_USER"
    [ -n "$CFG_STORE_BACKEND" ] && export CORRELIX_STORE_BACKEND="$CFG_STORE_BACKEND"
    INSTALL_ARGS+=(--tls "$CFG_TLS" --bootstrap-docker no)
    if [ -n "$CFG_SNMP_CIDRS" ]; then
      INSTALL_ARGS+=(--snmp-discovery "$CFG_SNMP_CIDRS")
    fi
  fi
}

# ---------- install transcript (FMEA row 14) ---------------------------------
# The filter copies the byte stream to the terminal untouched — a prompt with no
# newline still shows at once, and `@CX@` markers reach the wizard exactly as
# emitted — and writes the log line by line, each line prefixed with the UTC
# time it began. `@CX@ {json}` markers are the exception: they stay
# byte-identical at line start in the log too. If the terminal goes away (a
# dropped ssh session, a stopped wizard) the filter keeps logging instead of
# dying and taking the install down with SIGPIPE; if the log cannot be written
# (disk full) it says so once and keeps the terminal copy flowing.
# Kept in single quotes, so it must contain no single quote.
LOG_FILTER_PY='
import os, sys, time
MARK = b"@CX@ "
log = os.open(sys.argv[1], os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
state = {"out": True, "log": True}

def put(fd, data):
    while data:
        data = data[os.write(fd, data):]

def emit(line, t):
    if not state["log"]:
        return
    stamp = b"" if line.startswith(MARK) else time.strftime("%Y-%m-%dT%H:%M:%SZ ", time.gmtime(t)).encode()
    try:
        put(log, stamp + line + b"\n")
    except OSError as e:
        state["log"] = False
        if state["out"]:
            try:
                put(1, ("\ncorrelix: writing the install log failed (%s); the install continues, output on this terminal only\n" % e).encode())
            except OSError:
                state["out"] = False

pending, started = b"", 0.0
while True:
    chunk = os.read(0, 65536)
    if not chunk:
        break
    if state["out"]:
        try:
            put(1, chunk)
        except OSError:
            state["out"] = False
    now = time.time()
    parts = chunk.split(b"\n")
    for i, part in enumerate(parts[:-1]):
        if i == 0 and pending:
            emit(pending + part, started)
        else:
            emit(part, now)
    if len(parts) > 1:
        pending, started = parts[-1], now
    else:
        if not pending:
            started = now
        pending += parts[-1]
if pending:
    emit(pending, started)
'

# Full transcript of the installation — tail-able live from another terminal,
# and the first thing support asks for when something fails. Private (0600):
# it names hosts, paths and service accounts even though no secret is written.
start_install_log() {
  INSTALL_LOG="$HERE/correlix-install-$(date +%Y%m%d-%H%M%S).log"
  if ! ( umask 077 && : >> "$INSTALL_LOG" ); then
    die "Cannot create the install log $INSTALL_LOG." \
      "Make $HERE writable by $(id -un), then re-run."
  fi
  chmod 600 "$INSTALL_LOG"
  say "${BOLD}Correlix installer${RST}"
  say "Full log: $INSTALL_LOG"
  say "${DIM}(watch live from another terminal:  tail -f $INSTALL_LOG)${RST}"
  # fds 5/6 keep the real terminal: on_exit restores it, and the password
  # epilogue is written there so it never passes through the log.
  exec 5>&1 6>&2
  if command -v python3 >/dev/null 2>&1; then
    exec > >(exec python3 -c "$LOG_FILTER_PY" "$INSTALL_LOG" 5>&- 6>&-) 2>&1
  else
    warn "python3 is missing, so this log has no per-line timestamps (the host check below stops the install)."
    exec > >(exec tee -a "$INSTALL_LOG" 5>&- 6>&-) 2>&1
  fi
  LOG_FILTER_PID=$!
  trap on_exit EXIT
}

# ---------- commands ----------------------------------------------------
cmd_install() {
  if [ -n "$CONFIG_FILE" ]; then
    load_config "$CONFIG_FILE"
  fi
  if [ "$PRINT_FLAGS" = 1 ]; then
    # Contract/debug aid: print the expanded install.py argv (one per line)
    # and exit without touching the host. Assembly chatter goes to stderr so
    # stdout is exactly the argument list.
    assemble_install_args >&2
    printf '%s\n' "${INSTALL_ARGS[@]}"
    return 0
  fi
  start_install_log
  local root_was_unpacked=0
  if [ -d "$ROOT" ]; then root_was_unpacked=1; fi
  # Single writer from here on (FMEA row 12). A refusal exits 3 naming the
  # holder, before anything on the host is touched.
  acquire_bundle_lock install
  acquire_install_lock install
  # The subshell exists for the fail marker: die() inside preflight exits it,
  # and we translate that into a stage-fail + result before stopping. The
  # human output and the exit code are unchanged from the direct call.
  cx_stage preflight "checking this host" start
  if ! ( preflight ); then
    cx_stage preflight "checking this host" fail "host preflight failed (see messages above)"
    cx_result fail
    exit 1
  fi
  cx_stage preflight "checking this host" ok
  if [ "$MODE" = "bundle" ]; then
    verify_bundle
    # A first-run bundle only now has deployment/docker/ to lock.
    acquire_install_lock install
    # preflight ran before the source tree existed, so the host profiler that
    # ships inside it could not run yet: measure now, before any budget is spent.
    if [ "$root_was_unpacked" = 0 ]; then
      run_host_profile ""
    fi
  fi

  # Assemble install.py arguments. Defaults are the appliance path: embedded
  # Apache Kafka + embedded Valkey + everything else, zero questions asked.
  assemble_install_args

  say ""
  # -u + PYTHONUNBUFFERED: through the log pipe a buffered python writes its
  # stdout in 4 KiB blocks, so the log's lines came out of order and a killed
  # run lost its last lines (FMEA row 14). fds 5/6 are the terminal copies the
  # log filter bypasses; install.py must not inherit them. fd 9 (the lock) is
  # inherited on purpose — see the lock contract above.
  if ! PYTHONUNBUFFERED=1 python3 -u "$ROOT/scripts/install.py" "${INSTALL_ARGS[@]}" 5>&- 6>&-; then
    print_failure
    cx_result fail
    exit 1
  fi
  cx_stage verify-health "waiting for services to become healthy" start
  if wait_healthy; then
    cx_stage verify-health "waiting for services to become healthy" ok
    # No image pruning here (owner rule, FMEA S13): deleting unreferenced
    # image objects on a live host already removed images under running
    # containers once (2026-09-06). A previous version's images are removed
    # only by the explicit, named `cleanup-old-images --confirm` after an
    # upgrade.
    cx_stage verify-login "verifying the admin credential" start
    verify_admin_login
    # verify_admin_login is advisory by design (it warns, never blocks), so
    # the stage always closes ok; the credential itself NEVER rides a marker.
    cx_stage verify-login "verifying the admin credential" ok
    print_success
    cx_result ok "$(dashboard_url)" "$(env_get ADMIN_USERNAME || echo admin)"
  else
    cx_stage verify-health "waiting for services to become healthy" fail \
      "services did not become healthy and stable (see the named services above)"
    print_failure
    cx_result fail
    exit 1
  fi
}

# The image `purge_data_dir` runs its privileged `rm` in. The store data was
# written by containers as THEIR uids (postgres 999, clickhouse 101, victoria
# root), so an unprivileged installer cannot remove it from the host at all —
# it needs a container that is root inside the mount, exactly as cmd_reset_demo
# already does. On an air-gapped appliance we may not pull one, so the image
# has to be something already on this host (the same lesson install.py's
# _chown_helper_ref() encodes for the chown helper: `docker load` restores by
# TAG, and a virgin host has nothing else).
#
# Preference order: a tiny general-purpose image if the host happens to have
# one, then the bundle's own alpine-based images by name. `docker run
# --entrypoint sh` bypasses whatever entrypoint the borrowed image declares.
purge_helper_image() {
  local img
  for img in alpine:latest alpine:3 alpine busybox:latest busybox; do
    docker image inspect "$img" >/dev/null 2>&1 && { printf '%s' "$img"; return 0; }
  done
  if [ -n "$BUNDLE_DIR" ] && [ -f "$BUNDLE_DIR/MANIFEST" ]; then
    while read -r img; do
      case "$img" in *alpine*) ;; *) continue ;; esac
      docker image inspect "$img" >/dev/null 2>&1 && { printf '%s' "$img"; return 0; }
    done < <(sed -n 's/^  - //p' "$BUNDLE_DIR/MANIFEST" | sed 's/@sha256:[0-9a-f]*$//' | sort -u)
  fi
  return 1
}

# Remove $ROOT/data completely, or say precisely why it could not be and stop.
#
# `rm -rf "$ROOT/data"` alone is what shipped, and on a real appliance it fails
# with hundreds of "Permission denied", exits 1, and leaves the stores on disk
# AFTER the script has announced "Purging data..." — a purge that silently is
# not one (fresh-install acceptance, 2026-09-06, DEFECT-11). §16.1: the failure
# is now either repaired or named, never printed over.
purge_data_dir() {
  [ -e "$ROOT/data" ] || return 0
  # Fast path: everything in there is ours (a --no-start install, or a root
  # installer). Nothing to explain, nothing to borrow an image for.
  if rm -rf "$ROOT/data" 2>/dev/null && [ ! -e "$ROOT/data" ]; then
    return 0
  fi
  local img out rc=0
  if img="$(purge_helper_image)"; then
    say "  store data is owned by the service accounts inside the containers —"
    say "  removing it through a privileged helper container ($img)..."
    out="$(docker run --rm --entrypoint sh -v "$ROOT/data:/data" "$img" \
             -c 'find /data -mindepth 1 -maxdepth 1 -exec rm -rf {} +' 2>&1)" || rc=$?
    if [ "$rc" -ne 0 ]; then
      die "the helper container could not remove $ROOT/data (exit $rc): $(printf '%s' "$out" | tail -3)" \
"Nothing was left half-removed on purpose — the images and containers are gone.
Finish the purge by hand and re-run if you want the rest:
  sudo rm -rf '$ROOT/data'"
    fi
    rm -rf "$ROOT/data" 2>/dev/null || true
  fi
  if [ -e "$ROOT/data" ]; then
    die "could not remove $ROOT/data." \
"The store data belongs to the uids the containers ran as (postgres 999,
clickhouse 101, victoria 0) and this installer is not root, so it cannot
delete it, and no local image was available to do it from inside a
container. Nothing was quietly skipped — remove it with:
  sudo rm -rf '$ROOT/data'"
  fi
  return 0
}

# The anonymous volumes this compose project's containers are using, one per
# line. MUST be read BEFORE `compose down`: an anonymous volume carries no
# label naming a project, so once the containers are gone it can no longer be
# attributed to Correlix and nothing may safely remove it (a blanket
# `docker volume prune` would take other projects' volumes on a shared daemon).
#
# Only 64-hex names are collected — that is docker's anonymous-volume id shape.
# A NAMED volume would be "<project>_<name>", and `compose down --volumes`
# already owns those.
project_anonymous_volumes() {
  local ids
  ids="$(compose ps -aq 2>/dev/null)" || return 0
  [ -n "$ids" ] || return 0
  # shellcheck disable=SC2086  # deliberate word-split of the container id list
  docker inspect $ids \
    --format '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}}{{"\n"}}{{end}}{{end}}' \
    2>/dev/null | grep -E '^[0-9a-f]{64}$' | sort -u
}

# Remove the volumes captured above, and say what happened either way.
#
# `docker compose down --volumes` does NOT do this. Measured on Compose v2.40.3
# / Docker 29.1.3 (2026-09-07): `down --remove-orphans --volumes` on a project
# whose only volumes are anonymous removed NONE of them — the flag covers named
# volumes declared in the compose file, and this stack declares none. So the
# ten volumes the acceptance found (DEFECT-12) survive `-v` too, and the flag
# alone would have been a fix that fixed nothing.
remove_project_volumes() {
  local vols="$1" v failed="" n=0
  [ -n "$vols" ] || return 0
  for v in $vols; do
    if docker volume rm "$v" >/dev/null 2>&1; then n=$((n + 1))
    else failed="$failed $v"; fi
  done
  [ "$n" -gt 0 ] && ok "$n anonymous volume(s) removed"
  if [ -n "$failed" ]; then
    warn "these volumes could not be removed (something outside this install still uses them):$failed"
    warn "remove them with: docker volume rm$failed"
  fi
  return 0
}

# The install transcripts next to this script, the setup wizard's own install
# transcripts / job-state file / lock (it writes them into the bundle dir, which
# is this script's dir), and the initial-credential file. Transcripts written
# before FMEA row 6 carry the admin password in clear, so a purge has to remove
# them too (X3). A file that cannot be removed is named with the command that
# removes it, and the purge stops before dropping .env, so a re-run finishes.
#
# The wizard's lock and job file are left in place, and named, while a running
# wizard still holds that lock: unlinking a held lock file lets the next opener
# lock a NEW inode while the wizard believes it is the only one.
purge_install_logs() {
  local f n=0 failed="" kept=""
  local wiz_lock="$HERE/correlix-setup-install.lock" wiz_job="$HERE/correlix-setup-install.job.json"
  local wizard_running=0
  if [ -e "$wiz_lock" ] && ! flock -n "$wiz_lock" true; then
    wizard_running=1
  fi
  for f in "$HERE"/correlix-install-*.log "$HERE"/correlix-setup-install-*.log \
           "$wiz_job" "$wiz_lock" "$ADMIN_CREDENTIAL_FILE"; do
    [ -e "$f" ] || continue
    if [ "$wizard_running" = 1 ] && { [ "$f" = "$wiz_lock" ] || [ "$f" = "$wiz_job" ]; }; then
      kept="$kept '$f'"
      continue
    fi
    if rm -f -- "$f" && [ ! -e "$f" ]; then
      n=$((n + 1))
      say "  removed ${f##*/}"
    else
      failed="$failed '$f'"
    fi
  done
  if [ "$n" -gt 0 ]; then ok "$n install log / credential file(s) removed"; fi
  if [ -n "$kept" ]; then
    warn "the setup wizard is still running (it holds its lock), so these were left in place:$kept"
    warn "stop the wizard, then remove them with: rm -f$kept"
  fi
  if [ -n "$failed" ]; then
    die "could not remove:$failed" \
"They may contain the initial admin password. Remove them by hand, then re-run the purge:
  rm -f$failed"
  fi
  return 0
}

# The .env siblings that hold the same secrets as .env: install.py's last
# complete snapshot and the damaged copy it sets aside, the secret-rotation and
# resource-plan backups, and the .env a failed or completed upgrade set aside.
# A purge that removed .env but left these would leave every credential on
# disk. One that cannot be removed is named, and the purge stops before
# dropping .env, so a re-run finishes.
purge_env_siblings() {
  local f n=0 failed=""
  for f in "$ENV_FILE.snapshot" "$ENV_FILE.damaged" "$ENV_FILE.rotate.bak" "$ENV_FILE.plan.bak" \
           "$ENV_FILE".upgrade-failed-* "$ENV_FILE".upgraded-*; do
    [ -e "$f" ] || continue
    if rm -f -- "$f" && [ ! -e "$f" ]; then
      n=$((n + 1))
      say "  removed ${f##*/}"
    else
      failed="$failed '$f'"
    fi
  done
  if [ "$n" -gt 0 ]; then ok "$n configuration backup(s) holding secrets removed"; fi
  if [ -n "$failed" ]; then
    die "could not remove:$failed" \
"They hold this install's secrets. Remove them by hand, then re-run the purge:
  rm -f$failed"
  fi
  return 0
}

cmd_uninstall() {
  acquire_install_lock uninstall
  [ -f "$ENV_FILE" ] || die "Nothing to uninstall — no Correlix install found here."
  # Read the volume list while the containers still exist (see above). Only a
  # purge removes them; a plain uninstall keeps them with the rest of the data.
  local anon_vols=""
  [ "$PURGE" = 1 ] && anon_vols="$(project_anonymous_volumes)"
  say "Stopping and removing Correlix containers..."
  # --volumes is purge-only and covers NAMED volumes (none today, but a future
  # one must not survive a purge); the anonymous ones are removed explicitly
  # below because this flag does not touch them.
  if [ "$PURGE" = 1 ]; then
    compose down --remove-orphans --volumes
  else
    compose down --remove-orphans
  fi
  ok "containers removed"
  if [ "$PURGE" = 1 ]; then
    say "Purging data, configuration, and loaded images..."
    # Data FIRST, images second: the removal needs a local image to run the
    # privileged `rm` in, and the loop below deletes exactly those.
    purge_data_dir
    remove_project_volumes "$anon_vols"
    if [ "$MODE" = "bundle" ] && [ -f "$BUNDLE_DIR/MANIFEST" ]; then
      # MANIFEST pins images as tag@sha256:digest, but docker-load restored
      # them by TAG only (digests are pull-time metadata) — so `docker rmi
      # tag@digest` no-ops on a virgin host. Strip the digest and remove by tag.
      sed -n 's/^  - //p' "$BUNDLE_DIR/MANIFEST" | sed 's/@sha256:[0-9a-f]*$//' | sort -u | while read -r img; do
        docker rmi "$img" >/dev/null 2>&1 || true
      done
    fi
    purge_install_logs
    purge_env_siblings
    rm -f "$ENV_FILE"
    ok "data, volumes and configuration removed (images unreferenced elsewhere were deleted)"
  else
    say "Your data and configuration were kept:"
    say "  data:    $ROOT/data"
    say "  config:  $ENV_FILE"
    say "Remove everything with: ./install-correlix.sh uninstall --purge"
  fi
}

cmd_reset_demo() {
  acquire_install_lock reset-demo-data
  [ -f "$ENV_FILE" ] || die "Correlix is not installed here yet." "Run: ./install-correlix.sh"
  UI_PORT=$(env_get BASE_PORT); UI_PORT=${UI_PORT:-8000}
  say "Resetting to a clean evaluation state (credentials are kept)..."
  compose down --remove-orphans
  # Wipe store data but keep .env (secrets/identity) — dirs are recreated with
  # correct ownership by install.py before start.
  docker run --rm -v "$ROOT/data:/data" alpine sh -c 'find /data -mindepth 1 -maxdepth 1 -exec rm -rf {} +'
  local rargs=(--port "$(env_get BASE_PORT || echo 8000)")
  [ "$MODE" = "bundle" ] && rargs+=(--offline)   # images are already loaded; never build/pull
  PYTHONUNBUFFERED=1 python3 -u "$ROOT/scripts/install.py" "${rargs[@]}"
  if wait_healthy; then
    ok "Correlix reset — same URL and credentials as before."
  else
    print_failure; exit 1
  fi
}

# ---------- add-on packs ------------------------------------------------
# name → "profile|services|side-effect". Optional capability ships as image
# packs next to the bundle; enable = load pack (if present) + flip the compose
# profile in .env + up. Keep this registry in sync with make-installer.sh.
addon_spec() {
  case "$1" in
    log-search-ui)   echo "osd|opensearch-dashboards" ;;
    # EVERY service in the compose profile must be listed: `disable` stops
    # exactly what is named here, so an omission leaves a container running
    # on a customer who was told the add-on is off. kafka-exporter was
    # missing and survived `disable self-monitoring` (fresh-install
    # acceptance, 2026-09-06). Pinned by
    # tests/test_install_addon_packs.py::test_addon_registry_lists_every_service_in_its_profile.
    self-monitoring) echo "self-monitoring|grafana cadvisor node-exporter kafka-exporter" ;;
    # SSO (Keycloak) became a pack on 2026-09-06. It used to be a base image
    # and cost 235 MB in every bundle for a capability whose design is
    # DEFERRED; a default appliance no longer carries it.
    sso)             echo "sso|keycloak" ;;
    *) echo "" ;;
  esac
}

# The one line that lists the add-ons for a human. Used by every refusal and by
# the setup console, so a new pack is named in all of them or in none.
ADDON_HELP="Available add-ons: log-search-ui (log forensics UI), self-monitoring (Grafana + container/host metrics), sso (single sign-on via Keycloak)"

set_env_var() { # KEY VALUE — replace or append in .env
  if grep -q "^$1=" "$ENV_FILE"; then sed -i "s|^$1=.*|$1=$2|" "$ENV_FILE"
  else printf '%s=%s\n' "$1" "$2" >> "$ENV_FILE"; fi
}

cmd_enable() {
  acquire_install_lock enable
  [ -f "$ENV_FILE" ] || die "Correlix is not installed here yet." "Run: ./install-correlix.sh"
  local spec; spec=$(addon_spec "$ADDON_ARG")
  [ -n "$spec" ] || die "Unknown add-on: '${ADDON_ARG:-}'" "$ADDON_HELP"
  local prof="${spec%%|*}"
  # Load the add-on's image pack when installing from a bundle. A MISSING pack
  # is a refusal, not a shrug: on an appliance with no registry route the only
  # other outcome is `docker compose up` failing on a pull minutes later, with
  # a message that names Docker Hub instead of the file the customer needs
  # (scripts/CLAUDE.md 16.1).
  if [ "$MODE" = "bundle" ]; then
    local pack; pack=$(compgen -G "$BUNDLE_DIR/correlix-addon-$ADDON_ARG-"*.tar.zst | head -1 || true)
    [ -n "$pack" ] || die "The '$ADDON_ARG' add-on pack is not in this bundle." \
      "Optional capability ships as a separate download so the base appliance stays small.
Expected: $BUNDLE_DIR/correlix-addon-$ADDON_ARG-<version>.tar.zst
Copy that file next to this script and run the same command again."
    say "Loading $ADDON_ARG images..."
    zstd -dc "$pack" | docker load >/dev/null
  fi
  local cur; cur=$(env_get COMPOSE_PROFILES)
  case ",$cur," in *",$prof,"*) ;; *) set_env_var COMPOSE_PROFILES "${cur:+$cur,}$prof" ;; esac
  [ "$ADDON_ARG" = "self-monitoring" ] && set_env_var GRAFANA_URL "http://grafana:3000"
  # Keycloak does not create its own database and crash-loops on
  # `FATAL: database "keycloak" does not exist` until something does (first real
  # SSO bring-up, 2026-08-03 — docs/runbooks/okta-sso-setup.md §1). install.py
  # owns that step at install time; enabling the pack afterwards has to run it
  # too, or the add-on "works" by starting a container that never comes up.
  # Idempotent (SELECT-then-CREATE), and it needs postgres already running.
  if [ "$ADDON_ARG" = "sso" ]; then
    say "Preparing the Keycloak database..."
    PYTHONUNBUFFERED=1 python3 -u "$ROOT/scripts/install.py" --bootstrap-sso \
      || die "Could not create Keycloak's database." \
           "Keycloak will crash-loop until it exists. Create it by hand with:
  cd $ROOT/deployment/docker && docker compose exec postgres createdb -U \$DB_USER keycloak
then run: ./install-correlix.sh enable sso"
  fi
  say "Starting $ADDON_ARG..."
  compose up -d
  # The api reads GRAFANA_URL at start — recreate so status reflects the add-on.
  [ "$ADDON_ARG" = "self-monitoring" ] && compose up -d api
  ok "$ADDON_ARG enabled. Check: ./install-correlix.sh status"
}

cmd_disable() {
  acquire_install_lock disable
  [ -f "$ENV_FILE" ] || die "Correlix is not installed here yet."
  local spec; spec=$(addon_spec "$ADDON_ARG")
  [ -n "$spec" ] || die "Unknown add-on: '${ADDON_ARG:-}'" "$ADDON_HELP"
  local prof="${spec%%|*}" svcs="${spec##*|}"
  local cur; cur=$(env_get COMPOSE_PROFILES)
  set_env_var COMPOSE_PROFILES "$(printf '%s' "$cur" | tr ',' '\n' | grep -vx "$prof" | paste -sd, -)"
  # Stopping a service that is already stopped is not an error, but a stop that
  # genuinely FAILS must not be swallowed (§16.1) — the old
  # `>/dev/null 2>&1 || true` here would have reported "disabled" over a
  # container that was still running. Capture the output and only surface it if
  # the verification below finds something left behind.
  local out=""
  # shellcheck disable=SC2086
  out="$(compose --profile "$prof" stop $svcs 2>&1)" || true
  # shellcheck disable=SC2086
  out="$out$(compose --profile "$prof" rm -f $svcs 2>&1)" || true
  if [ "$ADDON_ARG" = "self-monitoring" ]; then set_env_var GRAFANA_URL ""; compose up -d api; fi
  # Verify, do not assume: name anything from this add-on still running.
  local still="" s
  for s in $svcs; do
    docker ps --format '{{.Names}}' 2>/dev/null | grep -qE "(^|[_-])${s}(-[0-9]+)?$" \
      && still="$still $s"
  done
  if [ -n "$still" ]; then
    say "$out"
    die "$ADDON_ARG did not fully stop — still running:$still" \
      "Stop them by hand and re-run:
  docker compose --profile $prof stop$still"
  fi
  ok "$ADDON_ARG disabled (its images and data were kept)."
}

cmd_support_bundle() {
  # The collector lives with the rest of the operational scripts; the wrapper
  # only locates it, hands the flags through, and translates its exit code
  # into customer-facing language. Exit 2 = the bundle IS written but PARTIAL.
  local sb="$ROOT/scripts/support-bundle.sh"
  [ -f "$sb" ] || die "support-bundle.sh is missing from this installation." \
      "Expected: $sb"
  say "Collecting a redacted Correlix support bundle (this can take a minute)..."
  local rc=0
  bash "$sb" ${SB_ARGS+"${SB_ARGS[@]}"} || rc=$?
  case "$rc" in
    0) ok "Support bundle written. Read its MANIFEST, then send the .tar.zst to support." ;;
    2) warn "Support bundle written but PARTIAL — at least one collector failed."
       say  "Every failure is named in the bundle's MANIFEST; send it anyway, it is still useful."
       exit 2 ;;
    *) die "Could not produce a support bundle (support-bundle.sh exited $rc)." \
           "Run it directly for the full output: $sb" ;;
  esac
}

# ---------- existing install · upgrade · rollback · old images ------------
# FMEA 2026-09-15 row 7: S7 (an install from a new folder adopts another
# folder's stack), U1 (no upgrade path, no pre-upgrade backup), S13 (a blanket
# image prune after every install).
#
# The compose project name is pinned (`name: netops`, docker-compose.yml), so
# EVERY Correlix folder on a host drives the same containers. Which folder owns
# them is recorded by compose itself, in each container's
# com.docker.compose.project.working_dir label — that label, not a file of
# ours, is the source of truth for "is Correlix installed, and where".
COMPOSE_PROJECT="netops"
UPGRADE_IN_PROGRESS=0
UPGRADE_STATE_FILE="$COMPOSE_DIR/.correlix-upgrade.state"
UPGRADE_COMPOSE_TIMEOUT_S=1800
UPGRADE_SPACE_MARGIN_KB=1048576
UPGRADE_STAMP=""
UPGRADE_FAIL_CAUSE=""
UPGRADE_BACKUP_PATH=""
UPGRADE_BACKUP_ARTIFACT=""
UPGRADE_HAS_DATA=0
UPGRADE_PREV_VERSION=""
UPGRADE_NEW_VERSION=""
PREV_COMPOSE_DIR="" PREV_ROOT="" PREV_ENV="" PREV_BUNDLE_DIR=""
DATA_MOVED=0
ENV_CARRIED=0
TAG_PROBLEMS=""

# canon_dir DIR — the physical path (symlinks resolved), or DIR itself when it
# does not exist (a deleted bundle folder still labels its containers).
canon_dir() { (cd -P -- "$1" 2>/dev/null && pwd -P) || printf '%s' "$1"; }

# The working directories of every container of the project, one per line.
# On failure: non-zero, with docker's own message on stdout for the caller.
project_working_dirs() {
  local out
  if ! out=$(timeout 60 docker ps -a --filter "label=com.docker.compose.project=$COMPOSE_PROJECT" \
      --format '{{.Label "com.docker.compose.project.working_dir"}}' 2>&1); then
    printf '%s' "$out"
    return 1
  fi
  printf '%s\n' "$out" | sed '/^$/d' | sort -u
}

# Ids of the project's RUNNING containers (empty = none). Non-zero if docker
# cannot answer.
project_running_ids() {
  timeout 60 docker ps -q --filter "label=com.docker.compose.project=$COMPOSE_PROJECT"
}

# The installer a human runs for a compose dir: the bundle root's when the
# compose dir sits in an extracted bundle, else the source tree's.
installer_for_compose_dir() {
  local root
  root=$(dirname "$(dirname "$1")")
  if [ -f "$(dirname "$root")/install-correlix.sh" ]; then
    printf '%s' "$(dirname "$root")/install-correlix.sh"
  else
    printf '%s' "$root/scripts/install-correlix.sh"
  fi
}

# Preflight gate (FMEA S7): refuse when a container of the project belongs to a
# DIFFERENT folder. The same folder is a normal idempotent re-run. `upgrade`
# skips it — another folder's stack is exactly what it expects to find.
check_existing_install() {
  if [ "$UPGRADE_IN_PROGRESS" = 1 ]; then return 0; fi
  local dirs d here others="" first=""
  if ! dirs=$(project_working_dirs); then
    die "Could not check this host for an existing Correlix install (docker ps failed: $(printf '%s' "$dirs" | tail -1))." \
      "Without that check an install could take over another folder's containers. Fix Docker access, then re-run."
  fi
  here=$(canon_dir "$COMPOSE_DIR")
  while IFS= read -r d; do
    [ -n "$d" ] || continue
    [ "$(canon_dir "$d")" != "$here" ] || continue
    others="$others
  $d"
    [ -n "$first" ] || first="$d"
  done <<< "$dirs"
  [ -n "$others" ] || return 0
  die "Correlix is already installed on this host from another folder:$others" \
"This folder: $COMPOSE_DIR
Both folders drive the same Docker Compose project ('$COMPOSE_PROJECT'), so installing
from here would take over those containers while that install's data and settings
stay in the other folder. Choose one:
  * upgrade that install to this bundle (verified backup first, automatic rollback on failure):
      $HERE/install-correlix.sh upgrade --from '$first'
  * or remove the old install first (its data is kept unless you add --purge):
      '$(installer_for_compose_dir "$first")' uninstall
If that folder no longer exists, stop its containers with:
  docker compose -p $COMPOSE_PROJECT down"
}

# ---- upgrade state: key=value lines, 0600, rewritten atomically ----
state_get() { sed -n "s/^$2=//p" "$1" 2>/dev/null | head -1; }  # FILE KEY

state_set() { # KEY VALUE
  local tmp="$UPGRADE_STATE_FILE.tmp.$$"
  if ! ( umask 077
         { if [ -f "$UPGRADE_STATE_FILE" ]; then grep -v "^$1=" "$UPGRADE_STATE_FILE" || [ "$?" -eq 1 ]; fi
           printf '%s=%s\n' "$1" "$2"; } > "$tmp" ) \
     || ! mv -f -- "$tmp" "$UPGRADE_STATE_FILE"; then
    rm -f -- "$tmp"
    warn "could not record the upgrade state ($1=$2) in $UPGRADE_STATE_FILE"
    return 1
  fi
}

# After the upgrade has started changing things, the state file is a
# diagnostic record: a failed write is already named by state_set's warning
# and must never abort a rollback half-way.
state_note() { state_set "$1" "$2" || warn "(continuing — the state file is a diagnostic record)"; }

prev_env_get() { sed -n "s/^$1=//p" "$PREV_ENV" 2>/dev/null | head -1; }

manifest_version() {
  if [ -f "$1" ]; then sed -n 's/^version:[[:space:]]*//p' "$1" | head -1; fi
}

# Image refs a MANIFEST names (base + add-on packs), by TAG: docker load
# restores tags, never the pull-time digest.
manifest_image_refs() {
  sed -n 's/^  - //p' "$1" | sed 's/@sha256:[0-9a-f]*$//' | sed '/^$/d' | sort -u
}

# The part of a bundle version that orders releases: a tag (v0.9.0-rc1) as is,
# a dated build (2026.09.15-ge8ebc980) without its commit.
version_key() { printf '%s' "${1%%-g[0-9a-f]*}"; }

# Sets PREV_COMPOSE_DIR / PREV_ROOT / PREV_ENV / PREV_BUNDLE_DIR, or refuses.
upgrade_resolve_previous() {
  local cand="" dirs d here n=0 c
  here=$(canon_dir "$COMPOSE_DIR")
  if [ -n "$UPGRADE_FROM" ]; then
    d=$(canon_dir "$UPGRADE_FROM")
    for c in "$d/deployment/docker" "$d/NetOps_Observability/deployment/docker" "$d"; do
      if [ -f "$c/docker-compose.yml" ]; then cand="$c"; break; fi
    done
    [ -n "$cand" ] || die "--from '$UPGRADE_FROM' is not a Correlix install folder (no deployment/docker/docker-compose.yml under it)." \
      "Point --from at the previous bundle folder, or leave it out to find the install automatically."
  else
    if ! dirs=$(project_working_dirs); then
      die "Could not look for the existing Correlix install (docker ps failed: $(printf '%s' "$dirs" | tail -1))." \
        "Fix Docker access, or name the previous folder with --from DIR."
    fi
    while IFS= read -r d; do
      [ -n "$d" ] || continue
      [ "$(canon_dir "$d")" != "$here" ] || continue
      n=$((n + 1))
      cand=$(canon_dir "$d")
    done <<< "$dirs"
    if [ "$n" -eq 0 ]; then
      die "No existing Correlix install was found on this host to upgrade." \
"For a first install run:  $HERE/install-correlix.sh install
If the previous install's containers were removed, name its folder:
  $HERE/install-correlix.sh upgrade --from <previous bundle folder>"
    fi
    if [ "$n" -gt 1 ]; then
      die "More than one other folder owns Correlix containers on this host:
$dirs" "Name the install to upgrade:  $HERE/install-correlix.sh upgrade --from <folder>"
    fi
  fi
  PREV_COMPOSE_DIR=$(canon_dir "$cand")
  [ "$PREV_COMPOSE_DIR" != "$here" ] || die "That is this bundle's own install — there is nothing to upgrade from." \
    "To repair or re-run it:  $HERE/install-correlix.sh install"
  PREV_ROOT=$(dirname "$(dirname "$PREV_COMPOSE_DIR")")
  PREV_ENV="$PREV_COMPOSE_DIR/.env"
  PREV_BUNDLE_DIR=$(dirname "$PREV_ROOT")
  [ -f "$PREV_BUNDLE_DIR/MANIFEST" ] || PREV_BUNDLE_DIR=""
  [ -f "$PREV_ENV" ] || die "The install in $PREV_COMPOSE_DIR has no .env, so there are no settings to carry forward." \
    "If it was uninstalled, run a fresh install from this folder instead:  $HERE/install-correlix.sh install"
  [ -w "$PREV_COMPOSE_DIR" ] || die "$PREV_COMPOSE_DIR is not writable by $(id -un)." \
    "Run the upgrade as the user that installed Correlix."
  say "Current install: $PREV_COMPOSE_DIR"
}

# An earlier upgrade from this folder that stopped half-way is never repeated
# blindly: data/ may already have moved.
upgrade_refuse_if_interrupted() {
  [ -f "$UPGRADE_STATE_FILE" ] || return 0
  local st bk
  st=$(state_get "$UPGRADE_STATE_FILE" status)
  bk=$(state_get "$UPGRADE_STATE_FILE" backup_dir)
  case "$st" in
    applying|rolling-back|rollback-failed)
      die "An earlier upgrade from this folder did not finish (status: $st)." \
"Previous install: $(state_get "$UPGRADE_STATE_FILE" previous_compose_dir)
Backup taken before it: ${bk:-unknown}
Repeating it blindly could move data twice. Bring the previous install back with the
steps in ${bk:-the backup folder}/RESTORE.txt, then remove $UPGRADE_STATE_FILE and re-run." ;;
  esac
}

# This bundle folder must be clean: an upgrade carries settings and data INTO
# it and never merges with, or overwrites, what is already there.
upgrade_check_new_folder() {
  local src="$PREV_ROOT/data" dst="$ROOT/data" d
  [ ! -e "$ENV_FILE" ] || die "This bundle folder already has its own configuration: $ENV_FILE" \
    "An upgrade carries the current install's settings into a freshly extracted bundle folder. Use one."
  if [ -e "$dst" ] && { [ ! -d "$dst" ] || [ -n "$(ls -A -- "$dst" 2>/dev/null)" ]; }; then
    die "This bundle folder already has a data directory: $dst" \
      "An upgrade moves the current install's data here; it never merges or overwrites. Use a freshly extracted bundle folder."
  fi
  UPGRADE_HAS_DATA=0
  [ -d "$src" ] || return 0
  UPGRADE_HAS_DATA=1
  if [ "$(stat -c %d -- "$src")" != "$(stat -c %d -- "$ROOT")" ]; then
    die "The current install's data ($src) is on a different filesystem than this bundle ($ROOT)." \
      "The upgrade moves data/ with a rename, which is instant and cannot half-finish; across filesystems it would be a long copy. Extract the new bundle on the same disk as the current one, then re-run."
  fi
  for d in "$PREV_ROOT" "$ROOT" "$src"; do
    [ -w "$d" ] || die "Cannot move data/: $d is not writable by $(id -un)." \
      "Run the upgrade as the user that installed Correlix."
  done
}

upgrade_check_versions() {
  local pk nk
  UPGRADE_PREV_VERSION=""
  if [ -n "$PREV_BUNDLE_DIR" ]; then UPGRADE_PREV_VERSION=$(manifest_version "$PREV_BUNDLE_DIR/MANIFEST"); fi
  UPGRADE_NEW_VERSION=$(manifest_version "$BUNDLE_DIR/MANIFEST")
  say "Upgrading Correlix ${UPGRADE_PREV_VERSION:-<unknown version>} -> ${UPGRADE_NEW_VERSION:-<unknown version>}"
  if [ -z "$UPGRADE_PREV_VERSION" ] || [ -z "$UPGRADE_NEW_VERSION" ]; then
    warn "a version is unknown (no MANIFEST) — the downgrade check is skipped."
    return 0
  fi
  if [ "$UPGRADE_PREV_VERSION" = "$UPGRADE_NEW_VERSION" ]; then
    die "This bundle is the version already installed ($UPGRADE_NEW_VERSION)." \
      "Nothing to upgrade. To repair that install, re-run it in its own folder:  '$(installer_for_compose_dir "$PREV_COMPOSE_DIR")' install"
  fi
  pk=$(version_key "$UPGRADE_PREV_VERSION")
  nk=$(version_key "$UPGRADE_NEW_VERSION")
  # Only versions of one scheme are ordered (both tags, or both dated builds).
  if [ "$pk" != "$nk" ] && [ "${pk%%[0-9]*}" = "${nk%%[0-9]*}" ] \
     && [ "$(printf '%s\n%s\n' "$pk" "$nk" | sort -V | head -1)" = "$nk" ] \
     && [ "${CORRELIX_ALLOW_DOWNGRADE:-0}" != 1 ]; then
    die "This bundle ($UPGRADE_NEW_VERSION) is OLDER than the installed version ($UPGRADE_PREV_VERSION) — refusing to downgrade." \
      "A downgrade can meet data a newer version already migrated. Restore a backup taken on $UPGRADE_NEW_VERSION instead, or set CORRELIX_ALLOW_DOWNGRADE=1 only if support asked you to."
  fi
}

fs_free_kb() { df -Pk -- "$1" 2>/dev/null | awk 'NR == 2 {print $4}'; }

# Size of a data tree in KiB. Store directories belong to the containers'
# uids, so when this user cannot read all of it the tree is measured from
# inside a local image that is root in a READ-ONLY mount.
data_size_kb() {
  local out img
  if out=$(du -sk -- "$1" 2>/dev/null); then
    printf '%s' "${out%%[[:space:]]*}"
    return 0
  fi
  if img=$(purge_helper_image) \
     && out=$(timeout 600 docker run --rm --entrypoint sh -v "$1:/data:ro" "$img" -c 'du -sk /data' 2>&1); then
    printf '%s' "${out%%[[:space:]]*}"
    return 0
  fi
  return 1
}

# Free-space gate BEFORE the backup (§16.4: a real gate, not a skip).
upgrade_space_gate() { # BACKUP_BASE
  local base="$1" need_kb data_kb=0 free_kb tmp_dir tmp_free
  if [ -n "$UPGRADE_BACKUP_FILE" ]; then
    need_kb=65536  # the settings copy only
  else
    if [ "$UPGRADE_HAS_DATA" = 1 ]; then
      data_kb=$(data_size_kb "$PREV_ROOT/data") || die "Could not measure $PREV_ROOT/data to check there is room for the backup." \
"Nothing was changed. Take the backup yourself, then pass it in:
  sudo '$PREV_ROOT/scripts/backup.sh' /roomy/disk/correlix-pre-upgrade.tar.zst
  $HERE/install-correlix.sh upgrade --backup-file /roomy/disk/correlix-pre-upgrade.tar.zst"
      case "$data_kb" in ''|*[!0-9]*) die "Could not measure $PREV_ROOT/data (du said: $data_kb)." ;; esac
    fi
    need_kb=$((data_kb + UPGRADE_SPACE_MARGIN_KB))
  fi
  free_kb=$(fs_free_kb "$base")
  case "$free_kb" in ''|*[!0-9]*) die "Could not read the free space of $base (df failed)." ;; esac
  if [ -z "$UPGRADE_BACKUP_FILE" ]; then
    tmp_dir="${TMPDIR:-/tmp}"
    if [ "$(stat -c %d -- "$tmp_dir")" = "$(stat -c %d -- "$base")" ]; then
      need_kb=$((need_kb * 2))  # backup.sh stages a copy, then writes the artifact, on one filesystem
    else
      tmp_free=$(fs_free_kb "$tmp_dir")
      case "$tmp_free" in ''|*[!0-9]*) die "Could not read the free space of $tmp_dir (df failed)." ;; esac
      [ "$tmp_free" -ge "$need_kb" ] || die "Not enough free space in $tmp_dir for the backup's staging copy: $((tmp_free / 1024)) MB free, about $((need_kb / 1024)) MB needed." \
        "Nothing was changed. backup.sh stages the data there before compressing it. Free space, or set TMPDIR to a roomier filesystem, then re-run."
    fi
  fi
  [ "$free_kb" -ge "$need_kb" ] || die "Not enough free space for the pre-upgrade backup in $base: $((free_kb / 1024)) MB free, about $((need_kb / 1024)) MB needed." \
    "Nothing was changed. Free space there, or put the backup elsewhere with --backup-dir DIR (or pass an existing backup with --backup-file FILE)."
  ok "disk: room for the pre-upgrade backup in $base"
}

# A VERIFIED backup before anything is touched: the settings (.env, compose
# files, MANIFEST — never .env.snapshot / .env.damaged) checksummed and
# re-read, and the stores through the install's own backup.sh plus its
# --verify. Refuses, having changed nothing, when either cannot be proven.
upgrade_backup() {
  local base bk f rc out bscript="$PREV_ROOT/scripts/backup.sh"
  base="${UPGRADE_BACKUP_DIR:-$(dirname "$BUNDLE_DIR")}"
  mkdir -p -- "$base" || die "Cannot create the backup folder $base."
  base=$(canon_dir "$base")
  upgrade_space_gate "$base"
  bk="$base/correlix-upgrade-backup-$UPGRADE_STAMP"
  [ ! -e "$bk" ] || die "The backup folder $bk already exists." "Re-run in a moment (the name carries the time)."
  ( umask 077 && mkdir -p -- "$bk/config" ) || die "Cannot create the backup folder $bk."
  chmod 700 "$bk" "$bk/config"
  say "${BOLD}Backing up the current install before changing anything${RST} -> $bk"
  cp -p -- "$PREV_ENV" "$bk/config/.env" || die "Could not copy $PREV_ENV into the backup." "Nothing was changed."
  for f in "$PREV_COMPOSE_DIR"/*.yml "$PREV_COMPOSE_DIR"/*.yaml; do
    [ -f "$f" ] || continue
    cp -p -- "$f" "$bk/config/" || die "Could not copy ${f##*/} into the backup." "Nothing was changed."
  done
  if [ -n "$PREV_BUNDLE_DIR" ]; then
    cp -p -- "$PREV_BUNDLE_DIR/MANIFEST" "$bk/config/MANIFEST" || die "Could not copy the previous MANIFEST into the backup." "Nothing was changed."
  fi
  out=""
  if ! ( cd "$bk/config" && find . -maxdepth 1 -type f -printf '%P\0' | sort -z \
           | xargs -0 sha256sum -- > "$bk/config.sha256" ) \
     || ! out=$(cd "$bk/config" && sha256sum -c --quiet "$bk/config.sha256" 2>&1) \
     || ! cmp -s -- "$PREV_ENV" "$bk/config/.env"; then
    die "The settings backup could not be verified ($bk/config)${out:+: $out}." "Nothing was changed."
  fi
  ok "settings backed up and verified ($bk/config)"
  [ -f "$bscript" ] || die "The current install has no scripts/backup.sh, so its stores cannot be backed up and verified." \
    "Nothing was changed. An upgrade never starts without a verified backup."
  if [ -n "$UPGRADE_BACKUP_FILE" ]; then
    [ -f "$UPGRADE_BACKUP_FILE" ] || die "--backup-file $UPGRADE_BACKUP_FILE does not exist." "Nothing was changed."
    UPGRADE_BACKUP_ARTIFACT=$(canon_dir "$(dirname "$UPGRADE_BACKUP_FILE")")/$(basename "$UPGRADE_BACKUP_FILE")
    say "Using the store backup you supplied: $UPGRADE_BACKUP_ARTIFACT"
  else
    UPGRADE_BACKUP_ARTIFACT="$bk/correlix-pre-upgrade.tar.zst"
    say "Backing up the stores with $bscript (the stack keeps running meanwhile)..."
    rc=0
    timeout "${CORRELIX_UPGRADE_BACKUP_TIMEOUT_S:-14400}" bash "$bscript" "$UPGRADE_BACKUP_ARTIFACT" 5>&- 6>&- || rc=$?
    if [ "$rc" -ne 0 ]; then
      die "The pre-upgrade backup failed (backup.sh exit $rc), so the upgrade was not started." \
"Nothing was changed. The lines above name the failing component. If it is the sealed
custody material, set BACKUP_SEALED_PASSPHRASE (docs/runbooks/backup-restore.md) and
re-run. Or take the backup as root and pass it in:
  sudo '$bscript' /roomy/disk/correlix-pre-upgrade.tar.zst
  $HERE/install-correlix.sh upgrade --backup-file /roomy/disk/correlix-pre-upgrade.tar.zst"
    fi
  fi
  rc=0
  out=$(timeout 1800 bash "$bscript" --verify "$UPGRADE_BACKUP_ARTIFACT" 2>&1 5>&- 6>&-) || rc=$?
  if [ "$rc" -ne 0 ]; then
    printf '%s\n' "$out" | tail -5 | redact_log_lines | sed 's/^/    /'
    die "The pre-upgrade backup could not be verified (backup.sh --verify exit $rc): $UPGRADE_BACKUP_ARTIFACT" \
      "Nothing was changed. An upgrade never starts without a backup proven readable."
  fi
  ok "store backup verified: $UPGRADE_BACKUP_ARTIFACT"
  UPGRADE_BACKUP_PATH="$bk"
}

# Protect every image of the previous version for a rollback BEFORE the new
# bundle's `docker load` moves tags such as netops-api:latest onto new images:
# each gets a correlix-rollback:<stamp>-NNN tag, and ref|id|tag is recorded.
upgrade_preserve_images() {
  local list="$UPGRADE_BACKUP_PATH/rollback-images.txt" ps_out refs ref id keep n=0 missing="" out
  if ! ps_out=$(timeout 60 docker ps -a --filter "label=com.docker.compose.project=$COMPOSE_PROJECT" --format '{{.Image}}' 2>&1); then
    die "Could not list the current install's container images (docker ps: $(printf '%s' "$ps_out" | tail -1))." \
      "Nothing was changed except the backup in $UPGRADE_BACKUP_PATH."
  fi
  refs=$( { if [ -n "$PREV_BUNDLE_DIR" ]; then manifest_image_refs "$PREV_BUNDLE_DIR/MANIFEST"; fi
            printf '%s\n' "$ps_out" | sed 's/@sha256:[0-9a-f]*$//'; } | sed '/^$/d; /^sha256:/d' | sort -u )
  ( umask 077 && : > "$list" ) || die "Cannot write $list." "Nothing was changed except the backup in $UPGRADE_BACKUP_PATH."
  while IFS= read -r ref; do
    [ -n "$ref" ] || continue
    # stderr is docker's "No such image" for a ref this host never loaded
    # (an add-on pack that was not enabled): inspected, genuine noise here.
    if ! id=$(timeout 60 docker image inspect --format '{{.Id}}' "$ref" 2>/dev/null); then
      missing="$missing $ref"
      continue
    fi
    n=$((n + 1))
    keep="correlix-rollback:$UPGRADE_STAMP-$(printf '%03d' "$n")"
    if ! out=$(timeout 60 docker tag "$id" "$keep" 2>&1); then
      die "Could not protect image $ref for a rollback (docker tag: $out)." \
        "Nothing was changed except the backup in $UPGRADE_BACKUP_PATH."
    fi
    printf '%s|%s|%s\n' "$ref" "$id" "$keep" >> "$list" || die "Cannot write $list."
  done <<< "$refs"
  [ "$n" -gt 0 ] || die "None of the current install's images is on this host, so a rollback could not restore it." \
    "Nothing was changed except the backup in $UPGRADE_BACKUP_PATH."
  if [ -n "$missing" ]; then warn "not on this host (not needed for a rollback):$missing"; fi
  ok "$n image(s) of the current version kept for a rollback (tags correlix-rollback:$UPGRADE_STAMP-*)"
}

upgrade_restore_image_tags() {
  local list="$UPGRADE_BACKUP_PATH/rollback-images.txt" ref id keep out
  TAG_PROBLEMS=""
  while IFS='|' read -r ref id keep; do
    [ -n "$ref" ] || continue
    if ! out=$(timeout 60 docker tag "$id" "$ref" 2>&1); then
      TAG_PROBLEMS="$TAG_PROBLEMS
  - could not restore image tag $ref -> $id (kept as $keep): $out"
    fi
  done < "$list"
  [ -z "$TAG_PROBLEMS" ]
}

# The manual way back, printed on a failed rollback and kept in the backup.
upgrade_restore_steps() {
  cat <<EOF
cd '$COMPOSE_DIR' && docker compose down --remove-orphans
cd '$PREV_COMPOSE_DIR' && docker compose down --remove-orphans
[ -d '$ROOT/data' ] && mv -T '$ROOT/data' '$PREV_ROOT/data'    # only if data/ is still in the new folder
[ -f '$PREV_ENV' ] || cp -p '$UPGRADE_BACKUP_PATH/config/.env' '$PREV_ENV'
while IFS='|' read -r ref id keep; do docker tag "\$id" "\$ref"; done < '$UPGRADE_BACKUP_PATH/rollback-images.txt'
'$PREV_ROOT/scripts/restore.sh' '$UPGRADE_BACKUP_ARTIFACT'    # ONLY if the data itself is damaged: it overwrites data/
cd '$PREV_COMPOSE_DIR' && docker compose up -d
EOF
}

# Settings carried forward: .env byte-for-byte (never regenerated, never the
# .env.snapshot / .env.damaged siblings), plus any overlay the .env's
# COMPOSE_FILE chain names that this bundle does not ship, and an operator's
# docker-compose.override.yml.
upgrade_carry_settings() {
  local tmp="$ENV_FILE.upgrade.tmp.$$" chain f parts=()
  if ! ( umask 077 && cp -- "$PREV_ENV" "$tmp" ) || ! mv -f -- "$tmp" "$ENV_FILE"; then
    rm -f -- "$tmp"
    return 1
  fi
  chain=$(prev_env_get COMPOSE_FILE)
  IFS=: read -ra parts <<< "$chain"
  parts+=(docker-compose.override.yml)
  for f in "${parts[@]}"; do
    case "$f" in ''|*/*) continue ;; esac
    if [ ! -e "$COMPOSE_DIR/$f" ] && [ -f "$PREV_COMPOSE_DIR/$f" ]; then
      cp -p -- "$PREV_COMPOSE_DIR/$f" "$COMPOSE_DIR/$f" || return 1
      say "  carried $f from the current install (this bundle does not ship it)"
    fi
  done
  ok "settings carried forward (.env unchanged — no secret was regenerated)"
}

# Every step after the first change. errexit is suspended in here (the caller
# tests the result), so each step checks and names its own failure.
upgrade_apply() {
  local running
  say ""
  say "${BOLD}Stopping the current install${RST} ($PREV_COMPOSE_DIR)..."
  if ! (cd "$PREV_COMPOSE_DIR" && timeout "$UPGRADE_COMPOSE_TIMEOUT_S" docker compose down --remove-orphans); then
    UPGRADE_FAIL_CAUSE="could not stop the current install (docker compose down in $PREV_COMPOSE_DIR failed — see above)"
    return 1
  fi
  if ! running=$(project_running_ids); then
    UPGRADE_FAIL_CAUSE="could not confirm the current install stopped (docker ps failed)"
    return 1
  fi
  if [ -n "$running" ]; then
    UPGRADE_FAIL_CAUSE="containers of the current install are still running after it was stopped: $(printf '%s' "$running" | tr '\n' ' ')"
    return 1
  fi
  if [ "$UPGRADE_HAS_DATA" = 1 ]; then
    if [ -d "$ROOT/data" ] && ! rmdir -- "$ROOT/data"; then
      UPGRADE_FAIL_CAUSE="could not clear the empty $ROOT/data before moving the data in"
      return 1
    fi
    if ! mv -T -- "$PREV_ROOT/data" "$ROOT/data"; then
      UPGRADE_FAIL_CAUSE="could not move data/ from $PREV_ROOT to $ROOT"
      return 1
    fi
    DATA_MOVED=1
    ok "data moved into $ROOT/data"
  fi
  ENV_CARRIED=1
  if ! upgrade_carry_settings; then
    UPGRADE_FAIL_CAUSE="could not carry the settings (.env) into $ENV_FILE"
    return 1
  fi
  say ""
  say "${BOLD}Installing ${UPGRADE_NEW_VERSION:-the new version} from this bundle${RST}"
  # Exactly as cmd_install runs it: unbuffered, no terminal fds, lock fd 9 inherited.
  if ! PYTHONUNBUFFERED=1 python3 -u "$ROOT/scripts/install.py" "${INSTALL_ARGS[@]}" 5>&- 6>&-; then
    UPGRADE_FAIL_CAUSE="the new version's installer (install.py) failed — see the lines above"
    return 1
  fi
  if ! wait_healthy; then
    UPGRADE_FAIL_CAUSE="the upgraded stack did not become healthy and stable (see the named services above)"
    return 1
  fi
}

# Put the previous install back, check it is stable, report both results,
# and exit: 4 = rolled back, 5 = the rollback failed too.
upgrade_rollback() {
  local cause="$1" problems="" running
  state_note status rolling-back
  say ""
  say "${RED}${BOLD}UPGRADE FAILED:${RST} $cause"
  say "${BOLD}Rolling back to the previous install${RST} ($PREV_COMPOSE_DIR)..."
  if [ "$ENV_CARRIED" = 1 ]; then
    say "  stopping the new version's containers..."
    if ! (cd "$COMPOSE_DIR" && timeout "$UPGRADE_COMPOSE_TIMEOUT_S" docker compose down --remove-orphans); then
      problems="$problems
  - could not stop the new version's containers (docker compose down in $COMPOSE_DIR failed)"
    fi
  fi
  if [ "$DATA_MOVED" = 1 ]; then
    if ! running=$(project_running_ids) || [ -n "$running" ]; then
      problems="$problems
  - containers are still running (or docker could not say), so data/ was NOT moved back; it is in $ROOT/data"
    elif mv -T -- "$ROOT/data" "$PREV_ROOT/data"; then
      DATA_MOVED=0
      ok "data moved back to $PREV_ROOT/data"
    else
      problems="$problems
  - could not move data/ back from $ROOT/data to $PREV_ROOT/data"
    fi
  fi
  if [ "$ENV_CARRIED" = 1 ] && [ -e "$ENV_FILE" ]; then
    if mv -f -- "$ENV_FILE" "$ENV_FILE.upgrade-failed-$UPGRADE_STAMP"; then
      ENV_CARRIED=0
    else
      problems="$problems
  - could not set aside $ENV_FILE (this folder still looks installed)"
    fi
  fi
  if upgrade_restore_image_tags; then
    ok "previous image tags restored"
  else
    problems="$problems$TAG_PROBLEMS"
  fi
  if [ -z "$problems" ]; then
    say "  starting the previous version again..."
    if ! (cd "$PREV_COMPOSE_DIR" && timeout "$UPGRADE_COMPOSE_TIMEOUT_S" docker compose up -d); then
      problems="$problems
  - docker compose up -d in $PREV_COMPOSE_DIR failed (see above)"
    elif ! ( COMPOSE_DIR="$PREV_COMPOSE_DIR" ENV_FILE="$PREV_ENV" wait_healthy ); then
      problems="$problems
  - the previous version started but did not pass the stability check (see the named services above)"
    fi
  else
    problems="$problems
  - the previous version was NOT started: the steps above must succeed first"
  fi
  say ""
  if [ -z "$problems" ]; then
    state_note status rolled-back
    say "${RED}${BOLD}The upgrade did not complete and was rolled back.${RST}"
    say "  Why it failed:  $cause"
    say "  Rollback:       the previous version (${UPGRADE_PREV_VERSION:-unknown}) is running again from"
    say "                  $PREV_COMPOSE_DIR and passed the stability check."
    say "  Backup taken before the upgrade (kept): $UPGRADE_BACKUP_PATH"
    say "  Full log: ${INSTALL_LOG:-}"
    say "  Fix the cause above, then run the upgrade again from this folder."
    cx_result fail
    exit 4
  fi
  state_note status rollback-failed
  say "${RED}${BOLD}################################################################${RST}"
  say "${RED}${BOLD}  THE UPGRADE FAILED AND THE AUTOMATIC ROLLBACK ALSO FAILED${RST}"
  say "${RED}${BOLD}################################################################${RST}"
  say "  Why the upgrade failed:  $cause"
  say "  What the rollback could not do:$problems"
  say ""
  say "  A verified backup of the install as it was before the upgrade: $UPGRADE_BACKUP_PATH"
  say "  Restore by hand (also in $UPGRADE_BACKUP_PATH/RESTORE.txt):"
  upgrade_restore_steps | sed 's/^/    /'
  say "  Full log: ${INSTALL_LOG:-}"
  cx_result fail
  exit 5
}

cmd_upgrade() {
  [ "$MODE" = "bundle" ] || die "upgrade runs from a NEW Correlix bundle folder." \
    "Extract the new bundle next to the current one and run its installer:  ./install-correlix.sh upgrade"
  [ -z "$CONFIG_FILE" ] || die "--config is not used by upgrade: the installed configuration is carried forward unchanged."
  UPGRADE_IN_PROGRESS=1
  UPGRADE_STAMP=$(date -u +%Y%m%dT%H%M%SZ)
  start_install_log
  acquire_bundle_lock upgrade
  acquire_install_lock upgrade
  upgrade_resolve_previous
  # The previous install is ours for the whole run too: nobody may enable,
  # uninstall or re-install it while its data is being moved.
  take_lock 7 "$PREV_COMPOSE_DIR/.install.lock" upgrade
  cx_stage preflight "checking this host" start
  # Preflight sees the CURRENT install's .env: the ports it publishes are held
  # by the very stack being upgraded, not by a foreign process.
  if ! ( ENV_FILE="$PREV_ENV" preflight ); then
    cx_stage preflight "checking this host" fail "host preflight failed (see messages above)"
    cx_result fail
    exit 1
  fi
  cx_stage preflight "checking this host" ok
  verify_bundle
  acquire_install_lock upgrade
  upgrade_refuse_if_interrupted
  upgrade_check_new_folder
  upgrade_check_versions

  UI_PORT=$(prev_env_get BASE_PORT)
  UI_PORT=${UI_PORT:-8000}
  assemble_install_args
  local tls=no
  case "$(prev_env_get COMPOSE_FILE)" in *compose.tls.yml*) tls=yes ;; esac
  INSTALL_ARGS+=(--tls "$tls" --bootstrap-docker no)

  upgrade_backup
  upgrade_preserve_images
  upgrade_restore_steps > "$UPGRADE_BACKUP_PATH/RESTORE.txt" \
    || die "Cannot write $UPGRADE_BACKUP_PATH/RESTORE.txt." "Nothing was changed except the backup."
  rm -f -- "$UPGRADE_STATE_FILE"
  if ! { state_set status applying && state_set started_utc "$(utc_now)" \
         && state_set previous_compose_dir "$PREV_COMPOSE_DIR" \
         && state_set previous_version "${UPGRADE_PREV_VERSION:-unknown}" \
         && state_set new_version "${UPGRADE_NEW_VERSION:-unknown}" \
         && state_set backup_dir "$UPGRADE_BACKUP_PATH"; }; then
    die "Cannot record the upgrade state in $UPGRADE_STATE_FILE." "Nothing was changed except the backup in $UPGRADE_BACKUP_PATH."
  fi

  if ! upgrade_apply; then
    upgrade_rollback "$UPGRADE_FAIL_CAUSE"
  fi

  # The previous folder must no longer be able to operate the shared-name
  # project: its install/uninstall would act on the upgraded containers.
  if ! mv -f -- "$PREV_ENV" "$PREV_ENV.upgraded-$UPGRADE_STAMP"; then
    warn "could not set aside $PREV_ENV — do NOT run install or uninstall from $PREV_ROOT: it would act on the upgraded containers."
  fi
  state_note status upgraded
  state_note finished_utc "$(utc_now)"
  verify_admin_login
  say ""
  say "${GREEN}${BOLD}────────────────────────────────────────────────${RST}"
  say "${GREEN}${BOLD}  Correlix upgraded: ${UPGRADE_PREV_VERSION:-unknown} -> ${UPGRADE_NEW_VERSION:-unknown}${RST}"
  say "${GREEN}${BOLD}────────────────────────────────────────────────${RST}"
  say "  Open the UI:   ${BOLD}$(dashboard_url)${RST}"
  say "  Sign-in is unchanged: same accounts and passwords as before."
  say "  Backup taken before the upgrade: $UPGRADE_BACKUP_PATH"
  say "  The previous version's images are kept, so you can still go back. When satisfied:"
  say "    $HERE/install-correlix.sh cleanup-old-images             (lists what would go)"
  say "    $HERE/install-correlix.sh cleanup-old-images --confirm   (removes it)"
  say "  $PREV_ROOT no longer holds an install (its .env was set aside as .env.upgraded-$UPGRADE_STAMP)."
  say "  Delete that folder once you no longer need it."
  cx_result ok "$(dashboard_url)" "$(env_get ADMIN_USERNAME || echo admin)"
}

# Remove ONLY named refs of the previous bundle — its MANIFEST and the rollback
# tags `upgrade` recorded — that no container on this host uses and this
# bundle does not name. No prune of any kind: docker is never asked to decide
# what is unused.
cmd_cleanup_old_images() {
  acquire_install_lock cleanup-old-images
  [ -f "$UPGRADE_STATE_FILE" ] || die "No upgrade is recorded for this install ($UPGRADE_STATE_FILE is missing)." \
    "cleanup-old-images removes only what a completed 'install-correlix.sh upgrade' left behind, run from the folder that upgrade ran in. Nothing was removed."
  local st bk list prev_manifest current="" ids used="" candidates ref id out n=0 failed=""
  st=$(state_get "$UPGRADE_STATE_FILE" status)
  [ "$st" = "upgraded" ] || die "The last upgrade recorded here did not complete (status: ${st:-unknown}), so the previous version's images are still needed." \
    "Nothing was removed."
  bk=$(state_get "$UPGRADE_STATE_FILE" backup_dir)
  list="$bk/rollback-images.txt"
  prev_manifest="$bk/config/MANIFEST"
  [ -f "$list" ] || die "The rollback image list $list is missing." \
    "Nothing was removed: without it this command cannot tell which images belonged to the previous version."
  if [ -n "$BUNDLE_DIR" ] && [ -f "$BUNDLE_DIR/MANIFEST" ]; then
    current=$(manifest_image_refs "$BUNDLE_DIR/MANIFEST")
  fi
  if ! ids=$(timeout 60 docker ps -aq 2>&1); then
    die "Could not list this host's containers (docker ps: $(printf '%s' "$ids" | tail -1))." \
      "Nothing was removed: an image is removed only when it is proven unused."
  fi
  if [ -n "$ids" ]; then
    # shellcheck disable=SC2086  # deliberate word-split of the container id list
    if ! used=$(timeout 120 docker inspect --format '{{.Image}}' $ids 2>&1); then
      die "Could not read which images this host's containers use (docker inspect: $(printf '%s' "$used" | tail -1))." \
        "Nothing was removed: an image is removed only when it is proven unused. Re-run in a moment."
    fi
  fi
  candidates=$( { if [ -f "$prev_manifest" ]; then manifest_image_refs "$prev_manifest"; fi
                  awk -F'|' 'NF >= 3 && $3 != "" {print $3}' "$list"; } | sed '/^$/d' | sort -u )
  say "Images of the previous version ($(state_get "$UPGRADE_STATE_FILE" previous_version)):"
  while IFS= read -r ref; do
    [ -n "$ref" ] || continue
    case $'\n'"$current"$'\n' in *$'\n'"$ref"$'\n'*)
      say "  keep     $ref   (this version uses it too)"; continue ;;
    esac
    # stderr is "No such image" for a ref already gone: inspected, noise here.
    if ! id=$(timeout 60 docker image inspect --format '{{.Id}}' "$ref" 2>/dev/null); then
      say "  gone     $ref"
      continue
    fi
    case $'\n'"$used"$'\n' in *$'\n'"$id"$'\n'*)
      say "  keep     $ref   (a container uses it)"; continue ;;
    esac
    if [ "$CONFIRM" != 1 ]; then
      say "  remove   $ref"
      n=$((n + 1))
      continue
    fi
    if out=$(timeout 300 docker rmi "$ref" 2>&1); then
      say "  removed  $ref"
      n=$((n + 1))
    else
      failed="$failed
  $ref: $(printf '%s' "$out" | tail -1)"
    fi
  done <<< "$candidates"
  if [ "$CONFIRM" != 1 ]; then
    say ""
    say "Nothing was removed. To remove the $n image(s) marked 'remove':"
    say "  $HERE/install-correlix.sh cleanup-old-images --confirm"
    return 0
  fi
  if [ -n "$failed" ]; then
    die "$n image(s) removed, but these could not be:$failed" "Nothing else was touched. Re-run after checking what still uses them (docker ps -a)."
  fi
  state_note images_removed_utc "$(utc_now)"
  ok "$n image(s) of the previous version removed — rolling back to it now needs its bundle again."
}

# Read-only health report (FMEA 2026-09-15 §4.6). No lock is taken on purpose:
# a doctor must be able to look at an install that is running, or at one whose
# installer died holding the lock. The report module only reads, bounds every
# docker call, and never prints a secret value. Its exit code passes through:
# 0 healthy · 1 problems found · 2 could not assess. Messages from this wrapper
# go to stderr so `doctor --json` keeps stdout pure JSON.
cmd_doctor() {
  local report="$ROOT/scripts/install_doctor.py" rc=0
  local jflag=()
  if [ ! -f "$report" ]; then
    printf 'doctor: %s is missing — this bundle is not unpacked yet, so there is no install to examine.\n' "$report" >&2
    exit 2
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    printf 'doctor: python3 is missing, so the report cannot run (prepare the host first: sudo ./prepare-host.sh).\n' >&2
    exit 2
  fi
  if [ "$DOCTOR_JSON" = 1 ]; then
    jflag=(--json)
  fi
  timeout 300 python3 -B "$report" --root "$ROOT" --bundle-dir "$HERE" ${jflag[@]+"${jflag[@]}"} || rc=$?
  case "$rc" in
    0|1|2) exit "$rc" ;;
    124)   printf 'doctor: the report did not finish within 300 s — could not assess.\n' >&2; exit 2 ;;
    *)     printf 'doctor: the report itself failed (exit %s) — could not assess.\n' "$rc" >&2; exit 2 ;;
  esac
}

# ---------- setup console (menu navigation) ------------------------------
menu_state() {
  if [ ! -f "$ENV_FILE" ]; then echo "not installed"
  else
    local total run
    total=$(compose ps --format '{{.Service}}' 2>/dev/null | wc -l)
    if [ "$total" -eq 0 ]; then echo "installed, stopped"
    else run=$(compose ps --format '{{.State}}' 2>/dev/null | grep -c running || true)
         echo "running ($run/$total services up)"; fi
  fi
}

pause() { printf '\n%s' "${DIM}Press Enter to return to the menu...${RST}"; read -r _ || true; }

pick_addon() { # sets PICKED or empty
  PICKED=""
  say ""; say "  1) log-search-ui     power-user log forensics UI"
  say "  2) self-monitoring   Grafana + container/host metrics"
  say "  3) sso               single sign-on — broker SAML / LDAP / OIDC (Keycloak)"
  printf '%s' "  Add-on [1-3, Enter to cancel]: "
  read -r a || true
  case "${a:-}" in
    1) PICKED="log-search-ui" ;;
    2) PICKED="self-monitoring" ;;
    3) PICKED="sso" ;;
  esac
}

cmd_menu() {
  while true; do
    clear 2>/dev/null || true
    say "${BOLD}┌──────────────────────────────────────────────┐${RST}"
    say "${BOLD}│  Correlix Setup                              │${RST}"
    say "${BOLD}└──────────────────────────────────────────────┘${RST}"
    say "  State: $(menu_state)"
    say ""
    say "  1) Prepare this host        (runs: sudo ./prepare-host.sh)"
    say "  2) Install Correlix"
    say "  3) Service health"
    say "  4) Logs"
    say "  5) Enable add-on"
    say "  6) Disable add-on"
    say "  7) Stop        8) Start"
    say "  9) Reset demo data"
    say "  0) Uninstall"
    say "  q) Quit"
    say ""
    printf '%s' "  Choose: "
    read -r choice || exit 0
    case "${choice:-}" in
      1) local prep="$HERE/prepare-host.sh"; [ -x "$prep" ] || prep="$ROOT/scripts/prepare-host.sh"
         ( sudo "$prep" ) || true; pause ;;
      2) ( cmd_install ) || true; pause ;;
      3) ( friendly_status ) || true; pause ;;
      4) printf '%s' "  Service name (Enter for all): "; read -r svc || true
         ( if [ -n "${svc:-}" ]; then compose logs --tail 200 "$svc"; else compose logs --tail 80; fi ) || true; pause ;;
      5) pick_addon; [ -n "$PICKED" ] && { ADDON_ARG="$PICKED"; ( cmd_enable ) || true; }; pause ;;
      6) pick_addon; [ -n "$PICKED" ] && { ADDON_ARG="$PICKED"; ( cmd_disable ) || true; }; pause ;;
      7) ( compose stop && ok "Correlix stopped (data kept)." ) || true; pause ;;
      8) ( compose start && ok "Correlix starting." ) || true; pause ;;
      9) printf '%s' "  This wipes all collected data (login kept). Type yes to confirm: "
         read -r conf || true
         if [ "${conf:-}" = "yes" ]; then ( cmd_reset_demo ) || true; else say "  cancelled."; fi
         pause ;;
      0) printf '%s' "  Remove Correlix containers? Type yes to confirm: "
         read -r conf || true
         if [ "${conf:-}" = "yes" ]; then ( cmd_uninstall ) || true; else say "  cancelled."; fi
         pause ;;
      q|Q) exit 0 ;;
      *) : ;;
    esac
  done
}

# ---------- graphical installer launch -----------------------------------
# The GUI is served on a MANAGEMENT ADDRESS the operator picks, over HTTPS by
# default. Both questions are asked here, in the terminal, because that is the
# one channel we know is already trusted: the operator is sitting in it.
#
# The address list comes from `correlix-setup --list-ips` (iface<TAB>ip) rather
# than from parsing `ip addr`, so the answer cannot disagree with the SANs the
# binary puts in its own certificate, and no extra tool has to exist on PATH.
setup_bin() {
  local bin="$BUNDLE_DIR/correlix-setup"
  [ -n "$BUNDLE_DIR" ] && [ -x "$bin" ] && { printf '%s' "$bin"; return 0; }
  bin="$HERE/correlix-setup"
  [ -x "$bin" ] && { printf '%s' "$bin"; return 0; }
  return 1
}

cmd_gui() {
  local bin
  bin=$(setup_bin) || die "correlix-setup binary missing from this bundle." \
    "Re-download the bundle, or use the terminal installer: ./install-correlix.sh install"

  local ips=() ifaces=() line iface ip iplist
  # Never swallow the failure (§16.1): if the binary cannot enumerate the
  # host's interfaces, say so by name instead of silently offering loopback.
  if ! iplist="$("$bin" -list-ips)"; then
    die "correlix-setup could not list this host's network interfaces." \
        "Run '$bin -list-ips' to see the error, or install from the terminal: ./install-correlix.sh install"
  fi
  while IFS=$'\t' read -r iface ip; do
    [ -n "${ip:-}" ] || continue
    ifaces+=("$iface"); ips+=("$ip")
  done <<< "$iplist"

  local chosen=""
  if [ "${#ips[@]}" -eq 0 ]; then
    warn "No management interface with an IPv4 address was found — using localhost."
    chosen="127.0.0.1"
  elif [ ! -t 0 ] || [ ! -t 1 ]; then
    chosen="${ips[0]}"
    say "Management address: ${chosen} (${ifaces[0]}) — first non-loopback interface."
  else
    local i=1
    say ""
    say "${BOLD}Which address should the installer be reachable on?${RST}"
    for i in "${!ips[@]}"; do
      printf '  %d) %-10s %s%s\n' "$((i + 1))" "${ifaces[$i]}" "${ips[$i]}" \
        "$([ "$i" -eq 0 ] && printf ' %s(default)%s' "$DIM" "$RST")"
    done
    printf '  %d) %-10s %s\n' "$(( ${#ips[@]} + 1 ))" "loopback" "127.0.0.1 (this machine only)"
    printf '\n  Choose [1-%d, Enter for 1]: ' "$(( ${#ips[@]} + 1 ))"
    read -r line || true
    line="${line:-1}"
    case "$line" in
      ''|*[!0-9]*) die "Not a number: $line" ;;
    esac
    if [ "$line" -ge 1 ] && [ "$line" -le "${#ips[@]}" ]; then
      chosen="${ips[$((line - 1))]}"
    elif [ "$line" -eq $(( ${#ips[@]} + 1 )) ]; then
      chosen="127.0.0.1"
    else
      die "Choice out of range: $line"
    fi
  fi

  # HTTPS is the default; HTTP has to be typed out in full, and is warned twice
  # (here, and again by the binary at launch).
  local scheme_arg=()
  if [ -t 0 ] && [ -t 1 ]; then
    say ""
    say "${BOLD}How should the installer be served?${RST}"
    say "  1) HTTPS ${DIM}(default — self-signed certificate, fingerprint printed below)${RST}"
    say "  2) HTTP  ${DIM}(no encryption — trusted isolated network only)${RST}"
    printf '\n  Choose [1-2, Enter for 1]: '
    read -r line || true
    case "${line:-1}" in
      1|'') : ;;
      2) warn "HTTP selected: the one-time token and everything you type will cross the network unencrypted."
         warn "Host preparation (the sudo step) stays disabled in this mode — run 'sudo ./prepare-host.sh' here instead."
         printf '  Type %shttp%s to confirm: ' "$BOLD" "$RST"
         read -r line || true
         [ "${line:-}" = "http" ] || die "Not confirmed — re-run and choose HTTPS."
         scheme_arg=(-http) ;;
      *) die "Not a valid choice: $line" ;;
    esac
  fi

  exec "$bin" -bundle "${BUNDLE_DIR:-$HERE}" -addr "$chosen:8800" "${scheme_arg[@]}"
}

# ---------- first-run chooser (GUI or CLI) --------------------------------
# The very first question a customer is asked. Everything downstream is the
# path they picked; both paths run the SAME install-correlix.sh install engine,
# so neither can drift ahead of the other.
cmd_choose() {
  say ""
  say "${BOLD}┌──────────────────────────────────────────────┐${RST}"
  say "${BOLD}│  Correlix installer                          │${RST}"
  say "${BOLD}└──────────────────────────────────────────────┘${RST}"
  say ""
  say "  How would you like to install Correlix?"
  say ""
  say "  1) ${BOLD}Graphical${RST}  — guided wizard in your browser ${DIM}(recommended)${RST}"
  say "  2) ${BOLD}Terminal${RST}   — text menu, right here"
  say "  q) Quit"
  say ""
  printf '  Choose [1-2, Enter for 1]: '
  local pick
  read -r pick || exit 0
  case "${pick:-1}" in
    1|'') cmd_gui ;;
    2)    cmd_menu ;;
    q|Q)  exit 0 ;;
    *)    die "Not a valid choice: $pick" ;;
  esac
}

case "$CMD" in
  menu)            cmd_choose ;;
  console)         cmd_menu ;;
  gui)             cmd_gui ;;
  install)         cmd_install ;;
  status)          friendly_status ;;
  logs)            [ -f "$ENV_FILE" ] || die "Correlix is not installed here yet."
                   if [ -n "$LOG_SVC" ]; then compose logs --tail 200 "$LOG_SVC"
                   else compose logs --tail 80; fi ;;
  stop)            compose stop; ok "Correlix stopped (data kept). Start again: ./install-correlix.sh start" ;;
  start)           compose start; ok "Correlix starting — check with: ./install-correlix.sh status" ;;
  uninstall)       cmd_uninstall ;;
  reset-demo-data) cmd_reset_demo ;;
  enable)          cmd_enable ;;
  support-bundle)  cmd_support_bundle ;;
  doctor)          cmd_doctor ;;
  disable)         cmd_disable ;;
  upgrade)         cmd_upgrade ;;
  cleanup-old-images) cmd_cleanup_old_images ;;
esac
