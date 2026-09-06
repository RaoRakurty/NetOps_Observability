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
#     ./install-correlix.sh reset-demo-data
#     ./install-correlix.sh enable  <add-on>    log-search-ui | self-monitoring
#     ./install-correlix.sh disable <add-on>
#     ./install-correlix.sh support-bundle [--out DIR] [--since 24h] [--no-logs]
#         Collect a REDACTED diagnostic bundle (compose state, container logs,
#         health, store/bus summaries) as one .tar.zst to send to support.
#         Secrets are stripped; read its MANIFEST before sending.
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
env_get() { sed -n "s/^$1=//p" "$ENV_FILE" 2>/dev/null | head -1; }

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
# support-bundle passthrough (rejected for every other subcommand).
SB_ARGS=()
if [ $# -gt 0 ]; then
  case "$1" in
    install|status|logs|stop|start|uninstall|reset-demo-data|enable|disable|menu|console|gui|support-bundle) CMD="$1"; shift ;;
    -*) : ;;  # bare options → install
    *) die "Unknown command: $1" "Commands: install status logs stop start uninstall reset-demo-data enable disable support-bundle gui console menu" ;;
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
    --lab)            LAB=1; shift ;;
    --purge)          PURGE=1; shift ;;
    -h|--help)        sed -n '3,36p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) if [ "$CMD" = "logs" ] && [ -z "$LOG_SVC" ]; then LOG_SVC="$1"; shift
       else die "Unknown option: $1" "See ./install-correlix.sh --help"; fi ;;
  esac
done

# ---------- preflight checks (install only) ----------------------------------
port_in_use() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && { exec 3>&-; return 0; } || return 1; }

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

  local free_gb
  free_gb=$(df -BG --output=avail "$(docker info -f '{{.DockerRootDir}}' 2>/dev/null || echo /var/lib/docker)" 2>/dev/null | tail -1 | tr -dc '0-9')
  free_gb=${free_gb:-0}
  if [ "$free_gb" -lt 20 ]; then
    die "Only ${free_gb} GB free disk for Docker; Correlix needs at least 40 GB (100 GB recommended)."
  elif [ "$free_gb" -lt 40 ]; then
    warn "${free_gb} GB free disk — enough to start an evaluation; 100 GB is recommended."
  else
    ok "disk: ${free_gb} GB free"
  fi

  if [ ! -f "$ENV_FILE" ] && port_in_use "$UI_PORT"; then
    die "Port $UI_PORT is already in use. Correlix's web UI needs this port." \
      "Either stop the service using it, or install on another port:
  ./install-correlix.sh install --ui-port 9443"
  fi

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

verify_bundle() {
  cd "$BUNDLE_DIR"
  # Re-join a split image archive (release assets are capped at 2 GiB/file).
  local part0
  part0=$(compgen -G "correlix-images-*.tar.zst.part00" | head -1 || true)
  if [ -n "$part0" ]; then
    local joined="${part0%.part00}"
    if [ ! -f "$joined" ]; then
      say "Joining image archive parts..."
      cat "${joined}".part* > "$joined"
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
    say "Extracting Correlix..."
    tar -xzf correlix-source-*.tar.gz
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
  code=$(curl -s -o /dev/null -w '%{http_code}' -m 10 \
    -H 'Content-Type: application/json' -d "$payload" \
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

wait_healthy() {
  say "Waiting for services to become healthy (this can take a few minutes)..."
  local deadline=$(( $(date +%s) + 420 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    local total unhealthy
    total=$(compose ps --format '{{.Service}}' 2>/dev/null | wc -l)
    unhealthy=$(compose ps --format '{{.Service}}|{{.State}}|{{.Health}}' 2>/dev/null \
      | awk -F'|' '$1 ~ /-init$/ {next} $2!="running" || $3=="unhealthy" || $3=="starting" {print}' | wc -l)
    if [ "$total" -gt 0 ] && [ "$unhealthy" -eq 0 ] \
       && curl -fsS -m 5 -o /dev/null "http://127.0.0.1:${UI_PORT}/" 2>/dev/null; then
      # Require STABILITY, not a lucky sample: a service can pass its first
      # seconds and then crash-loop (seen live: the api on a perms bug).
      # Re-verify after a pause before declaring success.
      sleep 25
      local bad2
      bad2=$(compose ps --format '{{.Service}}|{{.State}}|{{.Health}}' 2>/dev/null \
        | awk -F'|' '$1 ~ /-init$/ {next} $2!="running" || $3=="unhealthy" {print}' | wc -l)
      [ "$bad2" -eq 0 ] && return 0
    fi
    sleep 10
  done
  return 1
}

print_success() {
  local host ip
  ip=$(hostname -I 2>/dev/null | awk '{print $1}') ; host=${ip:-localhost}
  say ""
  say "${GREEN}${BOLD}────────────────────────────────────────────────${RST}"
  say "${GREEN}${BOLD}  Correlix is installed and running${RST}"
  say "${GREEN}${BOLD}────────────────────────────────────────────────${RST}"
  say ""
  say "  Open the UI:   ${BOLD}http://${host}:${UI_PORT}${RST}"
  say "  Sign in as:    ${BOLD}$(env_get ADMIN_USERNAME || echo admin)${RST}"
  say "  Password:      ${BOLD}$(env_get ADMIN_INITIAL_PASSWORD)${RST}"
  say "                 ${DIM}(generated for this install — change it in Settings)${RST}"
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
      [ -n "$spec" ] || die "Unknown add-on in config: '$a'" \
        "Available add-ons: log-search-ui (log forensics UI), self-monitoring (Grafana + container/host metrics)"
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
  # Full transcript of the installation — tail-able live from another
  # terminal, and the first thing support asks for when something fails.
  INSTALL_LOG="$HERE/correlix-install-$(date +%Y%m%d-%H%M%S).log"
  say "${BOLD}Correlix installer${RST}"
  say "Full log: $INSTALL_LOG"
  say "${DIM}(watch live from another terminal:  tail -f $INSTALL_LOG)${RST}"
  exec > >(tee -a "$INSTALL_LOG") 2>&1
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
  [ "$MODE" = "bundle" ] && verify_bundle

  # Assemble install.py arguments. Defaults are the appliance path: embedded
  # Apache Kafka + embedded Valkey + everything else, zero questions asked.
  assemble_install_args

  say ""
  if ! python3 "$ROOT/scripts/install.py" "${INSTALL_ARGS[@]}"; then
    print_failure
    cx_result fail
    exit 1
  fi
  cx_stage verify-health "waiting for services to become healthy" start
  if wait_healthy; then
    cx_stage verify-health "waiting for services to become healthy" ok
    # Reclaim superseded image layers from any previous version this host ran —
    # upgrades load new tags and the old layers otherwise sit on the appliance
    # disk forever. Dangling-only: everything the running stack references is
    # untouchable by definition.
    docker image prune -f >/dev/null 2>&1 || true
    cx_stage verify-login "verifying the admin credential" start
    verify_admin_login
    # verify_admin_login is advisory by design (it warns, never blocks), so
    # the stage always closes ok; the credential itself NEVER rides a marker.
    cx_stage verify-login "verifying the admin credential" ok
    print_success
    local ip host
    ip=$(hostname -I 2>/dev/null | awk '{print $1}'); host=${ip:-localhost}
    cx_result ok "http://${host}:${UI_PORT}" "$(env_get ADMIN_USERNAME || echo admin)"
  else
    cx_stage verify-health "waiting for services to become healthy" fail \
      "services did not become healthy within the wait window"
    print_failure
    cx_result fail
    exit 1
  fi
}

cmd_uninstall() {
  [ -f "$ENV_FILE" ] || die "Nothing to uninstall — no Correlix install found here."
  say "Stopping and removing Correlix containers..."
  compose down --remove-orphans
  ok "containers removed"
  if [ "$PURGE" = 1 ]; then
    say "Purging data, configuration, and loaded images..."
    if [ "$MODE" = "bundle" ] && [ -f "$BUNDLE_DIR/MANIFEST" ]; then
      # MANIFEST pins images as tag@sha256:digest, but docker-load restored
      # them by TAG only (digests are pull-time metadata) — so `docker rmi
      # tag@digest` no-ops on a virgin host. Strip the digest and remove by tag.
      sed -n 's/^  - //p' "$BUNDLE_DIR/MANIFEST" | sed 's/@sha256:[0-9a-f]*$//' | sort -u | while read -r img; do
        docker rmi "$img" >/dev/null 2>&1 || true
      done
    fi
    rm -rf "$ROOT/data" "$ENV_FILE"
    ok "data and configuration removed (images unreferenced elsewhere were deleted)"
  else
    say "Your data and configuration were kept:"
    say "  data:    $ROOT/data"
    say "  config:  $ENV_FILE"
    say "Remove everything with: ./install-correlix.sh uninstall --purge"
  fi
}

cmd_reset_demo() {
  [ -f "$ENV_FILE" ] || die "Correlix is not installed here yet." "Run: ./install-correlix.sh"
  UI_PORT=$(env_get BASE_PORT); UI_PORT=${UI_PORT:-8000}
  say "Resetting to a clean evaluation state (credentials are kept)..."
  compose down --remove-orphans
  # Wipe store data but keep .env (secrets/identity) — dirs are recreated with
  # correct ownership by install.py before start.
  docker run --rm -v "$ROOT/data:/data" alpine sh -c 'find /data -mindepth 1 -maxdepth 1 -exec rm -rf {} +'
  local rargs=(--port "$(env_get BASE_PORT || echo 8000)")
  [ "$MODE" = "bundle" ] && rargs+=(--offline)   # images are already loaded; never build/pull
  python3 "$ROOT/scripts/install.py" "${rargs[@]}"
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
    self-monitoring) echo "self-monitoring|grafana cadvisor node-exporter" ;;
    *) echo "" ;;
  esac
}

set_env_var() { # KEY VALUE — replace or append in .env
  if grep -q "^$1=" "$ENV_FILE"; then sed -i "s|^$1=.*|$1=$2|" "$ENV_FILE"
  else printf '%s=%s\n' "$1" "$2" >> "$ENV_FILE"; fi
}

cmd_enable() {
  [ -f "$ENV_FILE" ] || die "Correlix is not installed here yet." "Run: ./install-correlix.sh"
  local spec; spec=$(addon_spec "$ADDON_ARG")
  [ -n "$spec" ] || die "Unknown add-on: '${ADDON_ARG:-}'" "Available add-ons: log-search-ui (log forensics UI), self-monitoring (Grafana + container/host metrics)"
  local prof="${spec%%|*}"
  # Load the add-on's image pack when installing from a bundle.
  if [ "$MODE" = "bundle" ]; then
    local pack; pack=$(compgen -G "$BUNDLE_DIR/correlix-addon-$ADDON_ARG-"*.tar.zst | head -1 || true)
    if [ -n "$pack" ]; then
      say "Loading $ADDON_ARG images..."
      zstd -dc "$pack" | docker load >/dev/null
    fi
  fi
  local cur; cur=$(env_get COMPOSE_PROFILES)
  case ",$cur," in *",$prof,"*) ;; *) set_env_var COMPOSE_PROFILES "${cur:+$cur,}$prof" ;; esac
  [ "$ADDON_ARG" = "self-monitoring" ] && set_env_var GRAFANA_URL "http://grafana:3000"
  say "Starting $ADDON_ARG..."
  compose up -d
  # The api reads GRAFANA_URL at start — recreate so status reflects the add-on.
  [ "$ADDON_ARG" = "self-monitoring" ] && compose up -d api
  ok "$ADDON_ARG enabled. Check: ./install-correlix.sh status"
}

cmd_disable() {
  [ -f "$ENV_FILE" ] || die "Correlix is not installed here yet."
  local spec; spec=$(addon_spec "$ADDON_ARG")
  [ -n "$spec" ] || die "Unknown add-on: '${ADDON_ARG:-}'" "Available add-ons: log-search-ui, self-monitoring"
  local prof="${spec%%|*}" svcs="${spec##*|}"
  local cur; cur=$(env_get COMPOSE_PROFILES)
  set_env_var COMPOSE_PROFILES "$(printf '%s' "$cur" | tr ',' '\n' | grep -vx "$prof" | paste -sd, -)"
  # shellcheck disable=SC2086
  compose --profile "$prof" stop $svcs >/dev/null 2>&1 || true
  # shellcheck disable=SC2086
  compose --profile "$prof" rm -f $svcs >/dev/null 2>&1 || true
  if [ "$ADDON_ARG" = "self-monitoring" ]; then set_env_var GRAFANA_URL ""; compose up -d api; fi
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
  printf '%s' "  Add-on [1-2, Enter to cancel]: "
  read -r a || true
  case "${a:-}" in 1) PICKED="log-search-ui" ;; 2) PICKED="self-monitoring" ;; esac
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
         [ "${conf:-}" = "yes" ] && { ( cmd_reset_demo ) || true; } || say "  cancelled."
         pause ;;
      0) printf '%s' "  Remove Correlix containers? Type yes to confirm: "
         read -r conf || true
         [ "${conf:-}" = "yes" ] && { ( cmd_uninstall ) || true; } || say "  cancelled."
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
  disable)         cmd_disable ;;
esac
