#!/usr/bin/env bash
#
# install-correlix.sh — the one-command Correlix appliance installer (#97).
#
# A first-time customer runs exactly one thing and thinks about nothing else:
#
#     ./install-correlix.sh
#
# In an interactive terminal with no arguments this opens the SETUP CONSOLE —
# numbered menu navigation over every operation (prepare host, install,
# health, logs, add-ons, stop/start, reset, uninstall). In a pipeline/script
# it installs non-interactively. Explicit subcommands below always work.
#
# Everything under the hood (Apache Kafka event bus, Valkey cache, PostgreSQL,
# OpenSearch, ClickHouse, VictoriaMetrics, the Correlix services) is embedded,
# configured with generated credentials, and started automatically. No broker
# choices, no topic names, no compose internals.
#
# Commands (no argument = install):
#     ./install-correlix.sh install [--ui-port N]
#     ./install-correlix.sh status
#     ./install-correlix.sh logs [service]
#     ./install-correlix.sh stop
#     ./install-correlix.sh start
#     ./install-correlix.sh uninstall [--purge]
#     ./install-correlix.sh reset-demo-data
#     ./install-correlix.sh enable  <add-on>    log-search-ui | self-monitoring
#     ./install-correlix.sh disable <add-on>
#
# Advanced (documented in ADVANCED.md, hidden from the quickstart):
#     --external-kafka --broker-urls host1:9092[,host2:9092]
#         Use a customer-provided Kafka-compatible broker instead of the
#         embedded one (enterprise deployments).
#     --lab
#         Internal/developer mode: source-checkout install with the full dev
#         profile set. Not part of customer distribution and intentionally
#         undocumented in customer docs.
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
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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

# ---------- args ---------------------------------------------------------
CMD="install"
UI_PORT=8000
EXTERNAL_KAFKA=0
BROKER_URLS_ARG="${BROKER_URLS:-}"
LAB=0
PURGE=0
LOG_SVC=""
if [ $# -gt 0 ]; then
  case "$1" in
    install|status|logs|stop|start|uninstall|reset-demo-data|enable|disable|menu) CMD="$1"; shift ;;
    -*) : ;;  # bare options → install
    *) die "Unknown command: $1" "Commands: install status logs stop start uninstall reset-demo-data enable disable menu" ;;
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
    --lab)            LAB=1; shift ;;
    --purge)          PURGE=1; shift ;;
    -h|--help)        sed -n '3,32p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
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
  fi
  if [ ! -d "$ROOT" ]; then
    say "Extracting Correlix..."
    tar -xzf correlix-source-*.tar.gz
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
      return 0
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

# ---------- commands ----------------------------------------------------
cmd_install() {
  say "${BOLD}Correlix installer${RST}"
  preflight
  [ "$MODE" = "bundle" ] && verify_bundle

  # Assemble install.py arguments. Defaults are the appliance path: embedded
  # Apache Kafka + embedded Valkey + everything else, zero questions asked.
  local args=(--port "$UI_PORT")
  # Bundle installs start as the BASE appliance (add-ons come later via
  # `enable`); source checkouts get the developer default incl. dashboards +
  # self-monitoring.
  local profiles="embedded-bus,prober,osd,self-monitoring"
  local images=""
  if [ "$MODE" = "bundle" ]; then
    images=$(compgen -G "$BUNDLE_DIR/correlix-images-*.tar.zst" | head -1 || true)
    [ -n "$images" ] || die "Image archive not found in the bundle." \
      "Expected correlix-images-core-<version>.tar.zst (or its .partNN pieces) next to this script."
    args+=(--bundle "$images")
    profiles="embedded-bus,prober"
  fi
  if [ "$EXTERNAL_KAFKA" = 1 ]; then
    [ -n "$BROKER_URLS_ARG" ] || die "External Kafka mode needs your broker endpoints." \
      "Provide them like this:
  ./install-correlix.sh install --external-kafka --broker-urls broker1:9092,broker2:9092
(or set the BROKER_URLS environment variable). See ADVANCED.md."
    args+=(--broker-urls "$BROKER_URLS_ARG")
    say "Using your external Kafka-compatible broker: $BROKER_URLS_ARG"
  elif [ -n "$BROKER_URLS_ARG" ] && [ "$BROKER_URLS_ARG" != "kafka:9092" ]; then
    warn "BROKER_URLS is set but --external-kafka was not given — ignoring it and using the embedded bus."
  fi
  [ "$LAB" = 1 ] && say "${DIM}(lab mode: developer profiles; internal use only)${RST}"
  args+=(--profiles "$profiles")

  say ""
  if ! python3 "$ROOT/scripts/install.py" "${args[@]}"; then
    print_failure
    exit 1
  fi
  if wait_healthy; then
    print_success
  else
    print_failure
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
      sed -n 's/^  - //p' "$BUNDLE_DIR/MANIFEST" | while read -r img; do
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

case "$CMD" in
  menu)            cmd_menu ;;
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
  disable)         cmd_disable ;;
esac
