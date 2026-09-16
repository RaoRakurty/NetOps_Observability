#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

#
# prepare-host.sh — hardened host preparation for Correlix (#97).
#
# Run ONCE on a fresh Ubuntu/Debian server, before ./install-correlix.sh:
#
#     sudo ./prepare-host.sh              # prepare + tighten (idempotent)
#     sudo ./prepare-host.sh --check      # audit only — prints PASS/FIX per
#                                         # item, changes NOTHING (exit 1 if
#                                         # anything needs fixing)
#     sudo ./prepare-host.sh --firewall   # additionally configure the host
#                                         # firewall (UFW, or firewalld when it
#                                         # is the one running) for exactly the
#                                         # ports Correlix publishes
#     sudo ./prepare-host.sh --close-wizard-port
#                                         # remove the temporary setup-wizard
#                                         # rule (8800/tcp) once installed
#
# What it ensures (every step idempotent — safe to re-run):
#
#   PREREQUISITES
#     1  Docker Engine + Compose v2 from Docker's OFFICIAL apt repo
#        (docker-ce; GPG-verified). An already-working Docker+Compose v2
#        install of any flavor is left alone.
#     2  zstd, python3, curl, ca-certificates
#     3  Time sync active (chrony or systemd-timesyncd) — telemetry
#        timestamps and session tokens need a sane clock
#
#   DOCKER BEST PRACTICES
#     4  /etc/docker/daemon.json baseline:
#          live-restore    containers survive dockerd restarts/upgrades
#          log rotation    json-file, 20MB x 3 per container (default cap;
#                          the stack sets tighter per-service limits itself)
#          no-new-privileges  container processes cannot gain privileges
#                          (this is a DEDICATED appliance host; documented)
#     5  Dedicated service account `correlix` (system user, locked password,
#        member of docker group) — run the product as this user instead of a
#        personal admin account:  sudo -iu correlix
#     6  Invoking admin added to docker group (convenience; remove later if
#        your policy prefers only the service account)
#
#   KERNEL / LIMITS (persisted in /etc/sysctl.d/99-correlix.conf)
#     7  vm.max_map_count=262144   REQUIRED by the log-search store
#     8  vm.overcommit_memory=1    cache store (Valkey) background saves
#     9  vm.swappiness=10          keep the JVM/stores out of swap
#    10  net.core.rmem_max=26214400 (+default)  UDP ingest burst headroom
#                                   (syslog / NetFlow / sFlow receivers);
#                                   must stay >= the syslog-ng so-rcvbuf
#                                   request — see the sysctl block below
#    11  Baseline network hardening: ICMP-redirect accept/send off,
#        source-routing off, tcp_syncookies on
#
#   TIGHTENING
#    12  unattended-upgrades installed + enabled (security patches)
#    13  --firewall only: default-deny incoming, allowing exactly:
#          * SSH (every port sshd listens on; 22 if that cannot be read)
#          * every host port docker-compose.yml / compose.tls.yml publish
#            off-host — DERIVED from those files and the install's .env, never
#            a hand list (the hand list opened the container-side 1162/udp
#            instead of 162/udp and never opened 443, 514 or 11019).
#            Loopback-bound publishes are not opened. A TLS install gets 443,
#            a plaintext one its UI port; before the install exists, both.
#          * 8800/tcp for the setup wizard, as a separately tagged rule:
#            TEMPORARY — close it once installed with --close-wizard-port
#            (on firewalld it is runtime-only and also disappears at the next
#            reload or reboot).
#        Every allow lands BEFORE the default-deny. After enabling, the rules
#        are verified and the SSH/wizard listeners that answered before are
#        probed again; if either check fails the firewall is ROLLED BACK and the
#        run fails naming the port. (The probe dials this host's own address,
#        which proves the listener and the rule set, not reachability from
#        another machine.)
#        NOTE (honesty): Docker publishes its ports via iptables and BYPASSES
#        UFW for published ports — the host firewall guards host services (SSH
#        etc.); container exposure is governed by the compose port mappings.
#
# Non-Debian distros: apply the equivalents with your package manager;
# ./install-correlix.sh verifies the result either way.

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

CHECK=0; FIREWALL=0; CLOSE_WIZARD_PORT=0
for a in "$@"; do case "$a" in
  --check) CHECK=1 ;;
  --firewall) FIREWALL=1 ;;
  --close-wizard-port) CLOSE_WIZARD_PORT=1 ;;
  -h|--help) sed -n '3,82p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  *) echo "unknown arg: $a (see --help)" >&2; exit 2 ;;
esac; done

BOLD=$'\033[1m'; GREEN=$'\033[32m'; RED=$'\033[31m'; YELLOW=$'\033[33m'; RST=$'\033[0m'
[ -t 1 ] || BOLD='' GREEN='' RED='' YELLOW='' RST=''
FIXES=0
FAILED=0
pass(){ printf '  %sPASS%s  %s\n' "$GREEN" "$RST" "$1"; }
fixd(){ printf '  %sFIXED%s %s\n' "$GREEN" "$RST" "$1"; }
need(){ printf '  %sFIX%s   %s\n' "$YELLOW" "$RST" "$1"; FIXES=$((FIXES+1)); }
fixfail(){ printf '  %sFIX FAILED%s %s\n' "$RED" "$RST" "$1"; FAILED=$((FAILED+1)); }

SELF_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"

# --check is read-only and allowed unprivileged (install-correlix.sh runs it
# as its hard preflight gate); FIXING anything requires root.
if [ "$(id -u)" -ne 0 ] && [ "$CHECK" != 1 ]; then
  echo "ERROR: run with sudo:  sudo ./prepare-host.sh [--check] [--firewall]" >&2; exit 1
fi
if ! command -v apt-get >/dev/null 2>&1; then
  echo "ERROR: Debian/Ubuntu-family hosts only (apt). See the header for what" >&2
  echo "to apply manually on other distros." >&2; exit 1
fi
TARGET_USER="${SUDO_USER:-root}"
echo "${BOLD}== Correlix host preparation$( [ "$CHECK" = 1 ] && echo ' — AUDIT ONLY (--check)' )${RST}"

# ---------- 1) Docker Engine + Compose v2 ------------------------------------
if docker compose version >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  pass "docker + compose v2 present ($(docker compose version --short 2>/dev/null))"
elif [ "$CHECK" = 1 ]; then
  need "Docker Engine + Compose v2 not working (will install docker-ce from Docker's official repo)"
else
  echo "  installing Docker Engine + Compose v2 (Docker official repo)..."
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl gnupg
  install -m 0755 -d /etc/apt/keyrings
  # shellcheck disable=SC1091  # the host's own os-release, read at run time
  . /etc/os-release
  curl -fsSL "https://download.docker.com/linux/${ID}/gpg" \
    | gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${ID} ${VERSION_CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
  systemctl enable --now docker
  fixd "docker-ce + compose plugin installed, service enabled"
fi

# ---------- 2) small tools ----------------------------------------------------
MISSING_PKGS=()
for p in zstd python3 curl; do command -v "$p" >/dev/null || MISSING_PKGS+=("$p"); done
if [ "${#MISSING_PKGS[@]}" -eq 0 ]; then pass "zstd, python3, curl present"
elif [ "$CHECK" = 1 ]; then need "missing packages: ${MISSING_PKGS[*]}"
else apt-get install -y -qq "${MISSING_PKGS[@]}" ca-certificates && fixd "installed: ${MISSING_PKGS[*]}"; fi

# ---------- 3) time sync -------------------------------------------------
if timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -q yes; then
  pass "clock is NTP-synchronized"
elif [ "$CHECK" = 1 ]; then need "clock not NTP-synchronized (will enable systemd-timesyncd)"
else
  # `systemctl … 2>/dev/null || true` then an unconditional FIXED reported
  # "enabled" on hosts where the unit does not exist or is masked (FMEA P3,
  # the unattended-upgrades sibling of 217e3ab4). An undisciplined clock is not
  # cosmetic: it breaks TLS handshakes, expires tokens early and files events
  # into the wrong correlation window — all of it long after the install said
  # the host was ready. Report what happened, and name the command to run.
  if ts_err=$(systemctl enable --now systemd-timesyncd 2>&1); then
    fixd "systemd-timesyncd enabled (sync can take a minute; verify with: timedatectl)"
  else
    fixfail "could not enable time sync: $(printf '%s' "$ts_err" | tail -1) — run: sudo systemctl enable --now systemd-timesyncd (or install another NTP client, e.g. sudo apt-get install chrony)"
  fi
fi

# ---------- 4) docker daemon best practices -----------------------------------
DAEMON_JSON=/etc/docker/daemon.json
daemon_ok() {
  python3 - <<'PY' 2>/dev/null
import json,sys
try: d=json.load(open("/etc/docker/daemon.json"))
except Exception: sys.exit(1)
ok = d.get("live-restore") is True and d.get("log-driver")=="json-file" \
     and d.get("no-new-privileges") is True
sys.exit(0 if ok else 1)
PY
}
if daemon_ok; then
  pass "docker daemon.json baseline (live-restore, log caps, no-new-privileges)"
elif [ "$CHECK" = 1 ]; then
  need "docker daemon.json baseline not applied"
else
  if [ -f "$DAEMON_JSON" ]; then
    # merge, never clobber a customer's existing settings
    python3 - <<'PY'
import json
p="/etc/docker/daemon.json"
d=json.load(open(p))
d.update({"live-restore": True, "no-new-privileges": True,
          "log-driver": "json-file",
          "log-opts": {"max-size": "20m", "max-file": "3"}})
json.dump(d, open(p,"w"), indent=2)
PY
  else
    cat > "$DAEMON_JSON" <<'EOF'
{
  "live-restore": true,
  "no-new-privileges": true,
  "log-driver": "json-file",
  "log-opts": { "max-size": "20m", "max-file": "3" }
}
EOF
  fi
  systemctl reload docker 2>/dev/null || systemctl restart docker
  fixd "docker daemon.json baseline applied (live-restore, log caps, no-new-privileges)"
fi

# ---------- 5+6) service account + docker group -------------------------------
if id correlix >/dev/null 2>&1; then pass "service account 'correlix' exists"
elif [ "$CHECK" = 1 ]; then need "dedicated service account 'correlix' (system user, docker group)"
else
  useradd --system --create-home --home-dir /opt/correlix --shell /bin/bash correlix
  passwd -l correlix >/dev/null
  usermod -aG docker correlix
  fixd "service account 'correlix' created (home /opt/correlix, password locked, docker group)"
fi
RELOGIN=0
if [ "$TARGET_USER" != "root" ]; then
  if id -nG "$TARGET_USER" | grep -qw docker; then pass "$TARGET_USER in docker group"
  elif [ "$CHECK" = 1 ]; then need "$TARGET_USER not in docker group"
  else usermod -aG docker "$TARGET_USER"; RELOGIN=1; fixd "$TARGET_USER added to docker group (re-login required)"; fi
fi

# ---------- 7-11) kernel / limits ----------------------------------------
declare -A SYSCTLS=(
  [vm.max_map_count]=262144
  [vm.overcommit_memory]=1
  [vm.swappiness]=10
  # UDP receive buffers: net.core.rmem_max is a HOST-GLOBAL clamp (not
  # namespaced — it cannot be raised per-container) on every SO_RCVBUF
  # request, and syslog-ng's udp() source asks for so-rcvbuf(8388608) in
  # deployment/docker/syslog-ng/core.conf (syslog-ng 4.7 has no
  # SO_RCVBUFFORCE fallback, so a lower clamp silently wins and kernel-side
  # burst drops return, invisible to every counter the stack scrapes).
  # These two values MUST stay >= that request; 25 MiB gives the NetFlow/
  # sFlow/trap receivers the same headroom. Pinned against core.conf by
  # tests/test_ingest_contract.py (test_syslog_edge_absorbs_bursts...).
  [net.core.rmem_max]=26214400
  [net.core.rmem_default]=26214400
  [net.ipv4.conf.all.accept_redirects]=0
  [net.ipv4.conf.all.send_redirects]=0
  [net.ipv4.conf.all.accept_source_route]=0
  [net.ipv4.tcp_syncookies]=1
)
SYSCTL_MISS=""
for k in "${!SYSCTLS[@]}"; do
  cur=$(sysctl -n "$k" 2>/dev/null || echo "")
  [ "$cur" = "${SYSCTLS[$k]}" ] || SYSCTL_MISS="$SYSCTL_MISS $k"
done
if [ -z "$SYSCTL_MISS" ]; then pass "kernel settings (max_map_count, overcommit, swappiness, UDP buffers, net hardening)"
elif [ "$CHECK" = 1 ]; then need "kernel settings to apply:$SYSCTL_MISS"
else
  { echo "# Correlix host settings — generated by prepare-host.sh"
    for k in "${!SYSCTLS[@]}"; do echo "$k=${SYSCTLS[$k]}"; done; } > /etc/sysctl.d/99-correlix.conf
  sysctl --system >/dev/null
  fixd "kernel settings applied + persisted (/etc/sysctl.d/99-correlix.conf)"
fi

# ---------- 12) security patches ----------------------------------------------
if dpkg -s unattended-upgrades >/dev/null 2>&1; then pass "unattended-upgrades installed"
elif [ "$CHECK" = 1 ]; then need "unattended-upgrades not installed (automatic security patches)"
else
  # A && B || true then reporting FIXED said "installed + enabled" even when the
  # install failed (FMEA P3, shellcheck SC2015). Report what actually happened.
  if apt-get install -y -qq unattended-upgrades; then
    if dpkg-reconfigure -f noninteractive unattended-upgrades >/dev/null 2>&1; then
      fixd "unattended-upgrades installed + enabled"
    else
      fixfail "unattended-upgrades installed, but enabling it failed — run: sudo dpkg-reconfigure unattended-upgrades"
    fi
  else
    fixfail "could not install unattended-upgrades (automatic security patches) — check apt and run: sudo apt-get install unattended-upgrades"
  fi
fi

# >>> firewall-lib ------------------------------------------------------------
# Everything --firewall / --close-wizard-port does lives between these markers.
# tests/test_prepare_host_firewall.py runs exactly this block with fake ufw /
# firewall-cmd / sshd binaries. Callers provide: pass fixd need fixfail, CHECK,
# CLOSE_WIZARD_PORT, SELF_DIR.

WIZARD_PORT=8800
FW_TMP=""
FW_COMPOSE_DIR=""
FW_ENV_FILE=""
FW_WHY=""
FW_PROBE_PORTS=""

# Find docker-compose.yml + compose.tls.yml: a source checkout, an extracted
# bundle, or — before the installer has extracted anything — inside the
# bundle's source tarball. Sets FW_COMPOSE_DIR, or FW_WHY and returns 1.
fw_locate_compose() {
  local d out
  local tgzs=()
  for d in "$SELF_DIR/../deployment/docker" "$SELF_DIR/NetOps_Observability/deployment/docker"; do
    if [ -f "$d/docker-compose.yml" ]; then
      FW_COMPOSE_DIR="$(cd "$d" && pwd)"
      return 0
    fi
  done
  mapfile -t tgzs < <(compgen -G "$SELF_DIR/correlix-source-*.tar.gz")
  if [ "${#tgzs[@]}" -ge 1 ]; then
    FW_TMP=$(mktemp -d)
    if out=$(timeout 120 tar -xzf "${tgzs[0]}" -C "$FW_TMP" \
        NetOps_Observability/deployment/docker/docker-compose.yml \
        NetOps_Observability/deployment/docker/compose.tls.yml 2>&1); then
      FW_COMPOSE_DIR="$FW_TMP/NetOps_Observability/deployment/docker"
      return 0
    fi
    FW_WHY="could not read the compose files from ${tgzs[0]##*/}: $out"
    return 1
  fi
  FW_WHY="no deployment/docker/docker-compose.yml found next to $SELF_DIR, and no correlix-source-*.tar.gz to read it from"
  return 1
}

# One KEY from the install's .env (the running install's truth), unquoted.
fw_env_get() {
  [ -f "$FW_ENV_FILE" ] || return 0
  sed -n "s/^$1=//p" "$FW_ENV_FILE" | tail -1 | sed -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'$/\1/"
}

# tls | plain | undecided — .env's COMPOSE_FILE chain is the one on-disk
# statement of the scheme (install-correlix.sh reads it the same way).
fw_scheme() {
  if [ ! -f "$FW_ENV_FILE" ]; then echo undecided; return 0; fi
  case "$(fw_env_get COMPOSE_FILE)" in
    *compose.tls.yml*) echo tls ;;
    *) echo plain ;;
  esac
}

# The `ports:` entries of one compose file: "service<TAB>entry<TAB>override".
# A "-" entry marks the ports: key itself, so an `!override` with no entries is
# still seen. Block-style lists only — the style every Correlix compose file
# uses (pinned by the tests against a PyYAML reading of the same files).
fw_compose_ports() {
  awk -v sq="'" '
    /^services:/ { in_s = 1; next }
    in_s && /^[^ #]/ { in_s = 0 }
    !in_s { next }
    /^  [A-Za-z0-9_.-]+:[ \t]*(#.*)?$/ { svc = $1; sub(/:$/, "", svc); in_p = 0; next }
    /^    ports:/ { in_p = 1; ovr = ($0 ~ /!override/) ? 1 : 0; print svc "\t-\t" ovr; next }
    in_p && /^      - / {
      v = $0; sub(/^      - /, "", v); sub(/[ \t]+#.*$/, "", v)
      gsub(/"/, "", v); gsub(sq, "", v); gsub(/[ \t]/, "", v)
      print svc "\t" v "\t" ovr; next
    }
    in_p && /^[ \t]*(#.*)?$/ { next }
    in_p && /^      #/ { next }
    in_p { in_p = 0 }
  ' "$1"
}

# One compose publish entry → "hostport/proto", or nothing when it is not an
# off-host publish (loopback-bound, container-only, or a form this stack does
# not use — which is said, never silently dropped).
fw_resolve_publish() {
  local spec="$1" proto=tcp host="" ip="" var def val
  local bits=()
  case "$spec" in
    */udp) proto=udp; spec=${spec%/udp} ;;
    */tcp) spec=${spec%/tcp} ;;
  esac
  while [[ "$spec" =~ \$\{([A-Za-z_][A-Za-z0-9_]*)(:-([^}]*))?\} ]]; do
    var=${BASH_REMATCH[1]}
    def=${BASH_REMATCH[3]}
    val=$(fw_env_get "$var")
    [ -n "$val" ] || val=$def
    spec=${spec/"${BASH_REMATCH[0]}"/$val}
  done
  IFS=: read -r -a bits <<< "$spec"
  case "${#bits[@]}" in
    1) return 0 ;;                                  # container port only
    2) host=${bits[0]} ;;
    3) ip=${bits[0]}; host=${bits[1]} ;;
    *) echo "  NOTE  published port '$1' is in a form this script does not read — not opened" >&2; return 0 ;;
  esac
  case "$ip" in 127.*|localhost|::1|'[::1]') return 0 ;; esac
  case "$host" in
    ''|*[!0-9]*) echo "  NOTE  published port '$1' has no fixed host port — not opened" >&2; return 0 ;;
  esac
  printf '%s/%s\n' "$host" "$proto"
}

# The environment variable that MOVES a published host port
# ("${SYSLOG_PORT:-5514}:514/tcp" -> SYSLOG_PORT), or nothing when the compose
# file pins the port. The host port is the FIRST field of a publish entry, so
# only a leading ${...} moves it; an entry that pins an address first
# (127.0.0.1:...) is loopback-bound and never opened. install-correlix.sh's
# preflight quotes this back to the customer when the port is already in use,
# so the port check and the firewall name the same variable.
fw_publish_mover() {
  if [[ "$1" =~ ^\$\{([A-Za-z_][A-Za-z0-9_]*)(:-[^}]*)?\} ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
  fi
  return 0
}

# One compose publish entry -> "hostport/proto[:MOVER_VAR]", or nothing when it
# is not an off-host publish.
fw_emit_publish() {
  local resolved mover
  resolved=$(fw_resolve_publish "$1")
  [ -n "$resolved" ] || return 0
  mover=$(fw_publish_mover "$1")
  if [ -n "$mover" ]; then
    printf '%s:%s\n' "$resolved" "$mover"
  else
    printf '%s\n' "$resolved"
  fi
}

# Every host port the stack publishes off-host as "port/proto[:MOVER_VAR]",
# sorted and unique. THE port set: --firewall opens it, and
# install-correlix.sh's preflight checks it is free. One parser, two callers.
fw_stack_port_entries() {
  local scheme base tls="" overridden="" svc spec _ovr
  scheme=$(fw_scheme)
  base=$(fw_compose_ports "$FW_COMPOSE_DIR/docker-compose.yml")
  if [ "$scheme" != plain ] && [ -f "$FW_COMPOSE_DIR/compose.tls.yml" ]; then
    tls=$(fw_compose_ports "$FW_COMPOSE_DIR/compose.tls.yml")
  fi
  if [ "$scheme" = tls ]; then
    # compose.tls.yml replaces (`!override`) these services' port lists.
    overridden=$(printf '%s\n' "$tls" | awk -F'\t' '$2 == "-" && $3 == 1 { print $1 }')
  fi
  {
    while IFS=$'\t' read -r svc spec _ovr; do
      if [ -z "$svc" ] || [ "$spec" = "-" ]; then continue; fi
      if printf '%s\n' "$overridden" | grep -qx -- "$svc"; then continue; fi
      fw_emit_publish "$spec"
    done <<< "$base"
    while IFS=$'\t' read -r svc spec _ovr; do
      if [ -z "$svc" ] || [ "$spec" = "-" ]; then continue; fi
      fw_emit_publish "$spec"
    done <<< "$tls"
  } | sort -u
}

# The same set as ports only — what the firewall rules are built from.
fw_stack_ports() {
  fw_stack_port_entries | sed 's/:[A-Za-z_][A-Za-z0-9_]*$//' | sort -u
}

# Every port sshd listens on. sshd absent or unreadable → 22, the safe default
# (allowing a port nothing listens on costs nothing; missing the real one locks
# the operator out).
fw_ssh_ports() {
  local ports=""
  if command -v sshd >/dev/null 2>&1; then
    ports=$(timeout 10 sshd -T 2>/dev/null | awk '$1 == "port" { print $2 "/tcp" }' | sort -u) || ports=""
  fi
  [ -n "$ports" ] || ports="22/tcp"
  printf '%s\n' "$ports"
}

fw_mgmt_ip() {
  local ip
  ip=$(hostname -I 2>/dev/null | awk '{ print $1 }')
  printf '%s' "${ip:-127.0.0.1}"
}

# Does something answer TCP on ip:port? The exit status is the whole answer, so
# the connect error itself is not interesting.
fw_probe_port() {
  # shellcheck disable=SC2016  # $1/$2 expand in the child bash, from its argv
  timeout 3 bash -c 'exec 3<>"/dev/tcp/$1/$2"' _ "$1" "$2" 2>/dev/null
}

fw_backend() {
  if command -v firewall-cmd >/dev/null 2>&1 \
     && [ "$(timeout 10 firewall-cmd --state 2>/dev/null)" = running ]; then
    echo firewalld
  else
    echo ufw
  fi
}

# The listed ports that `ufw status` does not show as ALLOW.
fw_ufw_missing() {
  local status p missing=""
  if ! status=$(timeout 30 ufw status 2>&1); then
    printf '(ufw status failed: %s)' "$status"
    return 0
  fi
  for p in $1; do
    if ! printf '%s\n' "$status" | awk -v p="$p" '$1 == p && $2 == "ALLOW" { f = 1 } END { exit !f }'; then
      missing="$missing $p"
    fi
  done
  printf '%s' "${missing# }"
}

fw_ufw_rollback() { # was_active previous_default_incoming
  local out
  if [ "$1" = 1 ]; then
    if [ -n "$2" ] && ! out=$(timeout 30 ufw default "$2" incoming 2>&1); then
      echo "  rollback: could not restore the default incoming policy '$2': $out — restore it by hand: ufw default $2 incoming" >&2
    fi
  elif ! out=$(timeout 30 ufw --force disable 2>&1); then
    echo "  rollback: 'ufw --force disable' failed: $out — run it by hand NOW" >&2
  fi
}

fw_apply_ufw() { # "port/proto ..." (SSH + stack + wizard)
  local p out was_active=0 prev_default="" listening="" missing ip
  if ! command -v ufw >/dev/null 2>&1; then
    if ! out=$(timeout 600 apt-get install -y -qq ufw 2>&1); then
      fixfail "firewall NOT configured: installing ufw failed: $(printf '%s' "$out" | tail -2)"
      return 0
    fi
  fi
  if out=$(timeout 30 ufw status verbose 2>&1) && printf '%s\n' "$out" | grep -q '^Status: active'; then
    was_active=1
    prev_default=$(printf '%s\n' "$out" | sed -n 's/^Default: \([a-z]*\) (incoming).*/\1/p')
  fi
  ip=$(fw_mgmt_ip)
  for p in $FW_PROBE_PORTS; do
    if fw_probe_port "$ip" "${p%/*}"; then listening="$listening $p"; fi
  done
  # Allows FIRST: default-deny must never be active without them.
  for p in $1; do
    if [ "$p" = "$WIZARD_PORT/tcp" ]; then
      out=$(timeout 30 ufw allow "$p" comment 'correlix-setup wizard - temporary, close with prepare-host.sh --close-wizard-port' 2>&1) || {
        fixfail "firewall NOT configured: 'ufw allow $p' failed: $out"; fw_ufw_rollback "$was_active" "$prev_default"; return 0; }
    else
      out=$(timeout 30 ufw allow "$p" 2>&1) || {
        fixfail "firewall NOT configured: 'ufw allow $p' failed: $out"; fw_ufw_rollback "$was_active" "$prev_default"; return 0; }
    fi
  done
  for p in "deny incoming" "allow outgoing"; do
    # shellcheck disable=SC2086  # "policy direction" is two arguments on purpose
    out=$(timeout 30 ufw default $p 2>&1) || {
      fixfail "firewall NOT configured: 'ufw default $p' failed: $out"; fw_ufw_rollback "$was_active" "$prev_default"; return 0; }
  done
  if ! out=$(timeout 60 ufw --force enable 2>&1); then
    fixfail "firewall NOT configured: 'ufw --force enable' failed: $out"
    fw_ufw_rollback "$was_active" "$prev_default"
    return 0
  fi
  missing=$(fw_ufw_missing "$1")
  if [ -n "$missing" ]; then
    fw_ufw_rollback "$was_active" "$prev_default"
    fixfail "UFW rules did not take effect for: $missing — firewall rolled back to its previous state"
    return 0
  fi
  for p in $listening; do
    if ! fw_probe_port "$ip" "${p%/*}"; then
      fw_ufw_rollback "$was_active" "$prev_default"
      fixfail "$p answered on $ip before the firewall was enabled and does not now — firewall rolled back to its previous state"
      return 0
    fi
  done
  fixd "UFW enabled: default-deny incoming; allowed $1 ($WIZARD_PORT/tcp is temporary: --close-wizard-port)"
}

fw_firewalld_rollback() { # "port/proto ..." this run added
  local p out
  for p in $1; do
    out=$(timeout 30 firewall-cmd --permanent --remove-port="$p" 2>&1) \
      || echo "  rollback: could not remove permanent $p: $out" >&2
    out=$(timeout 30 firewall-cmd --remove-port="$p" 2>&1) \
      || echo "  rollback: could not remove runtime $p: $out" >&2
  done
}

fw_apply_firewalld() { # "port/proto ..." (SSH + stack + wizard)
  local p out added="" listening="" ip missing=""
  ip=$(fw_mgmt_ip)
  for p in $FW_PROBE_PORTS; do
    if fw_probe_port "$ip" "${p%/*}"; then listening="$listening $p"; fi
  done
  for p in $1; do
    [ "$p" = "$WIZARD_PORT/tcp" ] && continue
    if ! timeout 30 firewall-cmd --permanent --query-port="$p" >/dev/null 2>&1; then
      if ! out=$(timeout 30 firewall-cmd --permanent --add-port="$p" 2>&1); then
        fixfail "firewall NOT configured: 'firewall-cmd --permanent --add-port=$p' failed: $out"
        fw_firewalld_rollback "$added"
        return 0
      fi
      added="$added $p"
    fi
  done
  if ! out=$(timeout 60 firewall-cmd --reload 2>&1); then
    fixfail "firewall NOT configured: 'firewall-cmd --reload' failed: $out"
    fw_firewalld_rollback "$added"
    return 0
  fi
  # Runtime-only: gone at the next reload or reboot, or with --close-wizard-port.
  if ! out=$(timeout 30 firewall-cmd --add-port="$WIZARD_PORT/tcp" 2>&1); then
    fixfail "could not open the setup wizard port $WIZARD_PORT/tcp: $out"
  fi
  for p in $1; do
    timeout 30 firewall-cmd --query-port="$p" >/dev/null 2>&1 || missing="$missing $p"
  done
  if [ -n "$missing" ]; then
    fw_firewalld_rollback "$added"
    fixfail "firewalld rules did not take effect for:$missing — this run's rules rolled back"
    return 0
  fi
  for p in $listening; do
    if ! fw_probe_port "$ip" "${p%/*}"; then
      fw_firewalld_rollback "$added"
      fixfail "$p answered on $ip before the firewall change and does not now — this run's rules rolled back"
      return 0
    fi
  done
  fixd "firewalld: allowed $1 ($WIZARD_PORT/tcp runtime-only)"
}

fw_close_wizard_port() {
  local out
  if [ "$(fw_backend)" = firewalld ]; then
    if out=$(timeout 30 firewall-cmd --remove-port="$WIZARD_PORT/tcp" 2>&1); then
      fixd "setup wizard port $WIZARD_PORT/tcp closed (firewalld)"
    else
      fixfail "could not close $WIZARD_PORT/tcp on firewalld: $out"
    fi
  elif ! command -v ufw >/dev/null 2>&1; then
    pass "ufw is not installed — no wizard rule to close"
  elif out=$(timeout 30 ufw delete allow "$WIZARD_PORT/tcp" 2>&1); then
    fixd "setup wizard port $WIZARD_PORT/tcp closed (ufw)"
  else
    fixfail "could not close $WIZARD_PORT/tcp on ufw: $out"
  fi
}

fw_main() {
  local stack ssh list out missing
  if [ "$CLOSE_WIZARD_PORT" = 1 ]; then
    fw_close_wizard_port
    return 0
  fi
  if ! fw_locate_compose; then
    if [ "$CHECK" = 1 ]; then
      need "firewall: cannot derive the ports Correlix publishes — $FW_WHY"
    else
      fixfail "firewall NOT configured: cannot derive the ports Correlix publishes — $FW_WHY. Refusing to guess: a hand-kept list is how 443 and 162/udp went missing. Run this from the bundle directory."
    fi
    return 0
  fi
  FW_ENV_FILE="$FW_COMPOSE_DIR/.env"
  stack=$(fw_stack_ports)
  ssh=$(fw_ssh_ports)
  FW_PROBE_PORTS="$(printf '%s\n' "$ssh" | tr '\n' ' ')$WIZARD_PORT/tcp"
  # shellcheck disable=SC2086  # deliberate word-split of the port lists
  list=$(printf '%s\n' $ssh $stack | sort -u | tr '\n' ' ')
  list=${list% }
  case "$(fw_scheme)" in
    undecided) echo "  (no install yet: allowing both the HTTPS ingress and the plaintext UI port — re-run --firewall after installing to narrow it)" ;;
  esac
  if [ "$CHECK" = 1 ]; then
    if [ "$(fw_backend)" = firewalld ]; then
      missing=""
      for p in $list; do
        timeout 30 firewall-cmd --query-port="$p" >/dev/null 2>&1 || missing="$missing $p"
      done
      if [ -z "$missing" ]; then pass "firewalld allows every Correlix port"
      else need "firewalld is missing allow rules for:$missing"; fi
    elif ! command -v ufw >/dev/null 2>&1; then
      need "UFW not installed (would install it, default-deny incoming, allow: $list)"
    elif ! out=$(timeout 30 ufw status 2>&1) || ! printf '%s\n' "$out" | grep -q '^Status: active'; then
      need "UFW not active (would default-deny incoming and allow: $list)"
    else
      missing=$(fw_ufw_missing "$list")
      if [ -z "$missing" ]; then pass "UFW active with every Correlix port allowed"
      else need "UFW active but missing allow rules for: $missing"; fi
    fi
  elif [ "$(fw_backend)" = firewalld ]; then
    fw_apply_firewalld "$list $WIZARD_PORT/tcp"
  else
    fw_apply_ufw "$list $WIZARD_PORT/tcp"
  fi
  if [ -n "$FW_TMP" ]; then rm -rf "$FW_TMP"; fi
  return 0
}
# <<< firewall-lib ------------------------------------------------------------

# ---------- 13) firewall (opt-in) ----------------------------------------------
if [ "$FIREWALL" = 1 ] || [ "$CLOSE_WIZARD_PORT" = 1 ]; then
  fw_main
fi

# ---- PATH alias: `install-correlix` works from anywhere ----------------
if [ -x "$SELF_DIR/install-correlix.sh" ]; then
  if [ "$CHECK" = 1 ]; then
    if [ "$(readlink -f /usr/local/bin/install-correlix 2>/dev/null)" = "$SELF_DIR/install-correlix.sh" ]; then
      pass "command alias 'install-correlix' on PATH"
    else
      need "command alias 'install-correlix' (symlink to this bundle)"
    fi
  else
    ln -sf "$SELF_DIR/install-correlix.sh" /usr/local/bin/install-correlix
    fixd "command alias installed — run 'install-correlix' from anywhere"
  fi
fi

echo
if [ "$CHECK" = 1 ]; then
  if [ "$FIXES" -eq 0 ]; then echo "${GREEN}${BOLD}Audit clean — host is ready for Correlix.${RST}"; exit 0
  else echo "${YELLOW}${BOLD}$FIXES item(s) need fixing — run: sudo ./prepare-host.sh${RST}"; exit 1; fi
fi
if [ "$FAILED" -gt 0 ]; then
  echo "${RED}${BOLD}== $FAILED step(s) FAILED — see the FIX FAILED lines above.${RST}"
  exit 1
fi
echo "${GREEN}${BOLD}== Host is ready for Correlix.${RST}"
if [ "$RELOGIN" = 1 ]; then
  echo "   1. Log out and back in (docker group membership takes effect)."
  echo "   2. Run: ./install-correlix.sh"
else
  echo "   Run: ./install-correlix.sh"
fi
echo "   (Recommended: install as the service account —  sudo -iu correlix)"
if [ "$FIREWALL" = 1 ]; then
  echo "   After installing, close the setup wizard's port:  sudo ./prepare-host.sh --close-wizard-port"
fi
