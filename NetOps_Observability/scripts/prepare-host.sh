#!/usr/bin/env bash
#
# prepare-host.sh — hardened host preparation for Correlix (#97).
#
# Run ONCE on a fresh Ubuntu/Debian server, before ./install-correlix.sh:
#
#     sudo ./prepare-host.sh              # prepare + tighten (idempotent)
#     sudo ./prepare-host.sh --check      # audit only — prints PASS/FIX per
#                                         # item, changes NOTHING (exit 1 if
#                                         # anything needs fixing)
#     sudo ./prepare-host.sh --firewall   # additionally configure UFW for
#                                         # exactly the ports Correlix needs
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
#                                   (syslog / NetFlow / sFlow receivers)
#    11  Baseline network hardening: ICMP-redirect accept/send off,
#        source-routing off, tcp_syncookies on
#
#   TIGHTENING
#    12  unattended-upgrades installed + enabled (security patches)
#    13  --firewall only: UFW default-deny incoming; allow OpenSSH, the UI
#        (8000/tcp) and the device-facing ingest ports (5514 tcp+udp,
#        2055/4739/6343/1162 udp). NOTE (honesty): Docker publishes its ports
#        via iptables and BYPASSES UFW for published ports — UFW here guards
#        host services (SSH etc.); container exposure is governed by the
#        compose port mappings, which Correlix keeps to the documented set.
#
# Non-Debian distros: apply the equivalents with your package manager;
# ./install-correlix.sh verifies the result either way.

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

CHECK=0; FIREWALL=0
for a in "$@"; do case "$a" in
  --check) CHECK=1 ;;
  --firewall) FIREWALL=1 ;;
  -h|--help) sed -n '3,60p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  *) echo "unknown arg: $a (see --help)" >&2; exit 2 ;;
esac; done

BOLD=$'\033[1m'; GREEN=$'\033[32m'; RED=$'\033[31m'; YELLOW=$'\033[33m'; RST=$'\033[0m'
[ -t 1 ] || BOLD='' GREEN='' RED='' YELLOW='' RST=''
FIXES=0
pass(){ printf '  %sPASS%s  %s\n' "$GREEN" "$RST" "$1"; }
fixd(){ printf '  %sFIXED%s %s\n' "$GREEN" "$RST" "$1"; }
need(){ printf '  %sFIX%s   %s\n' "$YELLOW" "$RST" "$1"; FIXES=$((FIXES+1)); }

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
echo "${BOLD}== Correlix host preparation$( [ $CHECK = 1 ] && echo ' — AUDIT ONLY (--check)' )${RST}"

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
MISSING_PKGS=""
for p in zstd python3 curl; do command -v "$p" >/dev/null || MISSING_PKGS="$MISSING_PKGS $p"; done
if [ -z "$MISSING_PKGS" ]; then pass "zstd, python3, curl present"
elif [ "$CHECK" = 1 ]; then need "missing packages:$MISSING_PKGS"
else apt-get install -y -qq $MISSING_PKGS ca-certificates && fixd "installed:$MISSING_PKGS"; fi

# ---------- 3) time sync -------------------------------------------------
if timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -q yes; then
  pass "clock is NTP-synchronized"
elif [ "$CHECK" = 1 ]; then need "clock not NTP-synchronized (will enable systemd-timesyncd)"
else systemctl enable --now systemd-timesyncd 2>/dev/null || true; fixd "systemd-timesyncd enabled (verify sync with: timedatectl)"; fi

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
else apt-get install -y -qq unattended-upgrades && dpkg-reconfigure -f noninteractive unattended-upgrades >/dev/null 2>&1 || true; fixd "unattended-upgrades installed + enabled"; fi

# ---------- 13) firewall (opt-in) ----------------------------------------------
if [ "$FIREWALL" = 1 ]; then
  if [ "$CHECK" = 1 ]; then
    ufw status 2>/dev/null | grep -q "Status: active" && pass "UFW active" || need "UFW not active (would default-deny + allow SSH/8000/ingest ports)"
  else
    apt-get install -y -qq ufw
    ufw allow OpenSSH >/dev/null              # NEVER lock out the operator
    ufw allow 8000/tcp >/dev/null             # Correlix UI
    ufw allow 5514/tcp >/dev/null; ufw allow 5514/udp >/dev/null   # syslog
    for p in 2055 4739 6343 1162; do ufw allow "$p"/udp >/dev/null; done  # flows/traps
    ufw default deny incoming >/dev/null; ufw default allow outgoing >/dev/null
    ufw --force enable >/dev/null
    fixd "UFW enabled: deny-in default; SSH, 8000/tcp, ingest ports allowed"
  fi
fi

# ---- PATH alias: `install-correlix` works from anywhere ----------------
SELF_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
if [ -x "$SELF_DIR/install-correlix.sh" ]; then
  if [ "$CHECK" = 1 ]; then
    [ "$(readlink -f /usr/local/bin/install-correlix 2>/dev/null)" = "$SELF_DIR/install-correlix.sh" ]       && pass "command alias 'install-correlix' on PATH"       || need "command alias 'install-correlix' (symlink to this bundle)"
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
echo "${GREEN}${BOLD}== Host is ready for Correlix.${RST}"
if [ "$RELOGIN" = 1 ]; then
  echo "   1. Log out and back in (docker group membership takes effect)."
  echo "   2. Run: ./install-correlix.sh"
else
  echo "   Run: ./install-correlix.sh"
fi
echo "   (Recommended: install as the service account —  sudo -iu correlix)"
