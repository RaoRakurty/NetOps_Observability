#!/usr/bin/env bash
#
# prepare-host.sh — one-command host preparation for Correlix (#97).
#
# Run this ONCE on a fresh Linux host, before ./install-correlix.sh:
#
#     sudo ./prepare-host.sh
#
# It installs/configures everything Correlix needs that a stock server
# image lacks (each step is idempotent — safe to re-run):
#
#   1) Docker Engine + Docker Compose v2 plugin   (from the distro repo;
#      falls back to Docker's official apt repo if the distro lacks compose v2)
#   2) zstd            (unpacks the image bundle)
#   3) python3         (runs the installer; present on most servers already)
#   4) vm.max_map_count=262144   (kernel setting OpenSearch requires —
#      without it the log-search store crash-loops on startup)
#   5) docker group membership for the invoking user
#
# Needs: Debian/Ubuntu family + network access to your package mirror.
# Other distros: install the equivalents of step 1-3 with your package
# manager, then apply steps 4-5 manually — install-correlix.sh will verify
# everything either way.
#
# After it finishes: LOG OUT AND BACK IN (docker group takes effect), then
# run ./install-correlix.sh — no network access is needed from then on.

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: run with sudo:  sudo ./prepare-host.sh" >&2
  exit 1
fi
if ! command -v apt-get >/dev/null 2>&1; then
  echo "ERROR: this script supports Debian/Ubuntu-family hosts (apt)." >&2
  echo "On other distros install: Docker Engine + Compose v2, zstd, python3," >&2
  echo "set vm.max_map_count=262144, and add your user to the docker group." >&2
  exit 1
fi

# The user who invoked sudo — they get docker group membership.
TARGET_USER="${SUDO_USER:-root}"

echo "== Correlix host preparation"

# ---- 1) Docker Engine + Compose v2 -----------------------------------------
if docker compose version >/dev/null 2>&1; then
  echo "-> docker + compose v2 already present: $(docker compose version --short 2>/dev/null)"
else
  echo "-> installing Docker Engine + Compose v2"
  apt-get update -qq
  # Prefer the distro packages (Ubuntu >=22.04 ships docker-compose-v2).
  if apt-get install -y -qq docker.io docker-compose-v2 2>/dev/null; then
    :
  else
    # Distro lacks compose v2 — use Docker's official repo.
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
  fi
  systemctl enable --now docker
fi

# ---- 2+3) zstd + python3 ----------------------------------------------------
echo "-> installing zstd + python3"
apt-get install -y -qq zstd python3

# ---- 4) kernel setting OpenSearch requires ----------------------------------
if [ "$(sysctl -n vm.max_map_count)" -lt 262144 ]; then
  echo "-> setting vm.max_map_count=262144 (required by the log-search store)"
  echo "vm.max_map_count=262144" > /etc/sysctl.d/99-correlix.conf
  sysctl --system >/dev/null
else
  echo "-> vm.max_map_count already sufficient ($(sysctl -n vm.max_map_count))"
fi

# ---- 5) docker group ----------------------------------------------------
if [ "$TARGET_USER" != "root" ]; then
  if id -nG "$TARGET_USER" | grep -qw docker; then
    echo "-> $TARGET_USER already in the docker group"
    RELOGIN=0
  else
    echo "-> adding $TARGET_USER to the docker group"
    usermod -aG docker "$TARGET_USER"
    RELOGIN=1
  fi
else
  RELOGIN=0
fi

echo
echo "== Host is ready for Correlix."
if [ "${RELOGIN:-0}" = 1 ]; then
  echo "   1. Log out and back in (docker group membership takes effect)."
  echo "   2. Run: ./install-correlix.sh"
else
  echo "   Run: ./install-correlix.sh"
fi
