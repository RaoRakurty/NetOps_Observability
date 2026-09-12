#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

#
# bootstrap-ubuntu.sh — prepare a fresh Ubuntu / Debian host for the
# NetOps Observability stack.
#
# Installs Docker Engine + Compose v2 from Docker's official APT repo,
# applies the kernel sysctl that OpenSearch needs, and adds the
# invoking user to the docker group. Optionally opens UFW firewall
# ports for device-side ingestion.
#
# Idempotent: re-running after a successful install does nothing
# destructive.
#
# Usage:
#   sudo bash scripts/bootstrap-ubuntu.sh [--firewall] [--yes]
#
# Or simply:
#   python3 scripts/install.py
# ... which detects a missing Docker on Ubuntu/Debian and offers to run
# this script for you.

set -euo pipefail

# ---- argument parsing ------------------------------------------------------

FIREWALL=0
YES=0
for arg in "$@"; do
    case "$arg" in
        --firewall)  FIREWALL=1 ;;
        --yes|-y)    YES=1 ;;
        --help|-h)
            sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) echo "unknown arg: $arg" >&2; exit 2 ;;
    esac
done

# ---- preflight --------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "must be run as root. Try: sudo bash $0 $*" >&2
    exit 1
fi

if [[ ! -f /etc/os-release ]]; then
    echo "/etc/os-release missing — unsupported OS." >&2
    exit 1
fi
. /etc/os-release

case "$ID" in
    ubuntu|debian) ;;
    *)
        # Try ID_LIKE for derivatives.
        if [[ "${ID_LIKE:-}" != *"debian"* ]]; then
            echo "this script targets Ubuntu / Debian (got: $PRETTY_NAME)" >&2
            exit 1
        fi
        ;;
esac

case "${VERSION_ID:-}" in
    22.04|22.10|23.04|23.10|24.04|11|12) ;;   # known-good
    *) echo "WARN: untested on ${PRETTY_NAME}. Continuing anyway." ;;
esac

# ---- show the plan ----------------------------------------------------------

TARGET_USER="${SUDO_USER:-${USER:-root}}"

cat <<EOF

NetOps Observability — host bootstrap
=====================================
This script will:
  1) Remove any conflicting older docker packages (docker.io, etc.)
  2) Add Docker's official APT repo + GPG key
  3) Install: docker-ce, docker-ce-cli, containerd.io,
              docker-buildx-plugin, docker-compose-plugin, python3
  4) Set vm.max_map_count=262144 (required by OpenSearch)
  5) Add user "$TARGET_USER" to the docker group
EOF

if [[ $FIREWALL -eq 1 ]]; then
    echo "  6) Configure UFW: allow 8000/tcp, 514, 2055, 4739, 6343"
fi
echo

if [[ $YES -ne 1 ]]; then
    read -r -p "Proceed? [y/N] " ans
    case "${ans:-}" in
        y|Y|yes|YES) ;;
        *) echo "aborted."; exit 1 ;;
    esac
fi

# ---- step 1: remove conflicting packages ------------------------------------

echo
echo "→ removing conflicting legacy docker packages (if present)"
apt-get remove -y \
    docker docker-engine docker.io containerd runc docker-compose 2>/dev/null || true

# ---- step 2: prerequisites + Docker repo ------------------------------------

echo "→ installing prerequisites"
apt-get update -qq
apt-get install -y -qq ca-certificates curl gnupg lsb-release python3

echo "→ installing Docker's GPG key"
install -m 0755 -d /etc/apt/keyrings
curl -fsSL "https://download.docker.com/linux/${ID}/gpg" \
  | gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

echo "→ adding Docker apt repo"
ARCH="$(dpkg --print-architecture)"
CODENAME="$(. /etc/os-release && echo "${VERSION_CODENAME:-}")"
if [[ -z "$CODENAME" ]]; then
    CODENAME="$(lsb_release -cs)"
fi
echo "deb [arch=${ARCH} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${ID} ${CODENAME} stable" \
  > /etc/apt/sources.list.d/docker.list

# ---- step 3: install Docker -------------------------------------------------

echo "→ installing Docker Engine + Compose v2 plugin"
apt-get update -qq
apt-get install -y -qq \
    docker-ce docker-ce-cli containerd.io \
    docker-buildx-plugin docker-compose-plugin

systemctl enable --now docker
echo "→ Docker service: $(systemctl is-active docker)"

# ---- step 4: kernel sysctl --------------------------------------------------

echo "→ setting vm.max_map_count=262144 (for OpenSearch)"
echo "vm.max_map_count=262144" > /etc/sysctl.d/99-netops-opensearch.conf
sysctl --system >/dev/null
echo "   current: $(sysctl -n vm.max_map_count)"

# ---- step 5: docker group ---------------------------------------------------

if [[ "$TARGET_USER" != "root" ]] && id "$TARGET_USER" >/dev/null 2>&1; then
    echo "→ adding $TARGET_USER to docker group"
    usermod -aG docker "$TARGET_USER"
    GROUP_NOTICE=1
else
    GROUP_NOTICE=0
fi

# ---- step 6: UFW (optional) -------------------------------------------------

if [[ $FIREWALL -eq 1 ]]; then
    if command -v ufw >/dev/null; then
        echo "→ configuring UFW rules"
        ufw allow 8000/tcp comment 'NetOps dashboard' || true
        ufw allow 514/udp  comment 'NetOps syslog'    || true
        ufw allow 514/tcp  comment 'NetOps syslog'    || true
        ufw allow 2055/udp comment 'NetOps NetFlow'   || true
        ufw allow 4739/udp comment 'NetOps IPFIX'     || true
        ufw allow 6343/udp comment 'NetOps sFlow'     || true
        if ! ufw status | grep -q "Status: active"; then
            echo "   note: ufw not active — enable with 'sudo ufw enable' when ready."
        fi
    else
        echo "→ ufw not installed; skipping firewall step."
        echo "   apt-get install ufw, then re-run with --firewall."
    fi
fi

# ---- verify -----------------------------------------------------------------

echo
echo "==============================================================="
echo "  Installed:"
echo "    $(docker --version)"
echo "    $(docker compose version)"
echo "==============================================================="
echo

if [[ $GROUP_NOTICE -eq 1 ]]; then
    cat <<EOF
⚠  IMPORTANT
   $TARGET_USER is now in the docker group, but this shell session
   doesn't know that yet. Either:

     1. Log out and back in, OR
     2. Run:  newgrp docker

   Then continue with:
     python3 scripts/install.py
EOF
else
    echo "Next: python3 scripts/install.py"
fi
