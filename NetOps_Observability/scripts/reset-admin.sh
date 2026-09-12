#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

#
# reset-admin.sh — wipe the local user store and let the api container
# re-seed the admin user from the current ADMIN_INITIAL_PASSWORD in
# .env. Use this when you can't sign in because:
#
#   * `install.py --reset-env` was used after the admin was already
#     seeded (the old password stays in users.json).
#   * You forgot the admin password.
#   * users.json got corrupted.
#
# Reads ADMIN_INITIAL_PASSWORD from deployment/docker/.env and prints
# it at the end so you have it handy for the sign-in screen.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_DIR="$ROOT/deployment/docker"
USERS_FILE="$ROOT/data/api/users.json"
ENV_FILE="$COMPOSE_DIR/.env"

if [[ ! -f "$ENV_FILE" ]]; then
    echo "no .env at $ENV_FILE — run scripts/install.py first" >&2
    exit 1
fi

# 1. Remove users.json so api re-seeds on next start.
if [[ -f "$USERS_FILE" ]]; then
    sudo rm -f "$USERS_FILE"
    echo "→ removed $USERS_FILE"
else
    echo "→ no users.json present (will be created fresh)"
fi

# 2. Force-recreate the api container so it picks up the CURRENT .env.
# `docker compose restart` would not re-read env vars — it just bounces
# the existing container with whatever env it had at create time. That
# bug meant the api kept the old ADMIN_INITIAL_PASSWORD even after
# .env was rotated. --force-recreate guarantees a fresh env.
echo "→ recreating api with current .env"
(cd "$COMPOSE_DIR" && docker compose up -d --force-recreate api)

# Wait for the seed log line.
echo "→ waiting for api to seed admin…"
for _ in $(seq 1 15); do
    if docker compose -f "$COMPOSE_DIR/docker-compose.yml" logs api --tail=20 2>/dev/null \
       | grep -qE "(seeded|user|login)"; then
        break
    fi
    sleep 1
done

# 3. Show the credentials.
pw="$(grep -E '^ADMIN_INITIAL_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)"
user="$(grep -E '^ADMIN_USERNAME=' "$ENV_FILE" | cut -d= -f2-)"
host_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
port="$(grep -E '^BASE_PORT=' "$ENV_FILE" | cut -d= -f2-)"
port="${port:-8000}"

echo
echo "==============================================================="
echo "  Sign in:"
echo "    URL:  http://${host_ip:-localhost}:${port}"
echo "    User: ${user:-admin}"
echo "    Pass: ${pw}"
echo "==============================================================="
echo
echo "(Change the password from Settings > Change password after sign-in.)"
