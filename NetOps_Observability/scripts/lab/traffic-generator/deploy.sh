#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

# Build + run tgen as a container ON the lab host (10.70.245.120), pointed at the
# NMS collector. Run this FROM the traffic-generator/ dir (it ships itself over
# ssh, builds the image on the lab host, and starts it).
#
#   ./deploy.sh                         # serve mode: dashboard+API on :8080, encoders autostarted
#   MODE=ipfix FPS=4000 ./deploy.sh --apps AI,Collaboration   # headless one-shot run
#   ./deploy.sh --stop                  # stop + remove the container
set -euo pipefail

LAB_HOST="${LAB_HOST:-10.70.245.120}"
LAB_USER="${LAB_USER:-rao}"
LAB_PASS="${LAB_PASS:-rao123}"
COLLECTOR="${TGEN_COLLECTOR:-10.70.245.122}"
NAME=tgen
SD="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ssh_() { sshpass -p "$LAB_PASS" ssh -o StrictHostKeyChecking=no "$LAB_USER@$LAB_HOST" "$@"; }
scp_() { sshpass -p "$LAB_PASS" scp -o StrictHostKeyChecking=no -r "$@"; }

if [ "${1:-}" = "--stop" ]; then
  ssh_ "echo $LAB_PASS | sudo -S docker rm -f $NAME" 2>/dev/null || true
  echo "stopped $NAME"; exit 0
fi

if [ ! -f "$SD/webui/dist/index.html" ] || [ -n "$(find "$SD/webui/src" -newer "$SD/webui/dist/index.html" 2>/dev/null)" ]; then
  echo "→ building dashboard (webui/dist stale or missing)"
  (cd "$SD/webui" && npm install --silent && npm run build)
fi

echo "→ shipping source to $LAB_USER@$LAB_HOST:~/tgen-src"
ssh_ "mkdir -p ~/tgen-src/webui"
scp_ "$SD/Dockerfile" "$SD/config.yaml" "$SD/tgen" "$LAB_USER@$LAB_HOST:~/tgen-src/"
scp_ "$SD/webui/dist" "$LAB_USER@$LAB_HOST:~/tgen-src/webui/"

echo "→ building image on the lab host"
ssh_ "cd ~/tgen-src && echo $LAB_PASS | sudo -S docker build -t tgen:latest ."

echo "→ (re)starting container (collector=$COLLECTOR)"
ssh_ "echo $LAB_PASS | sudo -S docker rm -f $NAME 2>/dev/null || true"
# host networking so flow datagrams egress with the lab source; NET_RAW for packets mode.
# Default = serve mode: control API + dashboard on :${API_PORT:-8080}, autostarted
# encoders. Set MODE=<ipfix|netflow9|sflow|packets|l7|all> for a headless one-shot run.
if [ -n "${MODE:-}" ]; then
  RUN_ARGS="--mode $MODE --collector $COLLECTOR --fps ${FPS:-200} --workers ${WORKERS:-2}"
else
  RUN_ARGS="--serve --api-port ${API_PORT:-8080} --collector $COLLECTOR --fps ${FPS:-200} --workers ${WORKERS:-2}"
fi
ssh_ "echo $LAB_PASS | sudo -S docker run -d --name $NAME --network host --cap-add NET_RAW \
      --restart unless-stopped tgen:latest $RUN_ARGS ${EXTRA_ARGS:-} ${*:-}"

echo "→ running. logs:"
ssh_ "echo $LAB_PASS | sudo -S docker logs --tail 8 $NAME" || true
[ -z "${MODE:-}" ] && echo "→ dashboard: http://$LAB_HOST:${API_PORT:-8080}/"
