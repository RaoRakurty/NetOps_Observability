#!/usr/bin/env bash
# Build + run tgen as a container ON the lab host (10.70.245.120), pointed at the
# NMS collector. Run this FROM the traffic-generator/ dir (it ships itself over
# ssh, builds the image on the lab host, and starts it).
#
#   ./deploy.sh                         # build + run (mode=all, fps=1500)
#   ./deploy.sh --mode ipfix --fps 4000 --apps AI,Collaboration
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

echo "→ shipping source to $LAB_USER@$LAB_HOST:~/tgen-src"
ssh_ "mkdir -p ~/tgen-src"
scp_ "$SD/Dockerfile" "$SD/config.yaml" "$SD/tgen" "$LAB_USER@$LAB_HOST:~/tgen-src/"

echo "→ building image on the lab host"
ssh_ "cd ~/tgen-src && echo $LAB_PASS | sudo -S docker build -t tgen:latest ."

echo "→ (re)starting container (collector=$COLLECTOR)"
ssh_ "echo $LAB_PASS | sudo -S docker rm -f $NAME 2>/dev/null || true"
# host networking so flow datagrams egress with the lab source; NET_RAW for packets mode.
ssh_ "echo $LAB_PASS | sudo -S docker run -d --name $NAME --network host --cap-add NET_RAW \
      --restart unless-stopped tgen:latest --mode ${MODE:-all} --collector $COLLECTOR \
      --fps ${FPS:-1500} --workers ${WORKERS:-2} ${EXTRA_ARGS:-} ${*:-}"

echo "→ running. logs:"
ssh_ "echo $LAB_PASS | sudo -S docker logs --tail 8 $NAME" || true
