#!/usr/bin/env bash
# deploy.sh — install the end-to-end HTTP traffic generator onto a LAB CLIENT
# that sits BEHIND a clos leaf, and run it as a systemd service. Ships the
# stdlib script + your filled endpoints.conf over ssh, installs to
# /opt/cloud-edge-traffic, and enables cloud-edge-traffic.service.
#
# WHERE IT MUST RUN (this is the whole point — read README.md §"Why the client
# host matters"): CLIENT_HOST must be a host whose DEFAULT ROUTE egresses via
# leaf -> spine -> edge (.122) -> Internet, so its requests are REAL end-user
# traffic through the fabric. A host that reaches the clouds by some other NIC
# would light up the cloud logs but SKIP the fabric hops (dishonest path).
#
#   # 1. fill endpoints (post terraform apply) on your workstation:
#   cp endpoints.conf.example endpoints.conf && $EDITOR endpoints.conf
#   # 2. push + start on the lab client:
#   CLIENT_HOST=10.70.245.120 ./deploy.sh
#   ./deploy.sh --stop        # stop + disable the service
#   ./deploy.sh --status      # show service state + recent logs
#
# No secrets are shipped or embedded; endpoints.conf holds only public FQDNs.
set -euo pipefail

CLIENT_HOST="${CLIENT_HOST:-10.70.245.120}"   # MUST route via the leaf (see above)
CLIENT_USER="${CLIENT_USER:-rao}"
CLIENT_PASS="${CLIENT_PASS:-rao123}"          # lab default; override via env
DEST=/opt/cloud-edge-traffic
SVC=cloud-edge-traffic.service
SD="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ssh_() { sshpass -p "$CLIENT_PASS" ssh -o StrictHostKeyChecking=no "$CLIENT_USER@$CLIENT_HOST" "$@"; }
scp_() { sshpass -p "$CLIENT_PASS" scp -o StrictHostKeyChecking=no "$@"; }
sudo_() { ssh_ "echo '$CLIENT_PASS' | sudo -S $*"; }

case "${1:-}" in
  --stop)
    sudo_ "systemctl disable --now $SVC" 2>/dev/null || true
    echo "stopped $SVC on $CLIENT_HOST"; exit 0 ;;
  --status)
    sudo_ "systemctl status $SVC --no-pager -l" || true
    echo "--- recent logs ---"
    sudo_ "journalctl -u $SVC -n 30 --no-pager" || true
    exit 0 ;;
esac

if [ ! -f "$SD/endpoints.conf" ]; then
  echo "ERROR: $SD/endpoints.conf not found." >&2
  echo "  cp endpoints.conf.example endpoints.conf && edit it with real endpoints" >&2
  echo "  (from 'terraform output' in correlix-faultlab-iac/environments/edge-demo)" >&2
  exit 1
fi

echo "→ staging $DEST on $CLIENT_USER@$CLIENT_HOST"
sudo_ "mkdir -p $DEST && chown $CLIENT_USER $DEST"
echo "→ shipping script + config + unit"
scp_ "$SD/cloud_edge_traffic.py" "$CLIENT_USER@$CLIENT_HOST:$DEST/"
scp_ "$SD/endpoints.conf"        "$CLIENT_USER@$CLIENT_HOST:$DEST/"
scp_ "$SD/cloud-edge-traffic.service" "$CLIENT_USER@$CLIENT_HOST:/tmp/$SVC"

echo "→ installing + starting service"
sudo_ "install -m 0644 /tmp/$SVC /etc/systemd/system/$SVC && rm -f /tmp/$SVC"
sudo_ "systemctl daemon-reload && systemctl enable --now $SVC"
echo "→ started. recent logs:"
sudo_ "journalctl -u $SVC -n 12 --no-pager" || true
echo "→ tail live:  CLIENT_HOST=$CLIENT_HOST ./deploy.sh --status"
