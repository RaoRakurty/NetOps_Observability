#!/usr/bin/env bash
# capture-scenario.sh — the ONE-LINER the operator runs per scenario during the
# live capture window. Wraps capture.mjs to write the standard evidence-book
# shots for a <provider>/<scenario> in light mode at 2x DPI.
#
#   ./capture-scenario.sh <provider> <scenario> <phase>
#     provider : aws | azure | gcp
#     scenario : 1-dns 2-waf 3-lb-target 4-firewall 5-host-stop 6-tunnel 7-console-pivot
#     phase    : signal   -> 03-correlix-signal.png (Service View cloud lane)
#                rca      -> 04-correlix-rca.png     (Incidents / correlation)
#                recovery -> 05-recovery.png         (Service View after revert)
#                all      -> signal + rca (run this at peak fault)
#
# Examples:
#   ./capture-scenario.sh aws 2-waf all         # at fault peak
#   ./capture-scenario.sh aws 2-waf recovery    # after revert + soak
#
# The specific log-evidence shot (a cloud_*_log row zoomed) is captured
# separately once the operator has typed the lane query into Log Search:
#   node capture.mjs --route '#/logs/logs' --selector '.main' \
#     --out ../../docs/demos/cloud-fidelity-evidence/<provider>/<scenario>/03-correlix-signal.png
set -euo pipefail

PROV="${1:?provider (aws|azure|gcp)}"
SCEN="${2:?scenario dir, e.g. 2-waf}"
PHASE="${3:-all}"
SD="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTDIR="$SD/../../docs/demos/cloud-fidelity-evidence/$PROV/$SCEN"
mkdir -p "$OUTDIR"

# Canonical Correlix routes (verified against src/frontend/src/nav.tsx):
SIGNAL_ROUTE='#/monitoring/appobs'     # Service View — the cloud lane
RCA_ROUTE='#/monitoring/incidents'     # Incidents / correlation groups

shoot() { node "$SD/capture.mjs" --route "$1" --out "$2" "${@:3}"; }

case "$PHASE" in
  signal)   shoot "$SIGNAL_ROUTE" "$OUTDIR/03-correlix-signal.png" ;;
  rca)      shoot "$RCA_ROUTE"    "$OUTDIR/04-correlix-rca.png" ;;
  recovery) shoot "$SIGNAL_ROUTE" "$OUTDIR/05-recovery.png" ;;
  all)      shoot "$SIGNAL_ROUTE" "$OUTDIR/03-correlix-signal.png"
            shoot "$RCA_ROUTE"    "$OUTDIR/04-correlix-rca.png" ;;
  *) echo "unknown phase: $PHASE (signal|rca|recovery|all)" >&2; exit 2 ;;
esac
echo "→ wrote $PHASE shot(s) to $OUTDIR"
