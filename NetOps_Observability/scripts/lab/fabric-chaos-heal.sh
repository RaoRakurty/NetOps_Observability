#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

# =============================================================================
# fabric-chaos-heal.sh — telemetry/event generator for the clos-multivendor
# containerlab. Flaps fabric links hop-by-hop across the fabric to generate
# REAL syslog (LINK-3-UPDOWN, line-protocol, LLDP/adjacency churn) and exercise
# convergence — then ALWAYS auto-heals. A self-healing "nuts and bolts" loop:
# if anything is left down (even by Ctrl-C / kill), the EXIT trap restores it.
#
# Runs ON the lab host (10.70.245.120), talking to the nodes via `docker exec`
# (no per-vendor SSH needed for cEOS/SRL). Management interfaces are NEVER
# touched, so the box stays reachable and telemetry keeps flowing.
#
#   sudo ./fabric-chaos-heal.sh                 # one pass over the fabric, auto-heal
#   sudo ./fabric-chaos-heal.sh --rounds 0      # run forever (Ctrl-C heals on exit)
#   sudo ./fabric-chaos-heal.sh --hold 30 --gap 10
#   sudo ./fabric-chaos-heal.sh --heal-only     # panic button: restore everything, exit
#
# Flags:
#   --rounds N   passes over the fabric; 0 = infinite. default 1
#   --hold S     seconds a link stays DOWN before healing. default 20
#   --gap S      seconds between devices. default 8
#   --heal-only  just re-enable every managed interface and exit
# =============================================================================
set -uo pipefail

HOLD=20; GAP=8; ROUNDS=1; HEAL_ONLY=0
while [ $# -gt 0 ]; do case "$1" in
  --rounds) ROUNDS="${2:?}"; shift 2;;
  --hold)   HOLD="${2:?}";   shift 2;;
  --gap)    GAP="${2:?}";    shift 2;;
  --heal-only) HEAL_ONLY=1;  shift;;
  -h|--help) sed -n '2,24p' "$0"; exit 0;;
  *) echo "unknown arg: $1" >&2; exit 2;;
esac; done

P=clab-clos-multivendor

# Arista cEOS nodes → the fabric uplink to flap (a real data link, not mgmt).
CEOS_DEVS=(leaf1 leaf2 leaf3 leaf4 wan-r2)
CEOS_INTF=Ethernet1
# Nokia SR Linux spines → fabric interface.
SRL_DEVS=(spine1 spine2)
SRL_INTF=ethernet-1/1

log(){ echo "[$(date -u +%H:%M:%S)] $*"; }

# ceos_set <dev> <up|down> — shut / no-shut CEOS_INTF on a cEOS node.
ceos_set(){
  local dev="$1" act="$2" cmd
  [ "$act" = down ] && cmd="shutdown" || cmd="no shutdown"
  docker exec -i "${P}-${dev}" Cli -p 15 >/dev/null 2>&1 <<EOF
configure
interface ${CEOS_INTF}
${cmd}
end
EOF
}

# srl_set <dev> <up|down> — admin-disable / enable SRL_INTF on a spine.
srl_set(){
  local dev="$1" act="$2" st
  [ "$act" = down ] && st="disable" || st="enable"
  docker exec -i "${P}-${dev}" sr_cli >/dev/null 2>&1 <<EOF
enter candidate
set / interface ${SRL_INTF} admin-state ${st}
commit now
EOF
}

heal_all(){
  log "HEAL: restoring all managed fabric links"
  local d
  for d in "${CEOS_DEVS[@]}"; do ceos_set "$d" up; done
  for d in "${SRL_DEVS[@]}";  do srl_set  "$d" up; done
}
# Self-healing guarantee: whatever happens (normal end, Ctrl-C, kill), restore.
trap 'heal_all; exit' INT TERM
trap 'heal_all' EXIT

if [ "$HEAL_ONLY" = 1 ]; then heal_all; trap - EXIT; exit 0; fi

flap_ceos(){ local d="$1"; log "flap ${d}/${CEOS_INTF} DOWN"; ceos_set "$d" down; sleep "$HOLD"; log "flap ${d}/${CEOS_INTF} UP (heal)"; ceos_set "$d" up; }
flap_srl(){  local d="$1"; log "flap ${d}/${SRL_INTF} DOWN";  srl_set  "$d" down; sleep "$HOLD"; log "flap ${d}/${SRL_INTF} UP (heal)";  srl_set  "$d" up; }

round=0
while :; do
  round=$((round+1))
  log "===== round ${round} (hold=${HOLD}s gap=${GAP}s) ====="
  for d in "${CEOS_DEVS[@]}"; do flap_ceos "$d"; sleep "$GAP"; done
  for d in "${SRL_DEVS[@]}";  do flap_srl  "$d"; sleep "$GAP"; done
  if [ "$ROUNDS" != 0 ] && [ "$round" -ge "$ROUNDS" ]; then break; fi
done
log "complete — ${round} round(s); healing on exit"
