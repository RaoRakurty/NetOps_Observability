---
id: ospf-neighbor-down
title: OSPF Neighbor Down / Stuck
fault_domains: routing, ospf, control-plane, igp
signals: device_ospf_nbr_state, device_ospf_if_state, ospf_adjacency_change
keywords: ospf, neighbor, adjacency, exstart, exchange, init, two-way, full, dr, bdr, igp, area, hello
owner: Network / Routing
---

# OSPF Neighbor Down / Stuck

## Symptoms
- OSPF neighbor not Full (Down/Init/2-Way/ExStart/Exchange).
- Routes via the neighbor disappear or never install.
- Stuck in ExStart/Exchange points at MTU mismatch.

## Common fault domains
- Layer-1/2 link issue under the adjacency.
- MTU mismatch (classic ExStart/Exchange hang).
- Hello/dead-interval, area-id, auth, or network-type mismatch.
- DR/BDR election problem on a multi-access segment.

## Correlix evidence to check
- device_ospf_nbr_state (8 = Full) and device_ospf_if_state over time.
- Interface MTU on both ends; interface errors/flaps.
- Syslog %OSPF adjacency-change with the reason.

## Supporting evidence
- ExStart/Exchange stall + differing interface MTU → MTU mismatch.
- Coincident interface flap → link-driven.

## Contradicting evidence
- Adjacency Full but routes missing → LSA/area/filtering issue, not the adjacency.
- Only one neighbor on a shared segment affected → local-pair config, not the segment.

## Missing evidence
- No far-end config visibility for timer/area/auth comparison.
- No MTU probe across the segment.

## Recommended owner
Network / Routing.

## Next actions
1. Read the stuck state — ExStart/Exchange ⇒ check MTU first.
2. Compare hello/dead, area-id, network-type, auth on both ends.
3. Check the interface for L1/L2 errors or flaps.
4. Validate DR/BDR election on multi-access segments.
5. Confirm route install once Full returns.

## Escalation note
OSPF adjacency on <device>/<if> stuck in <state> since <start UTC>. MTU <a>/<b>. Interface <clean/errored>. Likely <mtu | timer | link | auth>.

## ITSM note template
OSPF neighbor on <device> interface <if> down/stuck (<state>) since <start UTC>. Suspected <cause>. Route impact: <prefixes/area>.
