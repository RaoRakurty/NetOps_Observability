---
id: isis-adjacency-issue
title: IS-IS Adjacency Issue
fault_domains: routing, isis, control-plane, igp, fabric
signals: device_isis_adj_state, isis_adjacency_change
keywords: isis, is-is, adjacency, level-1, level-2, fabric, igp, lsp, hello, spine, leaf
owner: Network / Routing
---

# IS-IS Adjacency Issue

## Symptoms
- IS-IS adjacency not Up on a fabric link (spine/leaf or core).
- Level-1/Level-2 adjacency mismatch; LSPs not exchanged.
- Underlay reachability gaps in the fabric.

## Common fault domains
- L1/L2 link fault under the adjacency.
- MTU too small for the LSP / hello padding.
- Level mismatch (L1 vs L2), area/system-id, or authentication mismatch.
- Interface not enabled for IS-IS on one side.

## Correlix evidence to check
- device_isis_adj_state (3 = Up), labelled by ifName + isis_neighbor.
- Interface MTU, errors, and flaps on the fabric link.
- Syslog adjacency-change events on the device/window.

## Supporting evidence
- Coincident fabric-link flap → link-driven.
- Hello-padding/MTU error or small MTU → MTU-driven.

## Contradicting evidence
- Adjacency Up but routes missing → SPF/LSP or redistribution issue.
- Only one level affected → level/area config, not the link.

## Missing evidence
- Far-end level/area/auth config not visible.
- LSDB consistency not directly observable from counters.

## Recommended owner
Network / Routing (fabric).

## Next actions
1. Identify the fabric link and the stuck level.
2. Verify MTU is large enough for LSPs / hello padding.
3. Compare level, area/system-id, and auth on both ends.
4. Check the link for L1/L2 errors or flaps.
5. Confirm underlay reachability restores when Up.

## Escalation note
IS-IS adjacency on <device> <if> to <neighbor> down since <start UTC>. Level <l>. MTU <a>/<b>. Link <state>.

## ITSM note template
IS-IS adjacency <device> <if> ↔ <neighbor> down (<state>) since <start UTC>. Suspected <mtu | level | link | auth>. Fabric reachability impact: <scope>.
