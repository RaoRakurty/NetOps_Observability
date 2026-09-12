---
id: asymmetric-routing
title: Asymmetric Routing
fault_domains: routing, firewall, forwarding, wan
signals: flow_one_way, firewall_session_drop, route_change
keywords: asymmetric, asymmetry, one-way, return path, firewall drop, stateful, ecmp, return traffic
owner: Network / Routing
---

# Asymmetric Routing

## Symptoms
- Traffic works intermittently or only one direction; stateful firewall drops return traffic.
- One-way flows observed (forward seen, return absent or different path).
- TCP sessions fail to establish across a stateful device.

## Common fault domains
- Forward and return paths diverge across a stateful firewall.
- ECMP/route change sending return traffic a different way.
- Redistribution/metric change altering the return path.

## Correlix evidence to check
- Flow records showing forward without matching return (or different egress).
- Firewall session/deny logs for out-of-state drops.
- Recent route/topology changes on the return path.

## Supporting evidence
- Firewall out-of-state denies coincide with the user impact.
- Flow shows forward via path A, return via path B through a stateful device.

## Contradicting evidence
- Both directions traverse the same stateful device → not asymmetry; look elsewhere.
- No stateful device on the path → asymmetry alone may be benign.

## Missing evidence
- Full bidirectional flow may be unsampled — infer from one-way records.
- Firewall state table not directly exported.

## Recommended owner
Network / Routing (with Security if a firewall is in path).

## Next actions
1. Confirm forward and return path divergence from flows.
2. Check the stateful device for out-of-state drops.
3. Identify the route/ECMP change that split the paths.
4. Re-symmetrize (route policy) or allow the asymmetric flow on the firewall.
5. Validate session establishment after the fix.

## Escalation note
Asymmetric path for <src>↔<dst> since <start UTC>: forward via <A>, return via <B>; stateful drops at <fw>. Likely <route-change | ecmp | redistribution>.

## ITSM note template
Asymmetric routing affecting <flow/app> since <start UTC>. Forward <path A>, return <path B>, firewall <fw> dropping out-of-state. Fix: <re-symmetrize | firewall policy>.
