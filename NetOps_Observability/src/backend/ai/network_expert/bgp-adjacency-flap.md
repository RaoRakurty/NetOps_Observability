---
id: bgp-adjacency-flap
title: BGP Adjacency / Session Flap
fault_domains: routing, bgp, control-plane, wan, peering
signals: device_bgp_peer_state, device_bgp_fsm_transitions, device_bgp_pfx_in, bgp_session_down
keywords: bgp, peer, session, flap, neighbor, prefix, withdraw, established, routing, idle, active
owner: Network / Routing
---

# BGP Adjacency / Session Flap

## Symptoms
- BGP peer leaves Established (Idle/Active/Connect) repeatedly.
- FSM established-transition counter increments; prefixes withdraw and re-advertise.
- Reachability for prefixes behind the peer is intermittent.

## Common fault domains
- Underlying link / interface flap carrying the session.
- Hold-timer expiry from CPU pressure, control-plane policing, or MTU on the TCP session.
- Policy / max-prefix limit tripping the session down.
- Provider-side reset on an eBGP edge.

## Correlix evidence to check
- device_bgp_peer_state (6 = Established) over time for the peer.
- device_bgp_fsm_transitions rate (flap counter).
- The carrying interface's oper-status and error counters.
- Correlated syslog (%BGP-5-ADJCHANGE) on the same device/window.

## Supporting evidence
- Interface down/flap coincides with the session drop (link-driven).
- max-prefix or hold-timer syslog at the drop time (control-plane-driven).

## Contradicting evidence
- Interface stays up and clean across the flap → not link-driven; suspect policy/CPU/MTU.
- Only one direction's prefixes affected → suspect policy/route-map, not the session.

## Missing evidence
- No peer-side view (eBGP) — correlate your interface + syslog and escalate.
- No TCP-MSS/MTU probe on the session path.

## Recommended owner
Network / Routing.

## Next actions
1. Establish the flap cadence from the transition counter.
2. Check the carrying interface for coincident flaps/errors.
3. Inspect syslog for hold-timer / max-prefix / notification causes.
4. For eBGP, validate path MTU and provider state.
5. If link-driven, hand off to the link/optical owner; if policy, review max-prefix/route-maps.

## Escalation note
Peer <ip/asn> on <device> flapping every <interval> since <start UTC>; transitions=<n>. Suspected cause: <link | hold-timer | max-prefix | provider>. Interface <if> <clean/flapping>.

## ITSM note template
BGP peer <ip> (AS<n>) on <device> flapping since <start UTC>, <n> transitions. Carrying interface <if> <state>. Likely <cause>. Prefix impact: <count> withdrawn.
