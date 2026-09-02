---
name: bgp-prefix-missing
layer: bgp
version: 1
when_to_use: prefix missing, route not advertised, route not received, bgp not advertising, prefix not in table, route missing, not learning routes, best path wrong
symptom_kinds: bgp, routing, policy, reachability
tools: run_protocol_diagnostic, get_rca_verdict, get_topology_context, search_logs
gather:
  - get_rca_verdict(correlation_id)
  - run_protocol_diagnostic(device_id, protocol=bgp, issue_id=bgp-prefix-not-exchanged)
  - get_topology_context(device_id)
  - search_logs(device, query=BGP, window=24h)
look_for:
  - Whether the session is Established first. A missing prefix on a session that is not up is the session's fault, not policy.
  - Whether the prefix is received-but-filtered, received-and-hidden by a better path, or never received at all. These are three different owners.
  - Outbound policy on the sending side and inbound policy on the receiving side, including prefix-list, route-map and maximum-prefix state.
  - Next-hop reachability. A received prefix whose next hop is unresolvable is valid but never installed, which looks identical to "missing" from the routing table.
decisions:
  - next=bgp-session-down when the session is not Established
  - next=path-seam-handoff when the missing prefix belongs to a partner or provider we do not control
  - next=log-confirmation when signature=none the prefix diagnostic ran and no known signature matched, so a maximum-prefix or policy event must be pinned from the device's own words
  - verdict=state which of the three cases applies — never received, received and filtered, or received and not best — and name the policy or next hop responsible
  - escalate=the advertising party when the prefix was never received and our inbound policy is clean
---

# BGP prefix missing

"The route is gone" is four different faults. Separating them is the whole job.

**Establish the session first.** If the peer is not Established, stop; that is
the fault and it belongs to the session skill.

**Then place the prefix in one of three buckets.**

- Never received — the sender did not advertise it, or an inbound filter dropped
  it before it was stored. The owner is the sender, or our inbound policy.
- Received and filtered — it arrived and our policy rejected it. The owner is us,
  and the exact clause is nameable.
- Received and not best — it is in the table but another path won. The owner is
  path selection, and the answer is which attribute decided it (weight, local
  preference, AS path length, origin, MED, eBGP over iBGP, IGP metric to the next
  hop, in that order).

**Unresolvable next hop is the silent fourth case.** The prefix is valid, present,
and not installed because the next hop cannot be reached. Check this before
blaming policy — it is an IGP fault wearing a BGP costume.

**Name the clause, not the concept.** "Filtered by inbound policy" is a
hypothesis; naming the prefix-list or route-map the evidence shows is a finding.
