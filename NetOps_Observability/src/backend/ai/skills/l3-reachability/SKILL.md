---
name: l3-reachability
layer: igp
version: 1
source: https://github.com/automateyournetwork/netclaw/blob/cfafa46c3227356ca6ef38261fa9c1f4ba4711cb/workspace/skills/pyats-troubleshoot/SKILL.md
when_to_use: cannot reach, can't reach, cant reach, unreachable from, no route to, destination unreachable, reachability problem, black hole, blackholed, traffic not getting through, is there a route
symptom_kinds: reachability, routing
tools: get_device_state, get_rca_verdict, get_topology_context, search_logs, get_recent_changes
gather:
  - get_device_state(device_id, area=routes, target=@prefix)
  - get_rca_verdict(correlation_id)
  - get_topology_context(device_id)
  - search_logs(device, window=6h)
  - get_recent_changes(device, window=24h)
look_for:
  - Whether the device has a route for the destination at all, read live from its routing table for the prefix in question. No route and a route to the wrong place are different faults; say which.
  - When the route is there, its next hop and how it was learned (connected, static, OSPF, IS-IS, BGP). A route learned the wrong way is often the whole story.
  - Whether the next hop itself is resolved — an address in the ARP or neighbour table. A route whose next hop never resolves forwards nothing.
  - Whether the route changed recently. A route that moved to a new next hop at the time of the complaint is the event; the reachability loss is its symptom.
  - Whether this device's configuration changed shortly before the symptom — a static route or a redistribution line changed is a classic cause, but a change that merely preceded it is correlated, not proven.
decisions:
  - next=bgp-prefix-missing when state:route=absent the device has no route for the destination, so the question is why the prefix was never learned or was filtered
  - next=interface-down when state:l2_entry=absent the next hop does not resolve in the device's ARP or neighbour table, so the link toward it is the next check
  - next=path-seam-handoff when state:route=present the device does hold a route for the destination, so whether traffic gets there is a question for the measured path beyond it
  - next=log-confirmation when state:collect=not_wired the routing table could not be read live, so the device's own words about route changes are the only evidence left
  - verdict=state whether the device holds a route for the destination, its next hop and protocol when it does, and whether that next hop resolves
  - escalate=the owner of the next hop's network, with the prefix, the route the device holds and the time it changed, when the next hop is outside our administration
---

# Layer-3 reachability

"Can't reach it" is a routing question before it is anything else, and the
device answers it directly.

**Ask the routing table first.** Look the destination up in the device's own
table, live. Three answers are possible and each sends the investigation
somewhere different: no route at all, a route via a next hop that does not
resolve, or a route that looks right. Never assume which one it is.

**No route is a learning problem.** The destination was never received, or it
was received and filtered, or a static route was removed. That is the BGP or
IGP method's question, not this one.

**A route is only as good as its next hop.** A next hop that has no ARP or
neighbour entry forwards nothing; the link toward it is the next check.

**A route that looks right hands off to the path.** When the device holds a
sensible route, whether traffic actually arrives is answered by the measured
path beyond it, hop by hop — not by pinging from the device, which Correlix
never does.

**The prefix must be in scope.** This method looks up the destination the
question names. When no prefix is in scope it says so and does not read the
whole routing table.

Method re-expressed from NetClaw's layer-3 decision tree (Apache-2.0, see NOTICE).
