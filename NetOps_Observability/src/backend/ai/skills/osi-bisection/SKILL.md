---
name: osi-bisection
layer: method
version: 1
when_to_use: something is broken, site is down, users complain, network slow, not working, where do i start, troubleshoot, investigate, unknown fault, no idea
symptom_kinds: unknown, general, triage
tools: get_rca_verdict, get_case_timeline, get_topology_context, get_active_major_incidents
gather:
  - get_rca_verdict(correlation_id)
  - get_case_timeline(correlation_id)
  - get_active_major_incidents()
  - get_topology_context(device_id)
look_for:
  - A correlation verdict already in scope. If the engine has concluded, START THERE and narrate its conclusion — do not re-derive a cause the engine already named.
  - Absent a verdict, work the layer order bottom-up and stop at the FIRST layer that explains the symptom: physical, then L2, then IGP, then BGP, then path/seam, then application. Logs confirm; they never lead.
  - Scope before mechanism: one interface, one device, one site, or many? A single-device symptom and a site-wide symptom are different faults with different owners.
  - Whether the evidence classes agree. Two independent classes agreeing is the threshold for "confirmed"; one class alone is "suspected" at best.
decisions:
  - next=interface-down when the symptom is one link, an interface counter, or a device that stopped reporting
  - next=optics-degraded when errors rise without the link going down
  - next=stp-topology when a whole L2 domain went unstable at once
  - next=mac-flap when hosts appear on more than one port
  - next=ospf-adjacency when an OSPF neighbour is not FULL
  - next=isis-adjacency when an IS-IS adjacency is not UP
  - next=bgp-session-down when a BGP peer is not Established
  - next=bgp-prefix-missing when the session is up but the prefix is absent
  - next=path-seam-handoff when the loss or latency sits on a hop we do not own
  - next=app-edge-5xx when the transport is clean and only one application is failing
  - next=security-exposure-context when the operator asks about exposure, posture, or a security finding
  - next=log-confirmation when a layer hypothesis needs a device's own words to confirm it
  - verdict=state the layer that explains the symptom, the scope it affects, and which evidence classes agree
  - escalate=say plainly which evidence is missing and which check would close the gap
---

# OSI bisection — the entry method

This is the top-level method, not a fault. Its job is to pick the RIGHT next
skill in one step rather than checking everything.

**Start from the engine, not from zero.** If a correlation case is in scope, its
verdict is the first fact: Correlix has already merged logs, metrics, flows and
paths for that window. Narrate what the engine concluded and use the layer order
only to decide what to check NEXT. Re-deriving a cause the engine already named
is how an assistant contradicts its own product.

**Absent a verdict, bisect.** Do not walk every layer. Ask which layer could
produce the reported symptom at the reported scope, check that one, and move on.
A symptom that survives at every layer is a scoping error, not a deep fault.

**Layer order and what each one owns**

- physical — link state, errors, optics, power, cabling. A physical fault
  explains everything above it, so it is checked first and, when found, ends the
  search.
- l2 — spanning tree, MAC learning, port security. L2 faults look like
  intermittent, bidirectional weirdness affecting a whole segment.
- igp — OSPF / IS-IS adjacency and LSDB. An IGP fault removes internal reach
  without removing link state.
- bgp — session state, then policy and prefix presence. A BGP fault removes
  external or inter-site reach with a healthy IGP.
- path_seam — the measured hop-by-hop path and who owns each hop. This is where
  "is it us or the provider" is answered, and it is the only layer that can
  exonerate the network.
- application — the service's own front door once transport is proven clean.
- logs — confirmation only.

**Honesty rules.** Name the scope before the mechanism. Say "possibly because of
X" when only one evidence class supports X. Never present a layer you did not
check as clean.
