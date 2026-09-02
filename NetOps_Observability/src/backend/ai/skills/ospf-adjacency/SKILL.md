---
name: ospf-adjacency
layer: igp
version: 1
when_to_use: ospf, ospf neighbor, adjacency stuck, exstart, exchange, ospf not full, ospf flapping, ospf down, igp adjacency
symptom_kinds: igp, adjacency, routing
tools: get_device_state, run_protocol_diagnostic, get_rca_verdict, get_topology_context, search_logs
gather:
  - get_device_state(device_id, area=igp)
  - get_rca_verdict(correlation_id)
  - run_protocol_diagnostic(device_id, protocol=ospf, issue_id=ospf-neighbor-stuck)
  - get_topology_context(device_id)
  - search_logs(device, query=OSPF, window=6h)
look_for:
  - The adjacency table read LIVE off the device. Never guess the state; the exact word the device prints is the tell.
  - The exact neighbour state. EXSTART or EXCHANGE is the classic IP MTU mismatch; INIT means hellos are heard one way only; DOWN means they are not heard at all.
  - Hello and dead interval, area id, and network type on BOTH ends. Any mismatch prevents the adjacency regardless of reachability.
  - Whether the underlying interface is clean. An IGP adjacency cannot be healthier than the link beneath it.
  - Authentication state, which fails silently on many platforms and produces a neighbour that never leaves INIT.
decisions:
  - next=interface-down when state:igp_nbr=none the device has no OSPF adjacency at all in this table, so the circuit beneath it is the next check
  - next=log-confirmation when state:collect=not_wired the adjacency table could not be read live, so the transition times must come from the device's own words
  - next=interface-down when signature=ospf-flap-l1 the adjacency is flapping with L1 errors on the interface beneath it
  - next=interface-down when verdict:phrase=link the RCA verdict names the link beneath the adjacency
  - next=optics-degraded when the link is up but errors could be dropping the larger database packets
  - next=log-confirmation when signature=none the adjacency diagnostic ran and no known signature matched, so the transition times must be pinned from the device's own words
  - verdict=name the neighbour, the stuck state and the mismatch the signature identified
  - escalate=the routing owner with both ends' parameters named when the mismatch is on the far end
---

# OSPF adjacency

An OSPF neighbour has exactly one healthy state, FULL. Everything else is a
specific, diagnosable stop.

**The state names the cause.** EXSTART or EXCHANGE means the database exchange
started and then stalled — on point-to-point links this is an IP MTU mismatch far
more often than anything else, because the larger database packets are the first
thing that will not fit. INIT means this router hears the neighbour's hellos but
the neighbour does not hear ours: one-way reachability, an inbound filter, or
authentication. Nothing at all means no hellos are arriving.

**Both ends or nothing.** Hello interval, dead interval, area, network type,
subnet mask and authentication must agree. Report the pair, not one side.

**Check below before reasoning above.** An adjacency over a link with rising
errors will fail intermittently in a way that looks like a protocol problem. The
protocol is fine; the link is not.

**Cite the signature.** When the protocol diagnostic matched a catalogued
signature, name it and quote the line it fired on. When nothing matched, say
that no known signature matched and show the captured output — never invent a
cause to fill the gap.
