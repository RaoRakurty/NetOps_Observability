---
name: isis-adjacency
layer: igp
version: 1
when_to_use: isis, is-is, isis adjacency, isis neighbor, level-1, level-2, isis down, isis init, isis flapping
symptom_kinds: igp, adjacency, routing
tools: run_protocol_diagnostic, get_rca_verdict, get_topology_context, get_device_health, search_logs
gather:
  - get_rca_verdict(correlation_id)
  - run_protocol_diagnostic(device_id, protocol=isis, issue_id=isis-adjacency-down)
  - get_topology_context(device_id)
  - search_logs(device, query=ISIS, window=6h)
look_for:
  - Adjacency state and level. An adjacency stuck in INIT is hearing hellos without completing the handshake.
  - Level mismatch between the two ends, and area address agreement for Level-1 adjacencies.
  - MTU. IS-IS pads its hellos to the interface MTU, so an MTU mismatch prevents the adjacency from forming at all rather than degrading it.
  - Authentication and the interface circuit type, both of which fail quietly.
decisions:
  - next=interface-down when verdict:phrase=link the RCA verdict names the circuit beneath the adjacency
  - next=optics-degraded when the link is up but padded hellos could be corrupted
  - next=log-confirmation when signature=none the adjacency diagnostic ran and no known signature matched, so the transition times must be pinned from the device's own words
  - verdict=name the neighbour system id, the level, the state and the mismatch the signature identified
  - escalate=the routing owner with both ends' level and area named when the mismatch is on the far end
---

# IS-IS adjacency

IS-IS fails differently from OSPF in one way worth leading with: padded hellos.

**MTU is checked at hello time.** Because IS-IS pads its hellos to the full
interface MTU, an MTU mismatch stops the adjacency from ever forming rather than
stalling it partway. If the adjacency never came up at all on a link that is
otherwise healthy, MTU is the first hypothesis.

**Level and area must match.** A Level-1 adjacency requires the same area
address; a Level-2 adjacency does not. A device configured level-1 talking to one
configured level-2 will see the neighbour and never adjoin.

**INIT means one-way.** Same meaning as OSPF: hellos are heard in one direction
only. Look at inbound filtering and authentication on the far end.

**Cite the signature.** Name the catalogued signature that fired and quote the
line. If none fired, say so and present the captured output.
