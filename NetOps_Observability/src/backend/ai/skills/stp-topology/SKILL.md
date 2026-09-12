---
name: stp-topology
layer: l2
version: 1
when_to_use: spanning tree, stp, tcn, topology change, broadcast storm, loop, root bridge, blocking port, vlan unstable, l2 storm
symptom_kinds: l2, instability, broadcast
tools: get_device_state, get_metric_anomalies, get_topology_context, search_logs, get_rca_verdict
gather:
  - get_device_state(device_id, area=l2)
  - get_rca_verdict(correlation_id)
  - get_topology_context(device_id)
  - get_metric_anomalies()
  - search_logs(device, query=SPANTREE, window=6h)
look_for:
  - The device's own L2 tables, read live: repeated flushes leave an ARP/MAC cache that looks nothing like a stable domain's.
  - A burst of topology-change notifications rather than a single one. One TCN is a port coming up; a stream of them is instability.
  - Which port is the source of the change and whether it is an access port that should have been edge-configured.
  - Whether the root bridge moved. A root change re-converges the whole domain and explains a simultaneous, domain-wide symptom.
  - Broadcast and unknown-unicast rates on the affected VLANs, and whether MAC tables are being flushed repeatedly.
decisions:
  - next=log-confirmation when state:collect=not_wired the device's own L2 tables could not be read, so the change source must come from its logs
  - next=mac-flap when hosts are appearing on more than one port during the changes
  - next=interface-down when one specific port is flapping and driving every change
  - next=log-confirmation when the change source port must be read from the device's own words
  - verdict=name the VLAN or domain, the change rate, the source port if known, and whether the root moved
  - escalate=the LAN owner with the source port named when the churn originates on an access port
---

# Spanning tree and L2 topology churn

The signature is simultaneity: everything on a segment degrades at once, in both
directions, and recovers together. That pattern is L2, not routing.

**One change is normal. A stream is the fault.** Count the topology-change
notifications over a stated window and name the source port if the evidence
carries it. An access port that is not configured as an edge port will generate
a domain-wide change every time a laptop is unplugged.

**A root move explains everything at once.** If the root bridge changed, every
path in the domain was recomputed. Say so before speculating about anything
above L2 — nothing above L2 will make sense during a re-convergence.

**Distinguish churn from a loop.** Repeated changes with normal traffic rates
are churn. Changes accompanied by broadcast or unknown-unicast rates that climb
without bound are a forwarding loop, and a loop is an outage, not a degradation.

**Do not propose changing spanning tree.** This skill diagnoses. Any change to
root priority, edge configuration, or guards is a human decision on a change
ticket.
