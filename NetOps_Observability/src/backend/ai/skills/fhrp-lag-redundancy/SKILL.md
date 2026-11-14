---
name: fhrp-lag-redundancy
layer: l2
version: 1
source: https://github.com/automateyournetwork/netclaw/blob/cfafa46c3227356ca6ef38261fa9c1f4ba4711cb/workspace/skills/pyats-topology/SKILL.md
when_to_use: hsrp, vrrp, glbp, first hop redundancy, gateway failover, default gateway failover, standby router, active standby flapping, hsrp flapping, vrrp flapping, gateway flapping, failover did not happen, lacp, etherchannel, port-channel, port channel, lag down, bundle member down, member link down, eth-trunk, link aggregation
symptom_kinds: failover, aggregation
tools: get_device_state, get_rca_verdict, get_topology_context, search_logs, get_recent_changes
gather:
  - get_device_state(device_id, area=redundancy)
  - get_rca_verdict(correlation_id)
  - get_topology_context(device_id)
  - search_logs(device, window=6h)
  - get_recent_changes(device, window=24h)
look_for:
  - For a gateway group (HSRP / VRRP) — which router is active, which is standby, and whether both routers agree. Two routers that both claim active are a split, usually because they cannot hear each other.
  - How often the active role moved. A role that flaps tracks something underneath it — an uplink the group tracks, or the link between the two routers.
  - For a link bundle (LACP) — which members are bundled and which have dropped out, and whether both ends agree on the bundle. A member out of the bundle with its link up is a negotiation or configuration mismatch, not a cable.
  - The links beneath the group or bundle. A member or uplink that is down explains a failover; fix that before blaming the redundancy protocol.
  - MAC movement in the same window — a gateway flapping between routers, or a split bundle, moves MAC addresses between ports.
  - The reads here are raw, not parsed. Quote what the device printed; do not invent roles or counts.
decisions:
  - next=interface-down when verdict:phrase=link the engine's verdict names a link, so the member or uplink beneath the group is the next check
  - next=mac-flap when verdict:phrase=mac the engine's verdict names MAC movement, which a gateway flapping between routers or a split bundle produces
  - next=log-confirmation when state:collect=not_wired the redundancy groups could not be read live, so the device's own state-change messages are the evidence left
  - verdict=name each gateway group or link bundle as the device printed it (raw, not parsed), which router is active and which standby or which members are bundled and which dropped, how often it changed, and whether both sides agree
  - escalate=the campus or data-centre network owner with the group or bundle, both devices' views and the member links attached
---

# Gateway redundancy and link bundles

Redundancy that fails over is working; redundancy that flaps or splits is
telling you about something underneath it.

**Gateway groups (HSRP / VRRP).** Read which router is active and which is
standby, from both routers if possible. Both claiming active is a split: the two
routers cannot hear each other. A role that keeps moving follows something the
group tracks — an uplink — or the link between the routers.

**Link bundles (LACP).** Read which members are bundled and which dropped out,
and whether both ends agree. A member out of the bundle while its link is up is
a negotiation or configuration mismatch, not a bad cable.

**Look underneath first.** A down member or uplink explains a failover; it is
the next check before the redundancy protocol itself.

**Raw, not parsed.** No output has been captured here to build a parser from, so
the device's output is quoted as printed. Never turn it into roles or counts the
device did not print.

Method re-expressed from NetClaw's topology-mapping checklist (first-hop redundancy) and its LACP audit (Apache-2.0, see NOTICE).
