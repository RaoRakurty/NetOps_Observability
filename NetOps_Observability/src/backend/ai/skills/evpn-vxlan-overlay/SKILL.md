---
name: evpn-vxlan-overlay
layer: wan_overlay
version: 1
source: https://github.com/automateyournetwork/netclaw/blob/cfafa46c3227356ca6ef38261fa9c1f4ba4711cb/workspace/skills/evpn-vxlan-fabric/SKILL.md
when_to_use: evpn, vxlan, vtep, vtep down, vni, vni down, nve peer down, nve down, fabric overlay, anycast gateway, silent host, type-2 route, type-5 route, ethernet segment, esi, leaf cannot reach, leaf spine overlay
applies_when: fact:role=dc_leaf|dc_spine
symptom_kinds: evpn, vxlan
tools: get_device_state, get_rca_verdict, get_topology_context, search_logs, get_recent_changes
gather:
  - get_device_state(device_id, area=evpn)
  - get_rca_verdict(correlation_id)
  - get_topology_context(device_id)
  - search_logs(device, window=6h)
  - get_recent_changes(device, window=24h)
look_for:
  - The underlay first. Two VTEPs that cannot reach each other's loopbacks over the underlay cannot carry overlay traffic, whatever the EVPN tables say. An interface or routing fault beneath the fabric comes before any overlay reasoning.
  - The VTEP peers this switch has learned. A peer that is missing here cannot receive this switch's traffic.
  - The VNIs and their state — a VNI that is down, or mapped to the wrong VLAN or VRF, isolates one segment while the rest of the fabric is healthy.
  - The EVPN control plane. EVPN routes ride BGP; a BGP session down between a leaf and its route reflectors withdraws the routes the overlay forwards on.
  - Route evidence, not assumption — a host is reachable through the fabric only when its MAC/IP route is learned. Say what was read and what was not.
  - The fabric reads here are raw, not parsed. Quote what the switch printed; do not invent counts.
decisions:
  - next=interface-down when verdict:phrase=interface the engine's verdict names an interface, so the underlay beneath the fabric is the next check
  - next=bgp-session-down when verdict:phrase=bgp the engine's verdict names BGP, which carries the EVPN routes the overlay forwards on
  - next=log-confirmation when state:collect=not_wired the fabric's live state could not be read, so the switch's own messages are the evidence left
  - verdict=say whether the underlay between the VTEPs is intact, name the VTEP peers and VNIs as the switch printed them (raw, not parsed), say whether the EVPN control plane is up, and name the segment the fault isolates
  - escalate=the data-centre fabric owner with the switch, the VTEP peers and VNIs as printed, and the underlay state attached
---

# EVPN-VXLAN overlay

An EVPN-VXLAN fabric has three things that can fail, in a fixed order of
dependency: the IP underlay between the switches, the BGP control plane that
carries the EVPN routes, and the VXLAN data plane that forwards on them.

**Underlay before overlay.** Two VTEPs that cannot reach each other's loopbacks
cannot carry overlay traffic. When the engine names an interface beneath the
fabric, that interface is the next check — not the overlay.

**Then the control plane.** EVPN routes ride BGP. A leaf that lost its BGP
sessions to the route reflectors loses the routes its overlay forwards on.

**Then the VTEPs and VNIs.** The switch's own list of VTEP peers and VNIs says
which segments it can carry. A missing peer or a down VNI isolates exactly what
it carries while the rest of the fabric stays healthy.

**Raw, not parsed.** No fabric output has been captured to build a parser from,
so the switch's output is quoted as it was printed. Never turn it into counts
the switch did not print.

**Not a fabric switch, not this method.** When Correlix has discovered the device
as something other than a data-centre leaf or spine, the method does not apply
and says so.

Method re-expressed from NetClaw's EVPN/VXLAN fabric workflow (Apache-2.0, see NOTICE).
