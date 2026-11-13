---
name: sdwan-overlay
layer: wan_overlay
version: 1
source: https://github.com/automateyournetwork/netclaw/blob/cfafa46c3227356ca6ef38261fa9c1f4ba4711cb/workspace/skills/sdwan-ops/SKILL.md
when_to_use: lost its overlay, overlay down, sd-wan down, sdwan down, bfd down, bfd sessions down, omp down, control connections down, lost controllers, tloc down, sd-wan tunnels down, overlay tunnels down
applies_when: fact:adjacency=overlay
symptom_kinds: overlay, tunnel, wan
tools: get_overlay_state, get_rca_verdict, get_network_topology, get_topology_context, search_logs, get_recent_changes
gather:
  - get_rca_verdict(correlation_id)
  - get_overlay_state(device_id)
  - get_network_topology()
  - search_logs(device, window=6h)
  - get_recent_changes(device, window=24h)
look_for:
  - The control plane first — the edge's OMP sessions to its controllers. An edge that lost its controllers keeps forwarding on stale routes for a while and then loses them; BFD alone never shows it.
  - The data plane per transport colour — BFD sessions up against total on each transport. One transport fully down is that transport's link or circuit; every transport down with the controllers still up is the data plane alone.
  - Which remote edges this edge has lost every session to. One remote edge lost is that site's problem; many lost at once is this edge's.
  - The underlay before the overlay. A transport whose sessions are all down sits on an interface; that interface and its circuit come before any overlay reasoning.
  - Whether many edges changed at the same moment. A fleet-wide drop at one instant points at the controllers or a policy push, not at any one edge's circuit.
  - The edge's own BFD, control-connection and OMP messages in its log, quoted, and whether its configuration or a pushed template changed shortly before — a change that merely preceded the drop is correlated, not proven.
decisions:
  - next=interface-down when state:overlay_ctl=down the edge has lost every OMP session to its controllers, so its transport interfaces beneath the overlay are the next check
  - next=interface-down when state:overlay_bfd=partial one or more transports have lost their sessions while others are up, so the interface beneath the failed transport is the next check
  - next=log-confirmation when state:overlay_bfd=down every BFD session is down while the controllers are still reachable, so the edge's own data-plane messages must say why the tunnels dropped
  - next=log-confirmation when state:overlay_ctl=none the edge holds no control-plane session at all, so the device's own words about its controller connections are the only evidence left
  - verdict=name the control plane state (OMP sessions up against total), each transport with its sessions up against total, the remote edges lost, and whether the fault sits in the underlay, the data plane or the controllers
  - escalate=the circuit provider for a transport whose sessions are all down with its interface up, or the SD-WAN controller owner when many edges lost their controllers at once, with the times and counts attached
---

# SD-WAN overlay

An SD-WAN edge has three things that can fail, in a fixed order of dependency:
the transport beneath it, the control plane that tells it where to go, and the
data-plane tunnels between edges. Read them in that order.

**Control plane first.** OMP sessions to the controllers. An edge that lost them
still forwards on what it last learned, so it looks healthy until its routes
age out. Report the sessions up against total, never just "up".

**Then the data plane, per transport.** BFD sessions fold per transport colour.
One colour down with the others up is that transport's link or circuit — the
interface beneath it is the next check. Every colour down while the controllers
are still reachable is the data plane alone, and the edge's own messages must
say why.

**Underlay before overlay.** A tunnel cannot be healthier than the interface it
rides. When a transport's sessions are all down, look at its interface and its
circuit before any overlay theory.

**Many edges at once is not one edge's fault.** When many edges lose sessions in
the same minute, the shared part — the controllers, a policy or template push —
is the lead, not any one site's circuit.

**Not an overlay member, not this method.** When Correlix has discovered no
overlay sessions on the device, the method does not apply and says so.

Method re-expressed from NetClaw's SD-WAN operations workflow (Apache-2.0, see NOTICE).
