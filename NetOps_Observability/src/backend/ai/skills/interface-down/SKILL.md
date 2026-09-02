---
name: interface-down
layer: physical
version: 1
when_to_use: interface down, port down, link down, line protocol down, uplink down, circuit down, device unreachable, no link
symptom_kinds: physical, reachability, adjacency
tools: get_device_health, get_topology_context, get_rca_verdict, search_logs
gather:
  - get_rca_verdict(correlation_id)
  - get_device_health(device)
  - get_topology_context(device_id)
  - search_logs(device, query=LINK, window=6h)
look_for:
  - Whether the interface is administratively down or operationally down. Admin-down is a change; oper-down is a fault.
  - Whether the LINK PARTNER also reports the loss. One side down and the other up is an optic, a patch, or a duplex problem, not a device failure.
  - Flap count and the time of the last transition. A single clean transition points at a change; repeated transitions point at optics or power.
  - Whether the device itself stopped reporting. A device that went quiet in every collector is unreachable, not down on one port.
decisions:
  - next=optics-degraded when evidence:kind=metric an anomalous interface counter is present alongside the link event
  - next=ospf-adjacency when the link recovered and the IGP neighbour did not
  - next=bgp-session-down when the link recovered and the BGP peer did not
  - next=path-seam-handoff when the down link is the handoff to a provider
  - next=log-confirmation when the transition time must be pinned from the device's own words
  - verdict=name the interface, the device, the transition time and whether one or both ends see it
  - escalate=field or provider when the far end is not ours and both ends agree the link is down
---

# Interface down

The cheapest true answer in networking: something below you is not passing
frames. Confirm that before reasoning about anything above it.

**Admin versus operational.** `admin down` is somebody's decision and belongs in
the change timeline, not the fault tree. `oper down` with `admin up` is the real
fault. Say which one you saw.

**Always check the far end.** A one-sided down is the classic tell for a failed
transceiver, a bad patch, or a speed/duplex mismatch. A two-sided down is a cut,
a power event, or a provider outage. This single comparison decides who owns it.

**Flaps are a different fault.** A port that has transitioned repeatedly is not
"down" — it is unstable, and the instability, not the current state, is the
finding. Report the flap count and the window.

**A quiet device is not a down port.** If reachability, SNMP and syslog all
stopped together, the device is unreachable and you are looking at its parent's
interface, not at this one.
