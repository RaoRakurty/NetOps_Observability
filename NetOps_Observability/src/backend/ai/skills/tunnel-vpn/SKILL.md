---
name: tunnel-vpn
layer: wan_overlay
version: 2
source: https://github.com/automateyournetwork/netclaw/blob/cfafa46c3227356ca6ef38261fa9c1f4ba4711cb/workspace/skills/fortigate-ops/SKILL.md
when_to_use: tunnel down, tunnel is down, is the tunnel up, vpn down, vpn is down, ipsec down, ipsec tunnel, gre tunnel, site to site vpn, vpn not passing traffic, tunnel flapping
symptom_kinds: tunnel, vpn, overlay
tools: get_device_state, get_tunnel_state, get_rca_verdict, get_topology_context, search_logs, get_recent_changes
gather:
  - get_rca_verdict(correlation_id)
  - get_device_state(device_id, area=interfaces)
  - get_device_state(device_id, area=vpn)
  - get_tunnel_state(device_id)
  - search_logs(device, window=6h)
  - get_recent_changes(device, window=24h)
look_for:
  - Which of the device's tunnels are down and which are up, by far end and interface. One tunnel down is a peer or a path; every tunnel down is this device or its transport.
  - The interface the tunnels ride on, read live. A tunnel cannot be healthier than the transport beneath it.
  - Whether the tunnel negotiated and still passes nothing. The IPsec SA read shows, per peer, whether each direction has an active SA and what it has carried since it came up — an SA that has sent but never received is up and passing nothing back, the classic selector or proxy-ID mismatch or a far end dropping the return traffic. Where the SA read is not parsed for this platform, say plainly that negotiation and traffic cannot be told apart.
  - Whether the far end is reachable at all from this device — the underlay route toward the remote endpoint is the first check when every tunnel is down.
  - The device's own tunnel messages (IKE negotiation, dead-peer detection, rekey failures) in its log, quoted, with first and last occurrence.
  - Whether the device's configuration changed shortly before the tunnels dropped — a peer address, key or crypto policy line changed is the classic cause, but a change that merely preceded the drop is correlated, not proven.
decisions:
  - next=sdwan-overlay when state:tunnel_type=sdwan the device terminates SD-WAN tunnels, which are read through the overlay's control and data plane instead
  - next=interface-down when state:if_oper=down the interface beneath the tunnels is operationally down, so the transport is the fault, not the tunnel
  - next=l3-reachability when state:tunnel=down every tunnel on the device is down, so whether it can reach the far ends at all is the next check
  - next=log-confirmation when state:tunnel=partial some tunnels are down while others are up, so the device's own negotiation and dead-peer messages must name which peer failed and how
  - next=log-confirmation when state:ipsec_sa=inactive a protected flow has no active SA in one direction, so the device's own negotiation and rekey messages must say why phase 2 did not complete
  - next=l3-reachability when state:ipsec_sa=one_way a flow has sent traffic but never received any back, so whether the far end and the return path are reachable is the next check
  - verdict=name each tunnel that is down by far end and interface, the transport state beneath it, and whether the read could tell negotiation from traffic
  - escalate=the far end's owner — the partner, the provider or the site — with the tunnel, its state and the time it dropped, when the local transport and route read clean
---

# Tunnel and VPN

A tunnel has two failure modes that look the same from far away and are fixed
in different places: it never came up, or it came up and passes nothing.

**Read the tunnels, then the transport beneath them.** Every tunnel rides an
interface; a down interface explains every tunnel on it. Read the interface
live before reasoning about crypto.

**One down or all down.** One tunnel down out of many points at that peer or
the path to it. Every tunnel down points at this device or its transport —
check the underlay route to the far ends next.

**Negotiation versus traffic.** IKE (phase 1) can be up while IPsec (phase 2)
is not, and a tunnel can read up while its selectors match nothing. When the
read only says up or down, say that the two cannot be told apart from it; do not
call a tunnel healthy because it reads up.

**SD-WAN is its own method.** An SD-WAN edge's tunnels are BFD sessions over
transports, governed by a control plane; they are read through the overlay
method, not this one.

**Exonerate the local side with evidence.** When the interface is up, the route
to the far end is present and only the far end's tunnel is down, hand it to the
far end's owner with the tunnel, its state and the time it dropped.

Method re-expressed from NetClaw's tunnel-phase rule (Apache-2.0, see NOTICE).
