---
name: network-design-read
layer: analysis
version: 1
source: https://github.com/automateyournetwork/netclaw/blob/cfafa46c3227356ca6ef38261fa9c1f4ba4711cb/workspace/skills/pyats-topology/SKILL.md
when_to_use: single point of failure, single points of failure, spof, how redundant, is the network redundant, is our network redundant, redundancy check, how resilient, network resilience, design review, network design review, review our design, explain our network design, explain the network design, if the circuit fails, if the mpls fails, if a link fails, what happens if a site loses, survive a failure, depends on one edge, depends on one transport
symptom_kinds: design, resilience
tools: get_network_topology, get_active_major_incidents
gather:
  - get_network_topology()
  - get_active_major_incidents()
look_for:
  - Underlay before overlay. The devices with their roles, sites and vendors, and the physical and routed links between them, come first; the overlay that rides them comes second.
  - Per site — how many WAN edges, how many uplinks, which transports. A site on one edge or on one transport is the commonest single point of failure, and it is OBSERVED, not inferred.
  - The single points of failure in the discovered links — a device or link whose loss would cut something off. They are DERIVED from what was discovered: an absent protocol is not an absent link, and with no links discovered none can be computed.
  - The redundancy that is visible (two edges, two transports) and the redundancy that is NOT collected (link aggregation, HSRP/VRRP). Uncollected redundancy is unknown, never missing.
  - For an SD-WAN estate — the overlay's shape, its transports, and which edge pairs hold no tunnel and why (edges in the same site build none to each other).
  - Whether an incident is active now. A design reading during an outage is about what that outage touched and what it spared.
  - What the reading could not see — its coverage — said plainly.
decisions:
  - next=scope-contrast when evidence:kind=finding an incident is active now, so the design reading continues as a contrast of what that incident touched and what it spared
  - verdict=describe the design in network terms, separating what was OBSERVED (devices, links, transports, sessions) from what is DERIVED (overlay shape, single points of failure, likely functions), name each single point of failure with what its loss would cut off, the redundancy present, and what the reading could not see
  - escalate=the network architect or site owner for each site that rides one WAN edge or one transport, with the site, the dependency and the evidence attached
---

# Reading the network's design

A design reading answers "how is this network built, and where would it
break?" in a network engineer's terms — not as a device list.

**Underlay first.** Devices, their roles and sites, and the links between them.
Then the overlay that rides those links: its shape, its transports, which pairs
hold tunnels and which do not, and why.

**Observed and derived are different statements.** A site with one WAN edge is
observed. A single point of failure computed from the discovered links is
derived — say "appears" or "likely" for it — and it cannot be computed when no
links were discovered. A protocol Correlix does not collect is unknown, never
absent: an uncollected HSRP pair is not a missing one.

**Name what would break.** For each single point of failure, say what its loss
would cut off. For each site on one edge or one transport, say so plainly.

**An active incident changes the question.** When something is broken right
now, the design reading turns into a contrast of what the incident touched and
what it spared.

**Say what the reading could not see.** Partial coverage is a finding in its
own right.

Method re-expressed from NetClaw's topology-mapping and IGP failure-analysis guidance (Apache-2.0, see NOTICE).
