---
name: bgp-session-down
layer: bgp
version: 1
when_to_use: bgp, bgp down, bgp neighbor down, peer down, bgp idle, bgp active, session not established, bgp flap, ebgp down, ibgp down
symptom_kinds: bgp, adjacency, routing, reachability
tools: get_device_state, run_protocol_diagnostic, get_rca_verdict, get_topology_context, search_logs, recall_investigations
gather:
  - get_device_state(device_id, area=bgp)
  - get_rca_verdict(correlation_id)
  - run_protocol_diagnostic(device_id, protocol=bgp, issue_id=bgp-session-down)
  - get_topology_context(device_id)
  - search_logs(device, query=BGP, window=6h)
  - recall_investigations(device, peer)
look_for:
  - The neighbour summary read LIVE off the device. The FSM state and the accepted-prefix count come from the device itself, never from an assumption.
  - The peer's FSM state. Idle means the session is not even being attempted or was damped; Active means we are trying and the TCP connection is not completing; Connect means TCP is mid-handshake.
  - Whether the peer address is reachable at all, and by which route. An eBGP peer that is not directly connected needs multihop, and an unreachable next hop keeps the session in Active forever.
  - The last notification or reset reason, which usually names the cause outright (hold timer expired, administrative reset, bad AS number).
  - Whether the underlying interface or the path to the peer changed at the same time as the session.
  - Whether this peer has been investigated before. A repeat of the same cause is worth saying out loud — but only after the live state confirms it, and only with the operator's earlier judgement stated.
decisions:
  - next=interface-down when state:bgp_peer=idle the device itself reports the peer Idle, so reachability to the peer — and the link carrying it — is the next check
  - next=log-confirmation when state:collect=not_wired the neighbour table could not be read live, so the reset reason must come from the device's own words
  - next=interface-down when verdict:phrase=link the RCA verdict names the link beneath the session
  - next=interface-down when signature=bgp-idle-unreachable the peering address is unreachable from this device, so the interface carrying the session is the next check
  - next=path-seam-handoff when the peer sits across a provider or partner handoff
  - next=bgp-prefix-missing when signature=bgp-nothing-advertised the session is Established but nothing is being advertised to the peer
  - next=log-confirmation when signature=uncollected the device rejected every read-only command, so NOTHING was captured and the device's own words are the only evidence left
  - next=log-confirmation when signature=none the session diagnostic ran and no known signature matched, so the reset reason must be read from the device's own words
  - verdict=name the peer, the FSM state, the reset reason if captured, and whether reachability to the peer is intact
  - escalate=the peer's owner, named from the seam, with the state and last reason quoted
---

# BGP session down

BGP tells you why it is unhappy more clearly than any other protocol. Read the
state and the last reason before hypothesising.

**The state narrows it to one of three questions.**

- Idle — the session is not being attempted. Either it is administratively shut,
  the peer is not configured, or damping has suppressed it. Nothing below BGP is
  implicated yet.
- Active — we are attempting TCP and not completing. This is a reachability or
  filtering question: can we reach the peer address, on port 179, from the right
  source address?
- Established but useless — a different fault; go to prefix analysis.

**Reachability to the PEER ADDRESS, not to the device.** eBGP peers are usually
one hop away and the session sources from the interface address; iBGP peers are
usually loopback-to-loopback and depend on the IGP. A working ping to the device
by another address proves nothing about the session.

**Read the last reason.** "Hold timer expired" says packets stopped arriving —
look below at the link. "Administrative reset" says a human or a script did it —
look at the change timeline. "Bad AS" or an OPEN-message error says
configuration, on one side or the other.

**Never propose clearing a session.** Clearing hides the evidence and is a
change. Diagnose and hand the operator a named next check.
