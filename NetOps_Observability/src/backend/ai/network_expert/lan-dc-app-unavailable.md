---
id: lan-dc-app-unavailable
title: LAN / DC Application Unavailable
fault_domains: lan, dc, switching, application, service
signals: device_if_oper_status, stp_topology_change, fhrp_state, mac_flap, service_health
keywords: application down, unavailable, lan, datacenter, dc, switch, vlan, stp, hsrp, vrrp, gateway, mac flap, outage
owner: Network / LAN-DC
---

# LAN / DC Application Unavailable

## Symptoms
- An application or service is unreachable for users on a LAN/DC segment.
- Coincident L2/L3 event: link down, STP topology change, FHRP failover, or MAC flap.

## Common fault domains
- Access/distribution link or device down.
- Spanning-tree topology change / loop.
- First-hop redundancy (HSRP/VRRP) failover or split.
- MAC flap from a loop or dual-homing issue.

## Correlix evidence to check
- device_if_oper_status on the access/uplink interfaces.
- STP topology-change and MAC-flap syslog on the segment.
- FHRP (HSRP/VRRP) state changes for the gateway.
- Service View health for the affected app and its segment.

## Supporting evidence
- Link-down or STP change coincides with the app outage window.
- Gateway FHRP failover at the outage start.

## Contradicting evidence
- L2/L3 segment clean but app down → app/host or upstream dependency.
- Whole site down, not just the segment → broader power/uplink event.

## Missing evidence
- Host/app-level health may be outside Correlix — correlate infra + escalate.
- Per-VLAN reachability not always directly observable.

## Recommended owner
Network / LAN-DC (escalate to app owner if the segment is clean).

## Next actions
1. Check access/uplink interface oper-status for the segment.
2. Look for STP topology changes / MAC flaps in the window.
3. Check FHRP gateway state for a failover/split.
4. If L2/L3 is clean, escalate to the app/host owner.
5. Confirm reachability restores after the fix.

## Escalation note
App <name> unavailable on <segment> since <start UTC>. L2/L3: <link-down | STP-change | FHRP-failover | MAC-flap | clean>. Gateway <state>.

## ITSM note template
LAN/DC app <name> unavailable since <start UTC>. Segment event: <type>. Gateway <state>. Owner: <network segment | app/host>.
