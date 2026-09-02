---
name: mac-flap
layer: l2
version: 1
when_to_use: mac flap, mac move, host moving between ports, duplicate mac, mac address flapping, station move, arp instability
symptom_kinds: l2, instability, duplicate
tools: get_device_health, get_topology_context, search_logs, get_metric_anomalies
gather:
  - get_topology_context(device_id)
  - get_device_health(device)
  - search_logs(device, query=MACFLAP, window=6h)
  - get_metric_anomalies()
look_for:
  - The pair of ports a single MAC address is moving between. That pair, not the MAC, is the finding.
  - Whether one of the two ports leads back into the same L2 domain by another route, which is a loop rather than a mobile host.
  - Whether the address belongs to a virtual or clustered service, where a legitimate failover looks identical to a flap but happens once, not continuously.
  - The move rate. A handful of moves is mobility; continuous moves are a topology defect.
decisions:
  - next=stp-topology when the moves coincide with topology-change notifications
  - next=interface-down when one of the two ports is also flapping
  - next=log-confirmation when the exact port pair must be read from the device's own words
  - verdict=name the address, the two ports, the move rate and whether it is mobility, failover or a loop
  - escalate=the LAN owner with both ports named when the pattern is a loop
---

# MAC flapping

A MAC address learned on two ports in quick succession means the same frames are
arriving by two paths. Either the host really moved, or the topology has a second
way back to itself.

**Report the port PAIR.** "MAC aa:bb:cc is flapping" is not actionable. "MAC
aa:bb:cc moving between Gi1/0/12 and Po1 roughly every two seconds" names the
loop.

**Three benign explanations, and how to rule them out.** A wireless client
roaming moves once per roam. A clustered or virtual-IP service moves on failover
and then stops. A misconfigured NIC team moves continuously — which is
indistinguishable from a loop at the switch, so say that the evidence cannot
separate them if it cannot.

**A loop is an outage in waiting.** Continuous moves plus rising broadcast rates
means the segment is already saturating. Escalate with both ports named rather
than continuing to characterise it.
