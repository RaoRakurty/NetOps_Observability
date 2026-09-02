---
name: app-edge-5xx
layer: application
version: 1
when_to_use: 5xx, 502, 503, 504, application errors, app slow, load balancer, tls handshake, timeouts, service degraded, app team says network, users cannot log in
symptom_kinds: application, errors, latency
tools: get_rca_verdict, get_topology_context, get_metric_anomalies, search_logs, get_case_timeline
gather:
  - get_rca_verdict(correlation_id)
  - get_topology_context(device_id)
  - get_metric_anomalies()
  - get_case_timeline(correlation_id)
look_for:
  - Whether transport to the service is clean. Prove that first, because it is the only claim the network team owns.
  - Which error the service is returning. A 502 or 504 is an upstream or timeout problem behind the balancer; a 503 is capacity or a drained pool; a TLS handshake failure is certificate or cipher, not reachability.
  - Whether the failure is proportional. Every request failing is a hard fault; a fraction failing points at one pool member or one path.
  - The change timeline on both the network and the service side in the window before onset.
decisions:
  - next=path-seam-handoff when transport measurements are outside baseline
  - next=optics-degraded when retransmissions are elevated without visible loss
  - next=log-confirmation when the onset time must be pinned before comparing to changes
  - verdict=state whether the network path is within baseline, and name the service-side signal that best explains the errors
  - escalate=the application or platform owner with the transport evidence attached as an exoneration
---

# Application edge errors

This skill exists to end the "it's the network" argument with evidence rather
than opinion, in either direction.

**Prove transport first, in one paragraph.** Path within baseline, no loss, no
error growth on the links in the path, no recent re-route. That is the network's
statement, and it should be short, cited, and shareable.

**Then read the error class.** A 502 or a 504 means the front door reached a
back end that failed or did not answer in time — the failure is behind the
balancer. A 503 means no healthy back end was available, which is capacity or a
drained pool. A TLS handshake failure is a certificate, cipher or SNI problem
and has nothing to do with reachability, which is why it so often gets
misattributed to the network.

**Partial failure points at one member.** If a fraction of requests fail, find
what that fraction has in common — one pool member, one availability zone, one
path. A uniform failure rate points at something in front of all of them.

**Exonerate honestly, and only that far.** "The network path is within baseline
for this window" is a defensible statement. "The network is fine" is not — say
what was measured, over what window, and what was not measured at all.
