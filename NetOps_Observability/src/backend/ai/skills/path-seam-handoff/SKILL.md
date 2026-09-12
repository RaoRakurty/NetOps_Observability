---
name: path-seam-handoff
layer: path_seam
version: 1
when_to_use: packet loss, latency, jitter, slow path, isp, provider, seam, handoff, wan, dia, mpls, is it the network, hop loss, traceroute, brownout
symptom_kinds: path, loss, latency, ownership
tools: get_topology_context, get_rca_verdict, get_case_timeline, get_metric_anomalies
gather:
  - get_rca_verdict(correlation_id)
  - get_topology_context(device_id)
  - get_case_timeline(correlation_id)
  - get_metric_anomalies()
look_for:
  - The first hop at which loss or latency appears, and whether it PERSISTS to the destination. Loss that appears at one hop and does not continue is that hop's control plane rate-limiting ICMP, not a fault.
  - Which side of the seam the degraded hop sits on. That single fact decides whether this is ours to fix or to escalate.
  - Whether the path CHANGED. A new hop sequence with new latency is a re-route, and the re-route is the event, not the latency.
  - Comparison against the path's own baseline rather than an absolute threshold. Forty milliseconds is fine on one path and an outage on another.
decisions:
  - next=optics-degraded when the degraded hop is a link we own and shows errors
  - next=interface-down when the path changed because a link we own went down
  - next=app-edge-5xx when every hop is within baseline and only the application is failing
  - next=bgp-prefix-missing when the path changed because the preferred route disappeared
  - verdict=name the hop, its seam and its owner, the metric versus baseline, and whether the path changed
  - escalate=the seam owner by name — the ISP, the partner or the site operator — with hop, timestamps and measured deltas attached
---

# Path and seam handoff

This is the layer that answers "is it us?" — and it is the only layer that can
honestly exonerate the network.

**Ownership before mechanism.** Every hop belongs to somebody. Find the first hop
where the measurement degrades, decide which seam it sits on, and name the owner.
An escalation to the right party with a hop and a timestamp is worth more than a
perfect theory sent to the wrong team.

**Distinguish real loss from ICMP de-prioritisation.** Routers rate-limit
responses to their own control plane. Loss that appears at hop four and vanishes
at hop five is an artefact. Loss that appears at hop four and continues to the
destination is real. Say which one you are looking at — this single distinction
is the most common false positive in path analysis.

**Compare to the path's baseline.** Absolute numbers mislead. Report the current
value, the baseline, and the delta.

**A path change is its own finding.** If the hop sequence differs from the
baseline path, lead with that. The latency did not increase; the traffic went a
different way, and something upstream decided it should.

**Exonerating is a legitimate conclusion.** When every hop is within baseline and
the transport is clean, say that clearly, attach the evidence, and hand it back.
That is the deliverable, not a failure to find a fault.
