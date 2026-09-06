---
topic: monitoring.probe-sources
question: Where do the synthetic and path numbers come from?
keywords: synthetics runner, service checks, stamp, rfc 8762, path sla, probe source, http icmp tcp check
---
Service checks — HTTP, ICMP and TCP — are run by the synthetics runner against
the targets you configured, so "up" means that runner got an answer. Path SLA
(round-trip and loss per target) comes from the STAMP sender, the two-way
active measurement protocol defined in RFC 8762; the far end reflects timestamped
packets so delay and loss are measured, not inferred. Neither number is a
hop-by-hop trace: for that, open Flow Trace.
