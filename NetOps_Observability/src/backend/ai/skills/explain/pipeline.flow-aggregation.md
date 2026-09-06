---
topic: pipeline.flow-aggregation
question: Why do exported and indexed flow counts differ?
keywords: flow records, exported versus indexed, exporter-side aggregation, netflow ipfix sflow counts
---
Flow records are aggregated exporter-side before they ever reach Correlix, so a
difference between what a device says it exported and what is indexed here is
expected, not a loss. Sampling rates, active and inactive flow timeouts and the
exporter's own cache all collapse many packets into one record, and each vendor
does it slightly differently. Treat the counts on this board as a presence
check — records are arriving from these exporters — rather than an audit. Full
per-dimension analysis lives in the Flows dashboard.
