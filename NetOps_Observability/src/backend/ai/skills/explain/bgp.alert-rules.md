---
topic: bgp.alert-rules
question: What do the BGP alert rule fields mean?
keywords: expected origin, upstreams, minimum visibility, minimum vantages, bgp alert policy
---
Four settings decide every verdict above. The expected origin is which AS is
allowed to announce the prefix; leave it empty and the baseline is learned from
the first observation and marked as guessed. The allowed carriers are your
upstreams; leave it empty and the unexpected-transit check does not run at all,
so its silence is unmeasured rather than clean. Least acceptable reach is the
share of collectors below which visibility counts as lost, and collectors that
must agree is how many vantage points must corroborate before a verdict is
asserted.
