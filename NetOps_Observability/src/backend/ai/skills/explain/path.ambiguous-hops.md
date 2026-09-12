---
topic: path.ambiguous-hops
question: What do ambiguous hops on this path mean?
keywords: ambiguous hops, ecmp, failover, segment sequence, exact hops vary
---
Traffic between this source and destination does not always take the same
device-by-device route. Equal-cost paths (ECMP) or a failover event mean the
individual hops vary per flow, so naming one exact device chain would be a
guess. What does not vary is the sequence of segments — client, site, provider,
destination — and that sequence is the stable essence of the path, which is why
the RCA workspace draws it and marks the break on a segment rather than
pretending to a hop list. A hop shown inside an ambiguous segment is one
observed example, not the only route.
