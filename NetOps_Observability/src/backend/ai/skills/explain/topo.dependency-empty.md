---
topic: topo.dependency-empty
question: Why are there no service dependencies?
keywords: dependency map empty, flow attribution, service dependencies, no dependency edges
---
Dependency edges are drawn from flows that were attributed to a service, so
they appear only where flow collection is running and attribution succeeded.
An empty dependency view means no attributed flow fell inside this time window
— not that your services talk to nothing. Widen the range first; if it stays
empty, confirm flow collection is active and that the exporters are reaching
the collector.
