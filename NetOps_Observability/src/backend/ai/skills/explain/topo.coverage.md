---
topic: topo.coverage
question: What does the coverage count mean?
keywords: topology coverage, stale nodes, stale edges, graph coverage
---
Coverage is how much of the persisted graph this view is drawing: the number of
nodes and edges it holds, and how many of those have not been re-observed
inside their freshness window. A stale object is history, not a live claim —
it was seen once and has not been confirmed since. A rising stale count usually
means a collector stopped, not that the network shrank, so check the source
before treating the objects as gone.
