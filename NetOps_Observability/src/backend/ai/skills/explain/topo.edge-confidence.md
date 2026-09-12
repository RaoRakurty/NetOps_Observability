---
topic: topo.edge-confidence
question: What is the difference between a confirmed and an inferred link?
keywords: confirmed link, inferred edge, flow observed edge, observed vs inferred, dashed edge
---
A confirmed link was observed by both ends: a neighbour protocol or an IGP
adjacency names the same pair of ports. It is drawn solid. An inferred link was
never observed as a link — it is deduced from traffic that was attributed to
both nodes, so the two talk but the path between them is unknown. It is drawn
dashed and carries lower confidence. Treat a dashed edge as a dependency, not
as a cable: acting on it as if it were a physical link is the mistake the
distinction exists to prevent.
