---
topic: wan.nothing-derived
question: Why has no WAN path been derived?
keywords: no measured path, nothing derived, wan path empty, path appears when
---
A path appears once an interface has an IP address and something to measure to.
Both halves are required: an interface with no address cannot be a path
endpoint, and an interface with no neighbour, no declared next-hop and no
anchor has no far end. An empty list therefore means the inputs are missing,
not that the WAN is idle. The endpoint registry below shows which half is
missing per interface.
