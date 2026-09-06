---
topic: path.computed
question: What does a computed path mean?
keywords: computed path, inferred shortest path, not a live trace, igp shortest path
---
A computed path is an inference, not a measurement. The platform walked the
IGP-weighted topology and returned the shortest route between the two
endpoints. Traffic usually follows it, and sometimes does not: policy routing,
equal-cost hashing, tunnels and a stale adjacency can all send packets
somewhere else. Nothing on a computed path was observed forwarding a packet,
which is why the word "traced" is never used for one. Run a traceroute between
the same endpoints to confirm it.
