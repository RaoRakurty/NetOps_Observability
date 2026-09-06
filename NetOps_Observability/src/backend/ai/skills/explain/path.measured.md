---
topic: path.measured
question: What does a measured path mean?
keywords: measured path, live traceroute, observed hops, ground truth path
---
Every hop on a measured path was observed by an active probe — a traceroute or
a per-hop measurement that got a reply from that router. It is ground truth for
the moment it ran, not a standing claim: paths move, and a measurement is only
as current as its timestamp. Hops that never replied appear as gaps rather than
being filled in from the topology, because a router that declines to answer is
not the same as a router that is not there.
