---
topic: path.no-path
question: Why was no path found between two devices?
keywords: no path found, no route between devices, separate fabrics, incomplete adjacency
---
The trace ran and found no route between the two endpoints over the topology
that has been discovered. Either the adjacency between them was never learned,
or they genuinely sit in separate fabrics with no path in the graph. This is
not a claim that traffic cannot flow: a path the platform has not discovered is
still a path. Widen discovery so the hops in between are learned, or re-aim the
trace at endpoints on the same fabric.
