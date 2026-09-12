---
topic: path.trace
question: How is a path between two devices resolved?
keywords: path trace, hop by hop, ingress egress interface, discovered topology
---
Pick a source and a destination and the platform resolves the route between
them hop by hop over the topology it has discovered, naming the interface
traffic enters and leaves on at each hop. Where an active probe has measured
those hops the result is a measurement; where it has not, the route is the
shortest path through the discovered adjacencies and is labelled as computed.
Either way the header says which, because a computed path is an inference and a
measured one is not.
