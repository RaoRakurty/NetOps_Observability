---
topic: overlay.flow
question: What does the flow overlay show?
keywords: flow overlay, flow dependency, dashed dependency edge, observed traffic
---
Dashed edges are dependencies observed in traffic, not links observed on the
wire. Two nodes exchanged flows, so one depends on the other; the path between
them is unknown. They carry lower confidence than a confirmed link on purpose,
and they are the only edges on this canvas that describe a conversation rather
than a cable.
