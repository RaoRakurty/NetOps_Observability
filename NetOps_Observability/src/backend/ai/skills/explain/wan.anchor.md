---
topic: wan.anchor
question: What is a reachability anchor?
keywords: reachability anchor, public anchor, fallback target, anchor measurement
---
An anchor is a well-known public address used as the target of last resort,
when an interface has neither a neighbour on the wire nor a declared ISP
next-hop. It proves the interface can reach the internet and gives a rough
latency, and that is all: the path to it crosses networks nobody here operates,
so a change in the number is not attributable. Prefer a neighbour or a
next-hop wherever one exists.
