---
topic: wan.registry
question: What is the endpoint registry?
keywords: endpoint registry, wan endpoints, derived endpoints, interfaces measured
---
The registry is every interface the platform has evidence is a WAN link, with
the address it carries, the address the far end targets, and what it was
derived to measure to. The evidence is per interface: the SD-WAN controller
calling it a transport port, a tunnel running over it, an ISP next-hop declared
for it, or an operator marking it. A device's name never makes all of its ports
WAN. Interfaces that only might be WAN are listed apart as possible, and are not
measured until someone marks them.
