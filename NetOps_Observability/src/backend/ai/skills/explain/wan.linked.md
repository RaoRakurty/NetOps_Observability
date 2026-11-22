---
topic: wan.linked
question: What does a linked interface mean?
keywords: linked interface, connected to wan device, wan adjacency, possible wan
---
The interface is not on a WAN router itself; it is directly connected to one.
That is usually the router's LAN side, so it is listed as possible rather than
measured. If that link really is part of the WAN path, mark it as WAN and it is
measured like any other. Turning linked interfaces off in the measurement
policy removes these rows instead of hiding them.
