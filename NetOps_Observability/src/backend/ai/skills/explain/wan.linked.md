---
topic: wan.linked
question: What does a linked interface mean?
keywords: linked interface, connected to wan device, measured too, wan adjacency
---
The interface is not on a WAN device itself; it is directly connected to one.
It is measured anyway, because the link between a WAN router and the switch
behind it is part of the WAN path and fails like one. Switching that behaviour
off is a single option in the measurement policy, and turning it off removes
these rows rather than hiding them.
