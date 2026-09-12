---
topic: bgp.path-map
question: How do I read the AS path map?
keywords: path map, as path graph, origin, line thickness, observed paths
---
Left to right: the network sitting next to a route collector, then the carriers
in between, then the origin that announces this prefix. Line thickness is how
many observed paths cross that link — an observation count, not capacity or
bandwidth. Your own watched networks are outlined in green and each carries its
registry holder. The graph is capped: the strongest adjacencies are kept, so the
trunk of the path is complete but the long tail of single-peer edges is not
drawn.
