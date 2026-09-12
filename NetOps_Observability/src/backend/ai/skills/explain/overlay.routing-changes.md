---
topic: overlay.routing-changes
question: What does the routing-changes overlay show?
keywords: routing changes overlay, adjacency change, best path change, bgp ospf isis change
---
Highlighted edges are the ones where routing moved inside the selected window:
a BGP, OSPF or IS-IS adjacency came up or went down, or a best path changed.
It is a change view, not a health view — a highlighted link can be perfectly
healthy now and still be the reason traffic went somewhere else. Widen the
window to see the change that started an incident rather than only its
aftermath.
