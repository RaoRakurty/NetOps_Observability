---
topic: topo.shape
question: What does Shape do to the layout?
keywords: topology shape, archetype, leaf-spine layout, ring layout, arrange canvas
---
Shape arranges the canvas as the kind of topology it is: leaf-spine, ring,
star, bus or mesh. Auto detects the shape from the graph and names what it
found and why. Forcing a shape redraws deterministically — the same graph
always lands in the same place — which makes two loads comparable. It changes
geometry only: no node, link or health state is altered by the arrangement you
pick.
