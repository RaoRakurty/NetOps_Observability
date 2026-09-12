---
topic: topo.at-scale
question: Why can the canvas not draw every node?
keywords: too many nodes, over ceiling, aggregated at scale, canvas scale limit
---
The interactive canvas has a node budget; past it, drawing every device makes
the map unreadable and the browser slow. Two ways out. Group the fabric by a
dimension, and the canvas draws site or region cards you can expand. Or search
for the part you care about and focus on the matches and their neighbours.
The enterprise overview renders the whole fabric with a different engine when
you need all of it at once. Nothing is hidden by either route — only undrawn.
