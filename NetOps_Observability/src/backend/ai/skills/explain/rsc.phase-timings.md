---
topic: rsc.phase-timings
question: Why are no phase timings recorded yet?
keywords: phase timings, recorded snapshots, detection and repair trend, nothing recorded
---
The detection-and-repair trend is drawn from phase-metric snapshots the engine
persists once an incident has been analysed — one snapshot per incident, the
freshest calculation kept. An empty window means no analysed incident fell in
it, not that detection and repair were instant. Timings appear on their own as
incidents are analysed. A bucket with nothing complete to measure is left as a
gap in the line rather than plotted as zero, because a measurement nobody took
is not a measurement of zero.
