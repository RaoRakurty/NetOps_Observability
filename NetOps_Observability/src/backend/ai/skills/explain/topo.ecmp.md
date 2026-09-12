---
topic: topo.ecmp
question: What does ECMP balance tell me?
keywords: ecmp, equal cost paths, ecmp sibling set, no ecmp backup, drain
---
Equal-cost paths are links that carry the same destination and should carry
roughly the same load. A sibling set that is balanced is behaving as designed.
A link with no equal-cost sibling has no backup: if it drains, its traffic has
nowhere to move, and the drain estimate shows where that traffic would land.
Imbalance across a sibling set is usually a hashing or an interface-state
problem, not a capacity one.
