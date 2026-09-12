---
topic: seam.group
question: What is a seam group?
keywords: seam group, redundant seams, active standby pair, group state
---
A seam group is the set of seams that carry the same traffic redundantly — two
ISP circuits, an active/standby pair. It is the unit an operator reasons about
during an outage: a fault on one member is not the same event as a fault on the
group. The engine proposes groups from evidence and a person confirms or
rejects them; confirming one is what lets the engine say "the pair is degraded"
instead of reporting two unrelated seam faults.
