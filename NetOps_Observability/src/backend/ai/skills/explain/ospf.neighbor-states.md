---
topic: ospf.neighbor-states
question: What do the OSPF neighbour state numbers mean?
keywords: ospf neighbor state, down attempt init twoway exstart exchange loading full, ospf adjacency
---
An OSPF adjacency forms through a fixed sequence: down, attempt, init, two-way,
exchange start, exchange, loading, full. Full is the only state in which the
two routers have exchanged a complete database and will use each other. Stuck
at two-way is normal on a broadcast segment between two routers that are
neither the designated router nor its backup. Stuck at exchange start is
usually an MTU mismatch.
