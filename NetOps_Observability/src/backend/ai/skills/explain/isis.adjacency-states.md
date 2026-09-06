---
topic: isis.adjacency-states
question: What do the IS-IS adjacency states mean?
keywords: isis adjacency state, down init up failed, isis system id, fabric igp
---
An IS-IS adjacency reports down, init, up or failed. Up is the working state.
Init means hellos are being received but the adjacency has not completed, which
usually points at a level or area mismatch. Failed is an adjacency that formed
and broke. The neighbour is identified by its IS-IS system identifier rather
than an IP address, so it will not match the names used elsewhere on this page.
