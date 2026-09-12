---
topic: topo.data-source
question: What is the difference between Live and Persisted?
keywords: live projection, persisted graph, reconciled graph, topology data source
---
Live recomputes the graph for this workflow on every load, so it shows what the
collectors resolved just now. Persisted reads the reconciled graph the platform
keeps: stable node and edge identifiers that survive a restart, with freshness
and coverage recorded per object. Live is the better answer to "what is
happening"; Persisted is the better answer to "what changed", because an object
that vanished from Live is still there, marked stale. Both can fail, and a
failed read is reported as a failure — never as an empty network.
