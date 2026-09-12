---
topic: path.traceroute
question: How is a traceroute measured here?
keywords: traceroute, paris consistent, ecmp traceroute, per hop probe, icmp deprioritized
---
Probes are Paris-consistent: every packet in a run carries the same flow
identity, so equal-cost hashing sends them all down one path. A classic
traceroute varies that identity and stitches several different paths into one
false list of hops. Per-hop round-trip and loss come from the routers' own
replies, and routers commonly deprioritise those replies — a slow hop with a
fast hop after it is a busy control plane, not a slow path.
