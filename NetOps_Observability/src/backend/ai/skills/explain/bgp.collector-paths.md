---
topic: bgp.collector-paths
question: How do I read the "Path to you" column?
keywords: path to you, as path, last hop origin, collector peers, paths in use
---
Each row is one distinct AS path, read left to right from the network next to a
public route collector towards you. The LAST hop is the origin — the AS actually
announcing this prefix — and it is the one to check first when a verdict says
the origin changed. The Collectors number is how many collector peers currently
see that exact path, so a path seen by one peer is far weaker evidence than one
seen by fifty. Repeated AS numbers (prepending) are collapsed.
