---
topic: bgp.transit-observed
question: How is "Who carries your traffic" worked out?
keywords: who carries your traffic, direct upstream, transit, as path derived, unexpected transit
---
It is derived from the AS paths the watchlist evaluator actually measured, so it
is an observation and never an assumption about your contracts. The highlighted
AS on each row is your direct upstream — the hop next to the origin; the rest
are networks seen further up the path. A carrier that appears without a
maintenance window, and that is not in the upstream list on your alert rules, is
what the watchlist flags as unexpected transit.
