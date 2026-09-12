---
title: View AS paths for a prefix
sidebar_label: View AS paths
sidebar_position: 5
description: Read the collector-to-origin AS-path graph for a prefix, deduplicated and capped, with unreadable paths dropped and counted rather than spliced.
page_type: task
---

# View AS paths for a prefix

The AS-path graph shows how route collectors reach a prefix: vantage points on
the left, converging AS hops in the middle, the origin on the right. It replaces
a wall of path strings with one picture of who is carrying the prefix today.

## Before you begin

- **`infrastructure:read`.**
- **A prefix.** Paths are per prefix. Looking up an ASN shows the message
  "Route-collector paths are per PREFIX. Look up one of this AS's prefixes to
  see them."
- **Outbound HTTPS to `stat.ripe.net`.**

## Steps

1. Go to **Analytics → Metric Dashboards → BGP Operations**.
2. Investigate a prefix.
3. Read **Current paths from route collectors** in the left column. The graph is
   at the top, the per-path table beneath it.
4. Check the chips above the graph: the number of observed paths, the origin AS,
   the observed path-length range, and which RIPE data call the graph was built
   from.
5. Use the path table when you need the exact AS sequence a set of collector
   peers reported.

From the API:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/bgp/aspath-graph?prefix=8.8.8.0/24"
```

```json
{
  "prefix": "8.8.8.0/24",
  "nodes": [
    {"asn": 24482, "name": "SGGS-AS-AP", "depth": 0, "vantage": true, "paths": 11},
    {"asn": 15169, "name": "GOOGLE", "depth": 1, "origin": true, "paths": 374}
  ],
  "edges": [{"from": 24482, "to": 15169, "peers": 11}],
  "origins": [15169],
  "paths": 374,
  "paths_seen": 374,
  "max_edges": 500,
  "edges_capped": false,
  "nodes_capped": false,
  "source": "bgp-state",
  "fetched_at": "2026-09-03T04:10:35.3515537Z"
}
```

## Result

| Field | What it tells you |
|---|---|
| `nodes` | One entry per AS, deduplicated. `depth` is the shortest distance from a collector peer. `origin`, `vantage` and `tenant` mark the origin AS, the collector-adjacent ASes, and any AS on this tenant's own watchlist. `paths` is the observation count for that AS. |
| `edges` | One entry per observed adjacency, deduplicated. `peers` is how many collector paths traverse it. It is an observation count, not a capacity. |
| `paths` and `paths_seen` | Paths folded into the graph, and paths the upstream offered. |
| `paths_dropped` | Paths that carried a hop Correlix could not read. |
| `edges_capped`, `nodes_capped` | Whether a cap changed the answer. |
| `source` | `bgp-state`, or `looking-glass` when the richer call was unavailable. |

Four rules govern what you see:

- **The edge cap is 500** and is applied deterministically. When it bites,
  `edges_capped` is `true`. A truncated graph always says it is truncated.
- **An unreadable path token drops the whole path.** The parser marks the gap
  in band, and the graph builder refuses to splice across it, because splicing
  would draw an adjacency between two ASes that are not neighbours. Those paths
  are counted in `paths_dropped` and shown as a coverage gap.
- **AS names are never invented.** Correlix resolves holder names over RDAP for
  at most 12 of the most important nodes, origins first. Every other node keeps
  an empty name and renders as the bare ASN.
- **A path is one collector's view.** Two collector peers disagreeing is normal.
  That is why alerting requires corroboration before it calls an origin change.

## Related

- [Investigate a BGP prefix](/bgp/investigate-a-prefix)
- [Configure BGP alerting](/bgp/alerting)
- [Check RPKI origin validation](/bgp/rpki)
