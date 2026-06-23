"""Routing (BGP-LS / IGP SPF) direction source (C7.5) — the precedence-3 source of
the directed-topology oracle (directed-topology-rca.md).

The routers' COMPUTED forwarding path: SPF over the IGP/BGP-LS link-state DB yields,
for each device, its next hop toward every destination — a directed forwarding DAG.
This covers backbone paths that have neither an active probe nor observed flows. It
is the lowest-precedence source (computed < observed < measured): a probe or flow
that actually traversed the path beats the routers' computed intent on conflict.

Contract (`routing_direction.json`, a list of `{from, to}`): `from` forwards toward
`to` (from is upstream of to). The Go producer (an SPF/nexthop export over the
BGP-LS LSDB) is DEFERRED until the LSDB yields data — currently empty — so this
source abstains by design until fed, exactly the oracle's safe no-op (the engine
already directs via NetFlow C7.3 + traceroute C7.4 today).

Pure + deterministic. A pair not in the forwarding set abstains (None → UNKNOWN); a
pair seen in BOTH directions (a transit link carrying both ways) → AMBIGUOUS — never
an assumed direction. The orientation is embedded per snapshot, so a routing-directed
edge replays deterministically.
"""
from __future__ import annotations

from typing import Iterable, Optional

from directed_topology import Orientation, Source, Verdict

# Computed direction is the lowest-confidence tier (it is intent, not observation).
ROUTING_CONFIDENCE = 0.7


def forwarding_pairs(rows: Iterable[dict]) -> set:
    """Build the directed forwarding set `{(upstream, downstream)}` from the routing
    export: each row `{from, to}` means `from` forwards toward `to`. Self-pairs and
    incomplete rows are dropped."""
    out: set = set()
    for r in rows:
        a, b = str(r.get("from") or ""), str(r.get("to") or "")
        if a and b and a != b:
            out.add((a, b))
    return out


def routing_direction_source(forward: set) -> Source:
    """A DirectedTopology Source over the computed forwarding set. orient(a,b):
    a→b only → A_UPSTREAM; b→a only → B_UPSTREAM; BOTH (transit both ways) →
    AMBIGUOUS; neither → None (UNKNOWN, abstain)."""
    def _src(a: str, b: str) -> Optional[Orientation]:
        ab = (a, b) in forward
        ba = (b, a) in forward
        if ab and ba:
            return Orientation(Verdict.AMBIGUOUS, source="routing")
        if ab:
            return Orientation(Verdict.A_UPSTREAM, confidence=ROUTING_CONFIDENCE, source="routing")
        if ba:
            return Orientation(Verdict.B_UPSTREAM, confidence=ROUTING_CONFIDENCE, source="routing")
        return None

    return _src
