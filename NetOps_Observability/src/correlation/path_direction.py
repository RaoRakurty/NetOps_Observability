"""Active-path-trace direction source (C7.4) — the precedence-1 (highest) source of
the directed-topology oracle (directed-topology-rca.md).

A traceroute / probe path is the MEASURED forwarding path: hop order IS direction —
an earlier hop is upstream of a later one. This is the strongest direction signal
(measured beats observed beats computed), so it is consulted FIRST. The Go API
exports probe_paths.json (ordered hop IPs per path); this module resolves the hop
IPs → devices via the EntityResolver (C7.1) and exposes the ordering as a Source.

Pure + deterministic. An endpoint that doesn't resolve, or a pair on no common path,
abstains (None → UNKNOWN). A pair seen in BOTH orders across paths (ECMP asymmetry /
a routing loop) → AMBIGUOUS — never an assumed direction. The orientation is embedded
per snapshot by run_window, so a path-directed edge replays deterministically.
"""
from __future__ import annotations

from typing import Iterable, Optional

from directed_topology import Orientation, Source, Verdict
from entity_resolver import EntityResolver

# Measured direction is high-confidence by construction (it is the observed path).
PATH_CONFIDENCE = 0.9


def resolve_path_order(paths: Iterable[dict], resolver: EntityResolver) -> set:
    """Build the ordered-pair set `{(upstream, downstream)}` from measured hop paths,
    resolving each hop IP → device via the (tenant-scoped) resolver. (a,b) ∈ result ⇒
    a appeared before b on some path. Unresolved hops are dropped (relative order of
    the rest is preserved); consecutive duplicates are collapsed."""
    before: set = set()
    for p in paths:
        devs: list[str] = []
        last: Optional[str] = None
        for ip in p.get("hops", ()):
            d = resolver.device_for_ip(ip)
            if d and d != last:
                devs.append(d)
                last = d
        for i in range(len(devs)):
            for j in range(i + 1, len(devs)):
                if devs[i] != devs[j]:
                    before.add((devs[i], devs[j]))
    return before


def traceroute_direction_source(before: set) -> Source:
    """A DirectedTopology Source over a measured ordered-pair set. orient(a,b):
    a-before-b only → A_UPSTREAM; b-before-a only → B_UPSTREAM; BOTH orders seen
    (ECMP/loop) → AMBIGUOUS; neither → None (UNKNOWN, abstain)."""
    def _src(a: str, b: str) -> Optional[Orientation]:
        ab = (a, b) in before
        ba = (b, a) in before
        if ab and ba:
            return Orientation(Verdict.AMBIGUOUS, source="traceroute")
        if ab:
            return Orientation(Verdict.A_UPSTREAM, confidence=PATH_CONFIDENCE, source="traceroute")
        if ba:
            return Orientation(Verdict.B_UPSTREAM, confidence=PATH_CONFIDENCE, source="traceroute")
        return None

    return _src
