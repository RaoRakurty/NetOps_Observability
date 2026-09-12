# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""NetFlow direction source (C7.3) — the precedence-2 source of the directed-
topology oracle (directed-topology-rca.md).

Observed traffic direction is *measured* direction: when traffic flows dominantly
from device A to device B, A is upstream of B on that path. This module turns the
C6 passive-flow lane into a directed per-device-pair volume and exposes it as a
DirectedTopology `Source`. Bidirectional honesty (the owner's key point): traffic
flows both ways — a BALANCED pair is AMBIGUOUS, never an assumed direction.

v1 coverage: a flow contributes direction only when BOTH its endpoints resolve to
known devices via the EntityResolver (C7.1) — loopbacks, interface IPs, mgmt. A
transit flow whose src/dst are customer endpoints does not resolve → it is ignored
(honest: direction is claimed only between devices we see both ends of). The
in_if/out_if→neighbour (fabric-transit) refinement is a documented follow-on; C7.4
(traceroute) and C7.5 (routing) cover paths NetFlow src/dst cannot.

Pure: the source closes over a volume snapshot; given the same volume it answers
identically. The orientation it returns is EMBEDDED in the snapshot by run_window,
so a directed edge replays deterministically (never recomputed from live volume).
"""
from __future__ import annotations

from collections.abc import Mapping

from directed_topology import Orientation, Source, Verdict
from entity_resolver import EntityResolver
from producers import _flow_field

# A flow contributes direction only above this share of the pair's bidirectional
# volume; below it the pair is balanced → AMBIGUOUS (abstain, never assume).
DEFAULT_DOMINANCE = 0.6


def flow_direction_sample(ev: dict, resolver: EntityResolver) -> tuple[str, str, float] | None:
    """One raw flow → (src_device, dst_device, bytes_scaled) when BOTH endpoints
    resolve to KNOWN, DISTINCT devices; else None (abstain). Bytes are scaled by the
    sampling rate (a 1-in-N sampler under-reports N×), matching the C6 lane."""
    src_ip = _flow_field(ev, "src_addr", "SrcAddr", "src_ip")
    dst_ip = _flow_field(ev, "dst_addr", "DstAddr", "dst_ip")
    if not src_ip or not dst_ip:
        return None
    sd = resolver.device_for_ip(src_ip)
    dd = resolver.device_for_ip(dst_ip)
    if not sd or not dd or sd == dd:
        return None
    try:
        nbytes = float(_flow_field(ev, "bytes", "Bytes") or 0)
    except ValueError:
        return None
    if nbytes <= 0:
        return None
    try:
        rate = int(_flow_field(ev, "sampling_rate", "SamplingRate") or 0)
    except ValueError:
        rate = 0
    return sd, dd, nbytes * (rate if rate > 0 else 1)


def netflow_direction_source(volume: Mapping[tuple, float],
                             dominance: float = DEFAULT_DOMINANCE) -> Source:
    """A DirectedTopology Source over directed per-pair volume `(src_dev,dst_dev)→bytes`.
    orient(a,b): compare bytes(a→b) vs bytes(b→a). The dominant direction wins when
    its share ≥ `dominance`; BALANCED → AMBIGUOUS (never an assumed direction); no
    flow either way → None (UNKNOWN)."""
    def _src(a: str, b: str) -> Orientation | None:
        ab = volume.get((a, b), 0.0)
        ba = volume.get((b, a), 0.0)
        total = ab + ba
        if total <= 0:
            return None
        if ab >= dominance * total:
            return Orientation(Verdict.A_UPSTREAM, confidence=ab / total, source="netflow")
        if ba >= dominance * total:
            return Orientation(Verdict.B_UPSTREAM, confidence=ba / total, source="netflow")
        return Orientation(Verdict.AMBIGUOUS, source="netflow")  # balanced → abstain

    return _src
