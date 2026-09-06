# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Wall-clock perf canary (perf-nightly rung — NOT a benchmark).

Everything else in the perf family (test_engine_complexity, test_rolling_stats,
test_ch_batching, test_series_budget) asserts OPERATION COUNTS and is therefore
runner-speed independent. This file is the one deliberate exception: a
catastrophic-regression detector. The naive O(n²) build_edges measured ~48s on
a 1k-node window (perf defect #1); the fixed engine finishes the same windows
in well under a second. A 30s ceiling can only trip if that class of regression
comes back — no healthy runner, however slow or contended, gets anywhere near
it, and no micro-regression can hide under it (the operation-count suites own
that ground).

Gating: marked ``perf_canary`` and skipped unless PERF_CANARY=1 (see
conftest.py) so the blocking PR gate never depends on wall-clock behavior;
perf-nightly.yml opts in. Failure policy: the workflow failure itself is the
alert (LOUD by owner decision); wiring it to ntfy is a follow-up.
"""

from __future__ import annotations

import time

import pytest

from engine import EngineConfig, build_edges, build_nodes
from signals import EntityType
from test_engine_complexity import sig

# Catastrophic ceiling, in seconds. Deliberately generous: expected runtime is
# < 1s; the reverted-to-naive engine measured ~48s. Do NOT tighten this into a
# benchmark — runner speed varies, operation counts are pinned elsewhere.
CANARY_CEILING_S = 30.0

N_NODES = 1_000


def _clustered_1k_signals():
    """The adversarial 1k shape: 100 clusters of 10 token-sharing nodes, so
    build_edges must both prune (inter-cluster) and score (intra-cluster)."""
    return tuple(
        sig("metric_anomaly", EntityType.SERVICE, f"c{c:03d}-m{k}",
            offset_s=float(k), tokens=(f"cluster-{c:03d}",))
        for c in range(100) for k in range(10)
    )


def _disjoint_1k_signals():
    """The storm shape: 1k nodes sharing nothing — C(n,2) gap hints, 0 edges."""
    return tuple(
        sig("metric_anomaly", EntityType.SERVICE, f"svc-{k:04d}",
            offset_s=float(k % 300))
        for k in range(N_NODES)
    )


@pytest.mark.perf_canary
@pytest.mark.parametrize("shape,make_signals", [
    ("disjoint", _disjoint_1k_signals),
    ("clustered", _clustered_1k_signals),
])
def test_build_edges_1k_window_under_catastrophic_ceiling(shape, make_signals):
    nodes = build_nodes(make_signals())
    assert len(nodes) == N_NODES, "canary window must really hold 1k nodes"

    start = time.perf_counter()
    edges, gap_hints = build_edges(nodes, (), EngineConfig())
    elapsed = time.perf_counter() - start

    # Sanity that the run did real work (not an early-out on bad input): the
    # honest gap-hint total is C(1000,2) minus intra-cluster candidate pairs.
    total_pairs = N_NODES * (N_NODES - 1) // 2
    if shape == "disjoint":
        assert edges == () and gap_hints == total_pairs
    else:
        assert gap_hints < total_pairs

    assert elapsed < CANARY_CEILING_S, (
        f"CATASTROPHIC perf regression: build_edges on the {shape} 1k-node "
        f"window took {elapsed:.1f}s (ceiling {CANARY_CEILING_S:.0f}s; healthy "
        "runs finish in <1s, the naive O(n²) engine measured ~48s). See "
        "test_engine_complexity.py for the operation-count contracts."
    )
