# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tracker 166A/166B/166C — the scheduler's new state must CONVERGE.

Bounded CPU is not enough. The carried-edge cache and the processed frontier
are both new structures that did not exist when tracker 165 qualified the
1.25 GiB envelope, and either could turn a bounded window into an unbounded
process.

The invariant under test:

    No carried edge may outlive the evidence that justifies it. When the
    semantic window releases a node, every edge incident to it must go.

    The processed frontier is a function of RETAINED STATE, never of process
    uptime.

These are convergence tests, not "did the cleanup line execute" tests: they
drive state through a full turnover and assert where it lands.
"""
from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone

import pytest

import main
from test_prune_buffer_156 import mk


@pytest.fixture(autouse=True)
def _clean():
    main.WINDOW_BUFFER.clear(); main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear(); main._PROCESSED_IDS.clear()
    main.TENANT_WATERMARK.clear(); main._TENANT_EDGES.clear()
    main.EDGE_CACHE_DROPPED = 0
    main.COPARTITION_OK = True
    yield
    main._TENANT_EDGES.clear(); main._PROCESSED_IDS.clear()


class _Edge:
    """Minimal stand-in with the two fields the cache keys on."""
    def __init__(self, a, b):
        self.from_node, self.to_node = a, b


class _Snap:
    def __init__(self, edges):
        self.edges = edges


def _sig_for(key_dev: int, kind: str, off: float, tenant="acme"):
    s = mk(key_dev, off)
    return main.dc_replace(s, tenant_id=tenant, kind=kind)


def _key(s):
    return f"{s.entity_type.value}:{s.entity_id}:{s.kind}"


# ── 166B: the lifecycle invariant ────────────────────────────────────────────

def test_an_edge_is_dropped_when_its_endpoint_leaves_the_window():
    live = _sig_for(1, "link_state_change", 0)
    gone = _sig_for(2, "if_util_high", 0)
    main._remember_edges("acme", [_Snap([_Edge(_key(live), _key(gone))])])
    assert main.edge_cache_state()["edges"] == 1

    # window now holds only `live`
    carried = main._carried_edges_for("acme", main.live_node_keys([live]))
    assert carried == (), "an edge to a released node was carried forward"
    assert main.edge_cache_state()["edges"] == 0
    assert main.EDGE_CACHE_DROPPED == 1


def test_an_edge_survives_while_BOTH_endpoints_remain():
    a = _sig_for(1, "link_state_change", 0)
    b = _sig_for(1, "if_util_high", 5)
    main._remember_edges("acme", [_Snap([_Edge(_key(a), _key(b))])])
    carried = main._carried_edges_for("acme", main.live_node_keys([a, b]))
    assert len(carried) == 1
    assert main.EDGE_CACHE_DROPPED == 0


def test_the_cache_converges_to_empty_after_a_full_window_turnover():
    """The decisive one. Fill, then release everything, and require the cache
    to land at zero — not merely to have called its cleanup."""
    sigs = [_sig_for(d, "link_state_change", d) for d in range(20)]
    edges = [_Edge(_key(sigs[i]), _key(sigs[i + 1])) for i in range(19)]
    main._remember_edges("acme", [_Snap(edges)])
    assert main.edge_cache_state()["edges"] == 19

    main._carried_edges_for("acme", main.live_node_keys([]))        # window fully released
    assert main.edge_cache_state()["edges"] == 0, "cache did not converge"
    assert main.edge_cache_state()["tenants"] == 0, "empty tenant entry lingers"


def test_the_cache_plateaus_when_the_node_SET_plateaus():
    """The live shape: signals keep arriving but the (entity, kind) node set is
    bounded by the estate, so the cache must stop growing once every grounding
    pair has been seen — not keep growing with signal count."""
    nodes = [_sig_for(d, "link_state_change", d) for d in range(10)]
    sizes = []
    for round_ in range(5):
        # same node keys every round, new signals
        edges = [_Edge(_key(nodes[i]), _key(nodes[j]))
                 for i in range(10) for j in range(i + 1, 10)]
        main._remember_edges("acme", [_Snap(edges)])
        main._carried_edges_for("acme", main.live_node_keys(nodes))
        sizes.append(main.edge_cache_state()["edges"])
    assert sizes[0] == sizes[-1] == 45, f"cache grew past its node set: {sizes}"


def test_a_tenants_cache_cannot_leak_into_another():
    a = _sig_for(1, "link_state_change", 0, tenant="t1")
    b = _sig_for(1, "if_util_high", 5, tenant="t1")
    main._remember_edges("t1", [_Snap([_Edge(_key(a), _key(b))])])
    assert main._carried_edges_for("t2", main.live_node_keys([a, b])) == ()
    assert len(main._carried_edges_for("t1", main.live_node_keys([a, b]))) == 1


# ── 166C: the processed frontier is bounded by retained state ────────────────

def _load(n, start=0):
    for i in range(n):
        s = mk(start + i, start + i)
        main.WINDOW_BUFFER.append(s)
        main._BUFFERED_ID_ORDER.append(str(s.signal_id))
        main._BUFFERED_IDS.add(str(s.signal_id))


def test_frontier_size_tracks_retained_state_not_uptime():
    """Ten full turnovers. If the frontier were a function of uptime it would
    grow to 10x the window; it must stay a function of what is retained."""
    peaks = []
    for cycle in range(10):
        _load(100, start=cycle * 1000)
        main._mark_processed(main.pending_signals())
        peaks.append(len(main._PROCESSED_IDS))
        # release the whole window through the real expiry path
        newest = max(s.ts.timestamp() for s in main.WINDOW_BUFFER)
        main.TENANT_WATERMARK["acme"] = (
            newest + main.RETENTION_REQUIRED_S + 10_000, time.monotonic())
        asyncio.run(main._prune_buffer(datetime.now(timezone.utc)))
        assert len(main.WINDOW_BUFFER) == 0
    assert max(peaks) == 100, f"frontier grew across turnovers: {peaks}"
    assert main._PROCESSED_IDS == set(), "frontier did not converge to empty"


def test_frontier_never_exceeds_the_retained_population():
    _load(500)
    main._mark_processed(main.pending_signals())
    st = main.scheduler_state()
    assert st["processed_tracked"] <= len(main.WINDOW_BUFFER), (
        "the frontier tracks more ids than the window holds")


def test_frontier_ratio_is_reported():
    _load(200)
    main._mark_processed(main.pending_signals()[:120])
    st = main.scheduler_state()
    assert st["processed_tracked"] == 120
    assert st["pending"] == 80
    assert st["processed_tracked"] + st["pending"] == len(main.WINDOW_BUFFER)
