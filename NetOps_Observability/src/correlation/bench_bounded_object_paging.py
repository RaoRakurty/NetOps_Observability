#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Standalone micro-benchmark for the P0 boundedness pass (ENGINE_DECISION_2026-08-28
#1/#2). NO live stack, NO Docker, NO ClickHouse — pure CPU timing of the child-row
emit path (edges + typed edges + evidence, plus the JSONEachRow insert bodies).

It compares, at the two profiled storm shapes:
  * BEFORE — the monolithic path: build each to_*_rows() list whole, then
    serialize the whole list into one insert body (one uninterruptible C call
    each, exactly what the offloaded pre-P0 path did per object).
  * AFTER  — main._emit_child_rows' paging: build the rows in CORR_ROW_PAGE_SIZE
    pages and serialize them in CORR_ROW_BATCH_ROWS insert-body batches, yielding
    the event loop between every unit.

For each it reports the WORST single synchronous work unit (the number the ≤500ms
target is about), the TOTAL emit+serialize time, and the MAX contiguous block the
loop would be blocked WITHOUT a yield (= the worst unit in each model, since AFTER
yields between every unit and BEFORE's units are the offload-boundary segments).

Run:  cd src/correlation && python3 bench_bounded_object_paging.py
"""

from __future__ import annotations

import dataclasses
import time
from datetime import datetime, timedelta, timezone

import main
from catalog import builtin_catalog
from engine import (
    Edge,
    EngineConfig,
    Grounding,
    build_nodes,
    run_window,
)
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)

T0 = datetime(2026, 6, 12, 9, 42, 0, tzinfo=timezone.utc)
TARGET_MS = 500.0


def _sig(kind, et, eid, *, off=0.0, src=Source.METRIC, sev=Severity.HIGH,
         tokens=()):
    return Signal(
        tenant_id="t1", ts=T0 + timedelta(seconds=off), source=src, kind=kind,
        observer=Observer(observer_id="obs1", observer_type=ObserverType.DEVICE),
        modality_class=ModalityClass.DEVICE_TELEMETRY, entity_type=et,
        entity_id=eid, severity=sev, native_id=f"b|{kind}|{eid}|{off}",
        entity_tokens=tokens, attrs={"onset_uncertainty_s": 5.0})


def _base_snapshot():
    """A real, valid ObjectSnapshot (ranking/seams/etc. populated) we re-shape."""
    window = (
        _sig("device_cpu_high", EntityType.DEVICE, "dallas-edge"),
        _sig("if_errors", EntityType.INTERFACE, "dallas-edge:Gi0/1", off=20),
        _sig("app_identity", EntityType.APP, "TeamsApp", off=15,
             src=Source.APP_IDENTITY, sev=Severity.INFO, tokens=("dallas-edge",)),
    )
    snaps = run_window(window, builtin_catalog(), (), EngineConfig())
    return next(s for s in snaps
                if "dallas-edge" in s.affected().get("devices", []))


def _storm_snapshot(n_nodes: int, n_edges: int):
    """The profiled storm shape: n_nodes real graph nodes + n_edges candidate
    edges. Nodes are real (build_nodes) so node count is honest; edges are
    deterministic rank-7 candidates (grounding_ref non-empty)."""
    node_sigs = tuple(
        _sig("metric_anomaly", EntityType.DEVICE, f"dev{i}", off=i % 60)
        for i in range(n_nodes))
    nodes = build_nodes(node_sigs)
    keys = [n.key for n in nodes] or ["device:dev0:m"]
    edges = tuple(
        Edge(from_node=keys[i % len(keys)],
             to_node=keys[(i + 1) % len(keys)],
             grounding=Grounding("topo", f"shared:tok{i % 101}", None),
             weight=0.5, w_temporal=0.4, w_topo=0.3, w_reinforce=0.2,
             direction_conf=0.0, direction_basis="none")
        for i in range(n_edges))
    return dataclasses.replace(_base_snapshot(), nodes=nodes, edges=edges)


def _time(fn, *args):
    t = time.perf_counter()
    out = fn(*args)
    return (time.perf_counter() - t) * 1000.0, out


def _before(snap, version):
    """Monolithic: one build + one body-serialize per child table."""
    units: list[tuple[str, float]] = []
    for name, build in (
        ("build corr_edges", lambda: snap.to_edge_rows(version)),
        ("build corr_path_edges", lambda: snap.to_typed_edge_rows(version)),
        ("build corr_evidence", lambda: snap.to_evidence_rows(version)),
    ):
        ms, rows = _time(build)
        units.append((name, ms))
        ms_body, _ = _time(main._ndjson_body, rows)
        units.append((name.replace("build", "serialize"), ms_body))
    return units


def _after(snap, version):
    """Paged: CORR_ROW_PAGE_SIZE builds + CORR_ROW_BATCH_ROWS body-serializes,
    a yield between every unit (so every unit is its own loop-block segment)."""
    page = main.CORR_ROW_PAGE_SIZE
    batch_rows = main.CORR_ROW_BATCH_ROWS
    units: list[tuple[str, float]] = []
    streams = (
        ("corr_edges", snap.edge_row_page, len(snap.edges)),
        ("corr_path_edges", snap.typed_edge_row_page, len(snap.edges)),
        ("corr_evidence", snap.evidence_row_page, snap.evidence_row_count()),
    )
    for name, page_fn, total in streams:
        batch: list[dict] = []
        start = 0
        while start < total:
            stop = min(start + page, total)
            ms, rows = _time(page_fn, version, start, stop)
            units.append((f"page-build {name}", ms))
            batch.extend(rows)
            start = stop
            if len(batch) >= batch_rows:
                ms_body, _ = _time(main._ndjson_body, batch)
                units.append((f"batch-serialize {name}", ms_body))
                batch = []
        if batch:
            ms_body, _ = _time(main._ndjson_body, batch)
            units.append((f"batch-serialize {name}", ms_body))
    return units


def _summ(units):
    worst_name, worst = max(units, key=lambda u: u[1])
    return {
        "worst_ms": worst,
        "worst_name": worst_name,
        "total_ms": sum(u[1] for u in units),
        "n_units": len(units),
    }


def _run_shape(label, n_nodes, n_edges):
    snap = _storm_snapshot(n_nodes, n_edges)
    b = _summ(_before(snap, 3))
    a = _summ(_after(snap, 3))
    print(f"\n{label}: {len(snap.nodes)} nodes / {len(snap.edges):,} edges "
          f"(page={main.CORR_ROW_PAGE_SIZE}, batch={main.CORR_ROW_BATCH_ROWS})")
    print(f"  {'':22}{'worst unit (ms)':>18}{'total (ms)':>14}"
          f"{'max block no-yield (ms)':>26}")
    print(f"  {'BEFORE (monolithic)':22}{b['worst_ms']:>18.1f}"
          f"{b['total_ms']:>14.1f}{b['worst_ms']:>26.1f}")
    print(f"  {'AFTER  (paged)':22}{a['worst_ms']:>18.1f}"
          f"{a['total_ms']:>14.1f}{a['worst_ms']:>26.1f}")
    verdict = "PASS <=500ms" if a["worst_ms"] <= TARGET_MS else "OVER 500ms"
    print(f"  worst AFTER unit: '{a['worst_name']}'  → {verdict}"
          f"  ({a['n_units']} units, yield between each)")
    print(f"  BEFORE worst unit: '{b['worst_name']}'  "
          f"(reduction {b['worst_ms'] / max(a['worst_ms'], 1e-9):.1f}x)")
    return b, a


def main_bench():
    print("=" * 78)
    print("P0 boundedness pass — child-row emit micro-benchmark (pure CPU, no stack)")
    print("=" * 78)
    _run_shape("SHAPE 1 (300n/45k)", 300, 45_000)
    _run_shape("SHAPE 2 (600n/180k)", 600, 180_000)
    print("\nnote: worst-unit is the number the <=500ms target governs. BEFORE ran"
          " these as\n      whole-object offloaded C calls (GIL-held), starving the"
          " heartbeat for the\n      call's duration; AFTER yields the loop between"
          " every bounded unit.")


if __name__ == "__main__":
    main_bench()
