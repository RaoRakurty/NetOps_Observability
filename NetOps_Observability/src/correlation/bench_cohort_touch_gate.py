#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Standalone micro-benchmark for P1 — the cohort-touch gate + digest memoization
(docs/design/COHORT_TOUCH_GATE_P1_2026-08-28.md §7). Evidence, not a gate.

NO live stack, NO Docker, NO ClickHouse: pure CPU timing of the two things a
drain epoch pays per cohort over an unchanged snapshot —

  1. run_window      — component formation, ranking, snapshot materialization;
  2. reconciliation  — main._engine_cycle_inner's per-snapshot loop: content_hash,
                       the registry compare, and material_hash on a content move
                       (the damping decision). Persistence is deliberately NOT
                       simulated: this measures re-derivation, which is what P1
                       removes.

It runs the SAME synthetic epoch twice — gate OFF (pre-P1: every component
re-ranked and re-materialized every cohort, every digest recomputed) and gate ON
(untouched components served from the intra-epoch ComponentMemo, digests cached
per instance) — and prints one JSON document.

The acceptance number (spec §9.3): on cohorts >= 2, memo hits ≈
(1 - touch_ratio) x components.

Run:  cd src/correlation && python3 bench_cohort_touch_gate.py
      python3 bench_cohort_touch_gate.py --components 2000 --cohorts 10 --touch 0.02
"""

from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timedelta, timezone

import engine
from catalog import builtin_catalog
from engine import (
    ComponentMemo,
    EngineConfig,
    ObjectSnapshot,
    build_nodes,
    prepare_run_window,
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

T0 = datetime(2026, 8, 28, 9, 0, 0, tzinfo=timezone.utc)
CAT = builtin_catalog()
CFG = EngineConfig()


def _sig(kind: str, entity_id: str, off: float, modality: ModalityClass,
         severity: Severity) -> Signal:
    return Signal(
        tenant_id="bench", ts=T0 + timedelta(seconds=off), source=Source.METRIC,
        kind=kind,
        observer=Observer(observer_id="obs1", observer_type=ObserverType.DEVICE),
        modality_class=modality, entity_type=EntityType.INTERFACE,
        entity_id=entity_id, severity=severity,
        native_id=f"bench|{kind}|{entity_id}|{off}",
        attrs={"onset_uncertainty_s": 5.0})


def _window(n_components: int) -> tuple[list[Signal], list[frozenset[str]]]:
    """One tenant, n two-node identity-grounded components — the shape a storm
    presents: many small independent incidents, each with an edge and a verdict.
    Returns the window and, per component, its node-key set."""
    sigs: list[Signal] = []
    comp_keys: list[frozenset[str]] = []
    for i in range(n_components):
        a = _sig("if_util_high", f"dev{i}:Gi0/1", i * 0.01,
                 ModalityClass.DEVICE_TELEMETRY, Severity.HIGH)
        b = _sig("if_errors_high", f"dev{i}:Gi0/1", i * 0.01 + 5,
                 ModalityClass.CONTROL_PLANE, Severity.WARN)
        sigs.extend((a, b))
        comp_keys.append(frozenset(n.key for n in build_nodes((a, b))))
    return sigs, comp_keys


def _reconcile(snapshots: list[ObjectSnapshot], registry: dict) -> dict:
    """main._engine_cycle_inner's reconciliation, minus the IO: hash, compare,
    and on a content move hash the material identity to decide damp vs persist.
    Byte-for-byte the same calls, so the digest cache's effect is honest."""
    persisted = damped = opened = 0
    for snap in snapshots:
        chash = snap.content_hash()
        reg = registry.get(snap.correlation_id)
        if reg is None:
            registry[snap.correlation_id] = {"hash": chash,
                                             "material": snap.material_hash()}
            opened += 1
        elif reg["hash"] != chash:
            mhash = snap.material_hash()
            if mhash != reg["material"]:
                persisted += 1
            else:
                damped += 1
            reg["hash"] = chash
            reg["material"] = mhash
    return {"opened": opened, "persisted": persisted, "damped": damped}


def _run(window, comp_keys, cohorts: int, touch: float, *, gate: bool) -> dict:
    """One synthetic epoch: freeze the window, prepare ONCE, drain K cohorts."""
    prep = prepare_run_window(tuple(window), (), CFG)
    memo = ComponentMemo() if gate else None
    registry: dict = {}
    carried: dict[tuple[str, str], object] = {}
    per_component = max(1, round(len(comp_keys) * touch))
    digest_before = engine.digest_cache_stats()
    per_cohort: list[dict] = []

    for k in range(cohorts):
        start = (k * per_component) % len(comp_keys)
        touched = comp_keys[start:start + per_component]
        keys = frozenset(key for c in touched for key in c)

        t0 = time.perf_counter()
        snapshots = run_window(window, CAT, (), CFG, cohort_keys=keys,
                               carried_edges=tuple(carried.values()), prep=prep,
                               memo=memo)
        t1 = time.perf_counter()
        outcome = _reconcile(snapshots, registry)
        t2 = time.perf_counter()
        for s in snapshots:
            for e in s.edges:
                carried[(e.from_node, e.to_node)] = e
        per_cohort.append({
            "cohort": k + 1,
            "objects": len(snapshots),
            "run_window_ms": round((t1 - t0) * 1000, 2),
            "reconcile_ms": round((t2 - t1) * 1000, 2),
            "memo_hits": memo.hits if memo is not None else 0,
            **outcome,
        })

    digest = {k: engine.digest_cache_stats()[k] - digest_before[k]
              for k in digest_before}
    total_ms = sum(c["run_window_ms"] + c["reconcile_ms"] for c in per_cohort)
    # memo counters are cumulative over the epoch; the deltas per cohort are what
    # the ratios are computed from (the engine never computes a ratio itself).
    hits = [c["memo_hits"] - (per_cohort[i - 1]["memo_hits"] if i else 0)
            for i, c in enumerate(per_cohort)]
    return {
        "gate": gate,
        "cohorts": per_cohort,
        "memo_hits_per_cohort": hits,
        "total_ms": round(total_ms, 2),
        "run_window_ms_total": round(sum(c["run_window_ms"] for c in per_cohort), 2),
        "reconcile_ms_total": round(sum(c["reconcile_ms"] for c in per_cohort), 2),
        "components": memo.components if memo is not None else None,
        "components_touched": memo.touched if memo is not None else None,
        "components_ranked": memo.misses if memo is not None else None,
        "snapshot_digest": digest,
    }


def main_bench(components: int, cohorts: int, touch: float) -> dict:
    window, comp_keys = _window(components)
    off = _run(window, comp_keys, cohorts, touch, gate=False)
    on = _run(window, comp_keys, cohorts, touch, gate=True)
    per_component = max(1, round(len(comp_keys) * touch))
    steady = on["memo_hits_per_cohort"][1:]          # cohorts >= 2
    expected = len(comp_keys) - per_component
    report = {
        "fixture": {
            "tenant": 1, "components": components, "signals": len(window),
            "cohorts": cohorts, "touch_target": touch,
            "components_touched_per_cohort": per_component,
            "touch_ratio": round(per_component / components, 4),
        },
        "gate_off": off,
        "gate_on": on,
        "verdict": {
            # spec §9.3: hits ~= (1 - touch_ratio) x components on cohorts >= 2
            "expected_hits_per_cohort_from_cohort_2": expected,
            "observed_hits_per_cohort_from_cohort_2": steady,
            "hits_match_expectation": all(h == expected for h in steady),
            "total_speedup_x": round(off["total_ms"] / max(on["total_ms"], 1e-9), 2),
            "run_window_speedup_x": round(
                off["run_window_ms_total"] / max(on["run_window_ms_total"], 1e-9), 2),
            "reconcile_speedup_x": round(
                off["reconcile_ms_total"] / max(on["reconcile_ms_total"], 1e-9), 2),
            "eval_waste_removed": (off["cohorts"][0]["objects"] * cohorts
                                   - (on["components_ranked"] or 0)),
        },
    }
    print(json.dumps(report, indent=2))
    return report


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--components", type=int, default=5000)
    ap.add_argument("--cohorts", type=int, default=10)
    ap.add_argument("--touch", type=float, default=0.02)
    args = ap.parse_args()
    main_bench(args.components, args.cohorts, args.touch)
