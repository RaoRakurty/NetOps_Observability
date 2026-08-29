#!/usr/bin/env python3
"""P2 `memflat` attribution — where does RSS go AFTER input stops? OFFLINE.

THE QUESTION
    The live 2.5K run's `memflat` gate FAILED after P2 steps 0-2: replica RSS
    went 494 -> 753 MiB (x1.53 > x1.3) *after input stopped*, while the engine
    still had ~21k pending signals to drain. Three candidate owners of that
    growth, and the gate cannot tell them apart:

      (a) WORKING SET   — OPEN_OBJECTS registry (one ObjectSnapshot per open
                          correlation object, each holding nodes/edges/signals),
                          the frozen window, the processed-id frontier.
      (b) THE P2 CACHES — RankMemo entries (RankingResult payloads),
                          Clause.kinds identity cache, Signal.signal_id
                          per-instance cache, the blob-per-cycle cache.
      (c) UNEXPLAINED   — i.e. a leak candidate.

WHAT THIS RUNS
    The same REAL drain sweep `bench_profile_p2.py` drives — `main._begin_epoch`
    -> N x `main.engine_cycle(epoch)` -> `main._epoch_lifecycle` ->
    `main._close_epoch` — over the same 2,500-device-SHAPED synthetic stream
    built by the REAL syslog producer (fixture reused from `bench_profile_p2`,
    so the two benches profile the identical workload). Persistence is mocked.
    NOTHING in engine.py / main.py / signals.py / catalog.py is modified: this
    module only reads.

    The sweep is shaped like the live memflat window:

      phase 1  ARRIVALS   — `--arrival-epochs` epochs, each preceded by a new
                            burst of signals, each draining `--cohorts` cohorts.
                            Input is flowing; the engine is behind.
      SNAPSHOT `input_stopped`  <- the live gate's t0 (RSS 494 MiB)
      phase 2  DRAIN      — epochs with NO arrivals until `epoch.pending()` is
                            empty (or `--max-drain-epochs`). Stream time is
                            frozen, so `_prune_buffer` expires nothing — exactly
                            the live shape.
      SNAPSHOT `drained`        <- the live gate's t1 (RSS 753 MiB)
      SNAPSHOT `memo_cleared`   <- RankMemo.clear() + clause cache clear + gc
      SNAPSHOT `working_set_dropped` <- OPEN_OBJECTS/window/ids cleared + gc

    The last two answer "reclaimable cache or leak": if RSS/heap returns toward
    the `input_stopped` level once the memo and then the working set are
    dropped, nothing leaked — it was retained, on purpose, by a named owner.

WHAT IS MEASURED AT EVERY SNAPSHOT
    * RSS / VmHWM from /proc/self/status (the number the live gate reads).
    * `tracemalloc` traced total + per-file and per-line attribution (--tracemalloc).
    * A gc census: live-object COUNT and shallow bytes per type of interest
      (RankingResult, ObjectSnapshot, Signal, Node, Edge, HypothesisScore,
      dict, str, tuple, list, set, frozenset, UUID, datetime).
    * DEEP bytes of every named owner, and — the number that actually settles
      the attribution — each owner's EXCLUSIVE deep bytes: what it retains that
      nothing already-walked retains. The RankMemo is walked LAST, seeded with
      everything the working set already holds, so a RankingResult that the memo
      shares with a live ObjectSnapshot is charged to the working set, not twice.

RUN
    cd src/correlation
    python3 bench_memflat_p2.py --label on                       # all P2 caches on
    CORR_RANK_MEMO=0 python3 bench_memflat_p2.py --label memo_off
    CORR_RANK_MEMO=0 CORR_BLOB_CYCLE_CACHE=0 CORR_CLAUSE_KINDS_CACHE=0 \
      CORR_SIGNAL_ID_CACHE=0 python3 bench_memflat_p2.py --label all_off
    python3 bench_memflat_p2.py --tracemalloc --label on_tm      # + line attribution

    Every knob is read once at import (like the P1/P2 flags), so the A/B is env
    only — one image, one fixture, one seed.

WHAT THIS OFFLINE SHAPE DOES *NOT* REPRODUCE
    The live replica's RSS also carries the Kafka client (fetch buffers, one
    per-partition prefetch), httpx/ClickHouse connection pools and their TLS
    buffers, the asyncio loop's task/timer churn, the aiohttp health sidecar,
    and glibc arena fragmentation under a two-thread (loop + executor) allocator
    pattern. None of that is present here: persistence is a counting stub and
    there is no broker. Read the numbers below as the ENGINE's share of the live
    growth, not as the live RSS curve.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import gc
import json
import os
import sys
import time
import tracemalloc
import types
from datetime import datetime, timedelta, timezone
from enum import Enum

os.environ.setdefault("CORR_SIGNALS_ENABLED", "true")
os.environ.setdefault("CORR_ENGINE_ENABLED", "true")

import logging

import catalog as catalog_mod
import engine
import main
import scoring as scoring_mod
import signals as signals_mod
from bench_profile_p2 import load, make_signals

# ═══════════════════════════════════════════════════════════════════════════
# mocked persistence — counts rows, inserts nothing, retains nothing
# ═══════════════════════════════════════════════════════════════════════════


class MockCH:
    """`main.ch` stand-in. Deliberately does NOT keep the rows: this bench
    measures what the ENGINE retains, and a sink that hoarded every row would
    invent a retention the real (streaming, HTTP) sink does not have."""

    def __init__(self) -> None:
        self.rows: dict[str, int] = {}
        self.calls: dict[str, int] = {}

    async def insert(self, table, rows, **kw):
        n = 0
        for _ in rows:
            n += 1
        self.rows[table] = self.rows.get(table, 0) + n
        self.calls[table] = self.calls.get(table, 0) + 1
        return True


# ═══════════════════════════════════════════════════════════════════════════
# sizing primitives
# ═══════════════════════════════════════════════════════════════════════════

_SKIP_TYPES = (type, types.ModuleType, types.FunctionType, types.MethodType,
               types.BuiltinFunctionType, types.GetSetDescriptorType,
               types.MemberDescriptorType)


def deep_size(roots, seen: set[int] | None = None,
              by_type: dict | None = None) -> tuple[int, set[int]]:
    """Transitive bytes reachable from `roots`, counting each object ONCE.

    Traversal is `gc.get_referents`, so it needs no per-type knowledge and
    cannot silently miss a container (frozen dataclasses, pydantic models,
    enums and UUIDs all traverse correctly). Classes, modules and functions are
    not followed — following a type reaches the whole interpreter and would
    charge every owner the same multi-MB constant.

    Returns (bytes, seen). Pass `seen` back in to make the NEXT call EXCLUSIVE
    of everything already walked: that is how a RankingResult shared between an
    open object and the rank memo is charged exactly once, to whoever is walked
    first."""
    if seen is None:
        seen = set()
    stack = list(roots)
    total = 0
    if by_type is None:
        by_type = {}
    while stack:
        obj = stack.pop()
        oid = id(obj)
        if oid in seen:
            continue
        if isinstance(obj, _SKIP_TYPES):
            continue
        seen.add(oid)
        try:
            n = sys.getsizeof(obj)
        except TypeError:                       # pragma: no cover - exotic types
            n = 0
        total += n
        tn = type(obj).__name__
        row = by_type.get(tn)
        if row is None:
            by_type[tn] = [1, n]
        else:
            row[0] += 1
            row[1] += n
        stack.extend(gc.get_referents(obj))
    return total, seen


def rss_kib() -> dict[str, int]:
    out = {"VmRSS": 0, "VmHWM": 0, "VmSize": 0}
    try:
        with open("/proc/self/status") as fh:
            for line in fh:
                k = line.split(":", 1)[0]
                if k in out:
                    out[k] = int(line.split()[1])
    except OSError:                             # pragma: no cover - non-Linux
        pass
    return out


CENSUS_TYPES = ("RankingResult", "ObjectSnapshot", "Signal", "Node", "Edge",
                "HypothesisScore", "Witness", "Observer", "dict", "str",
                "tuple", "list", "set", "frozenset", "UUID", "datetime",
                "OrderedDict", "deque")


def census() -> dict[str, dict[str, int]]:
    """Live-object count + shallow bytes per type of interest, over the WHOLE
    heap (`gc.get_objects`). Shallow on purpose: summed over every instance of a
    type it IS the type's total contribution, with no double counting between
    types the way a deep walk would have."""
    counts: dict[str, int] = {}
    bytes_: dict[str, int] = {}
    wanted = set(CENSUS_TYPES)
    for obj in gc.get_objects():
        name = type(obj).__name__
        if name not in wanted:
            continue
        counts[name] = counts.get(name, 0) + 1
        try:
            bytes_[name] = bytes_.get(name, 0) + sys.getsizeof(obj)
        except TypeError:                       # pragma: no cover
            pass
    # str is not tracked by the GC, so gc.get_objects() never returns one; the
    # census reports it as unmeasurable rather than as zero (a silent lie).
    return {n: {"count": counts.get(n, 0), "bytes": bytes_.get(n, 0)}
            for n in CENSUS_TYPES}


def _signal_id_cache_bytes() -> dict[str, int]:
    """The P2 `Signal.signal_id` per-instance cache, measured on THIS window:
    how many buffered signals carry `_signal_id_c`, and what they cost."""
    n = 0
    uuid_bytes = 0
    dict_bytes = 0
    for sig in main.WINDOW_BUFFER:
        cached = sig.__dict__.get("_signal_id_c")
        if cached is None:
            continue
        n += 1
        uuid_bytes += deep_size([cached], set())[0]
        dict_bytes += sys.getsizeof(sig.__dict__)
    return {"cached_signals": n, "uuid_bytes": uuid_bytes,
            "instance_dict_bytes_total": dict_bytes}


# ═══════════════════════════════════════════════════════════════════════════
# one measurement point
# ═══════════════════════════════════════════════════════════════════════════

def measure(label: str, *, tm: bool, light: bool = False) -> dict:
    """One measurement point.

    `light=True` measures RSS and counts ONLY. It exists because the deep walk
    is not free in the resource it is measuring: `seen` holds one id per live
    object — 1.2 M ids = ~32 MiB — so a full measurement at `input_stopped`
    leaves ~32 MiB of arena behind that the NEXT RSS reading would score as
    engine growth. The RSS curve therefore comes from a `--light` run and the
    byte attribution from a full one; mixing them overstates the growth."""
    gc.collect()
    point: dict = {"label": label, "rss": rss_kib(), "t": round(time.time(), 3)}
    # The tracemalloc snapshot is taken FIRST, before the deep walks: their
    # `seen` id-sets are tens of MB on a large heap and would otherwise show up
    # in the attribution as this bench measuring itself. The bench's own frames
    # are filtered out too, for the same reason.
    if tm:
        snap = tracemalloc.take_snapshot().filter_traces((
            tracemalloc.Filter(False, __file__),
            tracemalloc.Filter(False, tracemalloc.__file__),
            tracemalloc.Filter(False, "<frozen importlib._bootstrap>"),
        ))
        point["_tm"] = snap
        cur, peak = tracemalloc.get_traced_memory()
        point["tracemalloc"] = {"current_bytes": cur, "peak_bytes": peak}

    if light:
        memo = main.RANK_MEMO
        point["owners"] = {
            "open_objects": {"count": len(main.OPEN_OBJECTS)},
            "window_buffer": {"count": len(main.WINDOW_BUFFER)},
            "rank_memo": {"entries": len(memo) if memo is not None else 0,
                          "stats": dict(memo.stats()) if memo is not None else {}},
            "clause_kinds_cache": {"entries": len(catalog_mod._CLAUSE_KINDS_CACHE),
                                   "stats": catalog_mod.clause_kinds_cache_stats()},
        }
        return point

    # ── named owners, walked in a FIXED order so 'exclusive' is reproducible ──
    # Working set first (it is the thing the engine must hold), caches last:
    # anything the memo shares with a live snapshot is therefore charged to the
    # working set, and the memo's exclusive number is its TRUE marginal cost.
    seen: set[int] = set()
    owners: dict[str, dict] = {}

    def owner(name: str, roots, extra: dict | None = None) -> None:
        nonlocal seen
        incl, _ = deep_size(roots, set())
        bt: dict[str, list[int]] = {}
        excl, seen = deep_size(roots, seen, bt)
        top = sorted(bt.items(), key=lambda kv: -kv[1][1])[:6]
        row = {"deep_bytes_inclusive": incl, "deep_bytes_exclusive": excl,
               "exclusive_top_types": {k: {"count": v[0], "bytes": v[1]}
                                       for k, v in top}}
        if extra:
            row.update(extra)
        owners[name] = row

    owner("open_objects", [main.OPEN_OBJECTS],
          {"count": len(main.OPEN_OBJECTS)})
    owner("window_buffer", [main.WINDOW_BUFFER],
          {"count": len(main.WINDOW_BUFFER)})
    owner("processed_ids", [main._PROCESSED_IDS],
          {"count": len(main._PROCESSED_IDS)})
    owner("buffered_ids", [main._BUFFERED_IDS, main._BUFFERED_ID_ORDER],
          {"count": len(main._BUFFERED_IDS)})
    owner("archive_slice_hash", [main._ARCHIVE_SLICE_HASH],
          {"count": len(main._ARCHIVE_SLICE_HASH)})
    owner("tenant_edges", [main._TENANT_EDGES])
    owner("window_index_cache", [main._WINDOW_INDEX_CACHE, main._CYCLE_ROW_CACHE],
          {"count": len(main._WINDOW_INDEX_CACHE) + len(main._CYCLE_ROW_CACHE)})
    # PRE-P2, process-lifetime interns — not part of this attribution's question
    # but they sit on the same growth curve, so they are named rather than left
    # to inflate whatever gets walked next.
    owner("grounding_interns",
          [engine._SHARED_TOKEN_GROUNDINGS, engine._SEAM_TOKEN_GROUNDINGS],
          {"count": len(engine._SHARED_TOKEN_GROUNDINGS)
                    + len(engine._SEAM_TOKEN_GROUNDINGS)})
    owner("signal_interns",
          [signals_mod._OBSERVER_CACHE, signals_mod._ENTITY_ID_CACHE,
           signals_mod._ENTITY_TOKENS_CACHE],
          {"count": len(signals_mod._OBSERVER_CACHE)
                    + len(signals_mod._ENTITY_ID_CACHE)
                    + len(signals_mod._ENTITY_TOKENS_CACHE)})
    # The catalog is walked BEFORE the clause-kinds cache: the cache's values are
    # frozensets it owns, but its KEYS' Clause objects belong to the catalog, and
    # charging the whole template corpus to a micro-cache would be a fiction.
    owner("catalog", [main.CATALOG, catalog_mod._VERSION_HASH_CACHE,
                      scoring_mod._CATALOG_PLAN_CACHE])

    memo = main.RANK_MEMO
    memo_vals = list(memo._lru.values()) if memo is not None else []
    shared = 0
    if memo_vals:
        live_rankings = {id(reg["snapshot"].ranking)
                         for reg in main.OPEN_OBJECTS.values()
                         if isinstance(reg, dict) and "snapshot" in reg}
        shared = sum(1 for v in memo_vals if id(v) in live_rankings)
    owner("rank_memo", [memo._lru] if memo is not None else [],
          {"entries": len(memo_vals),
           "enabled": memo is not None,
           # A memoized RankingResult that a live open object ALSO points at is
           # not new retention; this is how many of the memo's entries are in
           # that class.
           "entries_shared_with_open_objects": shared,
           "stats": dict(memo.stats()) if memo is not None else {}})

    owner("clause_kinds_cache", [catalog_mod._CLAUSE_KINDS_CACHE],
          {"entries": len(catalog_mod._CLAUSE_KINDS_CACHE),
           "enabled": catalog_mod.CORR_CLAUSE_KINDS_CACHE,
           "stats": catalog_mod.clause_kinds_cache_stats()})

    sid = _signal_id_cache_bytes()
    sid["enabled"] = signals_mod.CORR_SIGNAL_ID_CACHE
    owners["signal_id_cache"] = sid

    owners["blob_cycle_cache"] = {
        "enabled": engine.CORR_BLOB_CYCLE_CACHE,
        "entries_now": engine.blob_cycle_size(),
        "max_entries": engine._BLOB_CYCLE_CACHE_MAX,
        "note": "cycle-scoped: opened by engine_cycle, dropped in its finally, "
                "so it is 0 between cycles by construction",
    }
    owners["digest_cache"] = {"stats": engine.digest_cache_stats()}

    point["owners"] = owners
    # The walker's id-set is dropped BEFORE the census: it is a multi-MB `set`
    # and would otherwise appear in the census as engine memory.
    seen.clear()
    del seen
    gc.collect()
    point["census"] = census()
    # The biggest individual objects on the heap, with a referrer hint. This is
    # the "unexplained" bucket's microscope: an owner table can only account for
    # what it names, and a single multi-MB container hiding outside every named
    # root is exactly the shape a leak takes.
    big = []
    for obj in gc.get_objects():
        if isinstance(obj, _SKIP_TYPES):
            continue
        try:
            n = sys.getsizeof(obj)
        except TypeError:
            continue
        if n >= 262144:
            hint = ""
            for r in gc.get_referrers(obj):
                if isinstance(r, dict):
                    for k, v in list(r.items())[:400]:
                        if v is obj and isinstance(k, str):
                            hint = k
                            break
                if hint:
                    break
            big.append((n, type(obj).__name__, len(obj) if hasattr(obj, "__len__") else -1, hint))
    big.sort(reverse=True)
    point["big_objects"] = [{"bytes": b[0], "type": b[1], "len": b[2], "attr": b[3]}
                            for b in big[:15]]
    gc.collect()
    return point


# ═══════════════════════════════════════════════════════════════════════════
# the sweep
# ═══════════════════════════════════════════════════════════════════════════

async def sweep(args) -> dict:
    now = datetime(2026, 8, 28, 12, 0, 0, tzinfo=timezone.utc)
    ch = MockCH()
    main.ch = ch
    points: list[dict] = []
    epochs: list[dict] = []
    seq = 0
    e = 0

    async def run_epoch(tag: str, when: datetime) -> dict:
        t0 = time.perf_counter()
        epoch = await main._begin_epoch(when)
        if args.storm:
            epoch.storm = True                 # the live 2.5K leg ran storm-declared
        pend_before = len(epoch.pending())
        cohorts = 0
        for _ in range(args.cohorts):
            await main.engine_cycle(epoch)
            epoch.cohorts = cohorts = cohorts + 1
            if not epoch.pending():
                break
        await main._epoch_lifecycle(epoch, main._make_loop_yield()[0])
        pend_after = len(epoch.pending())
        main._close_epoch(epoch)
        row = {
            "tag": tag, "wall_s": round(time.perf_counter() - t0, 2),
            "cohorts": cohorts, "pending_before": pend_before,
            "pending_after": pend_after, "window": len(main.WINDOW_BUFFER),
            "open_objects": len(main.OPEN_OBJECTS),
            "versions_persisted": main.VERSIONS_PERSISTED,
            "rank_memo_entries": main.rank_memo_stats()["entries"],
            "rss_kib": rss_kib()["VmRSS"],
        }
        epochs.append(row)
        print(f"  [{tag}] epoch wall={row['wall_s']}s cohorts={cohorts} "
              f"pending {pend_before}->{pend_after} window={row['window']} "
              f"open={row['open_objects']} memo={row['rank_memo_entries']} "
              f"rss={row['rss_kib'] // 1024} MiB", file=sys.stderr, flush=True)
        return row

    points.append(measure("start", tm=args.tracemalloc, light=args.light))

    # ── phase 1: arrivals still flowing ──────────────────────────────────────
    for i in range(args.arrival_epochs):
        batch = make_signals(args.signals, args.devices,
                             t_end=now + timedelta(seconds=30 * i),
                             span_s=args.span_s, seq0=seq, burst=args.burst)
        load(batch)
        seq += args.signals
        del batch
        await run_epoch(f"arrival {i + 1}/{args.arrival_epochs}",
                        now + timedelta(seconds=60 * e))
        e += 1

    points.append(measure("input_stopped", tm=args.tracemalloc, light=args.light))

    # ── phase 2: input has STOPPED; drain the backlog to empty ───────────────
    drained = 0
    for i in range(args.max_drain_epochs):
        row = await run_epoch(f"drain {i + 1}", now + timedelta(seconds=60 * e))
        e += 1
        drained += 1
        if row["pending_after"] == 0:
            break

    points.append(measure("drained", tm=args.tracemalloc, light=args.light))

    # ── reclaimability probe 1: drop the P2 caches only ──────────────────────
    if main.RANK_MEMO is not None:
        main.RANK_MEMO.clear()
    catalog_mod._CLAUSE_KINDS_CACHE.clear()
    gc.collect()
    points.append(measure("memo_cleared", tm=args.tracemalloc, light=args.light))

    # ── reclaimability probe 2: drop the working set as well ─────────────────
    main.OPEN_OBJECTS.clear()
    main._ARCHIVE_SLICE_HASH.clear()
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear()
    main._PROCESSED_IDS.clear()
    main._TENANT_EDGES.clear()
    gc.collect()
    gc.collect()
    points.append(measure("working_set_dropped", tm=args.tracemalloc, light=args.light))

    return {"points": points, "epochs": epochs, "drain_epochs": drained,
            "rows": dict(ch.rows), "insert_calls": dict(ch.calls),
            "versions_persisted": main.VERSIONS_PERSISTED,
            "versions_damped": main.VERSIONS_DAMPED}


# ═══════════════════════════════════════════════════════════════════════════
# the ESTIMATOR CALIBRATION (--calibrate)
# ═══════════════════════════════════════════════════════════════════════════
#
# THE QUESTION
#     `RankMemo`'s byte bound is only as good as `estimate_result_bytes`. The
#     live 2.5K run (p2-s04-08290653, replica-3, /metrics 07:54 UTC) showed the
#     original estimator reading ~56 KiB per entry, so a 96 MiB budget held
#     1,780 entries, evicted 38,177 and collapsed the hit rate from 66 % to 6 %.
#     The estimator was an UPPER BOUND by construction (no id-`seen` set, no
#     model of catalog-owned objects), and a memory bound sized off an upper
#     bound is a smaller cap than it claims to be.
#
# THE REFERENCE
#     `tracemalloc` is the only instrument that answers "how much memory would
#     the process give back if these N results were dropped", which is exactly
#     what a memo entry costs. The procedure:
#
#       1. capture REAL component evidence from a drain sweep (the same fixture
#          `bench_profile_p2` profiles), deduplicated by `rank_key` so every
#          result is a distinct memo entry;
#       2. drop the whole engine working set, so nothing else holds a result;
#       3. `tracemalloc.start()`, rank all N, `gc.collect()`, read `current`;
#       4. drop the results, `gc.collect()`, read `current` again.
#
#     The difference IS the aggregate marginal: cross-entry sharing is charged
#     once, exactly as RSS charges it. Divided by N it is the number the bound
#     must be denominated in.
#
#     A `gc.get_referents` deep walk over the same result set matched this
#     figure to 0.002 % (8,307,634 B walked vs 8,307,450 B freed), so the two
#     instruments agree and neither is measuring itself.


def _capture_evidence(args) -> list:
    """REAL component evidence tuples from a drain sweep, deduplicated by
    `rank_key` — one entry per distinct memo key, which is what the memo would
    actually hold. `engine.rank` is wrapped for the duration and restored."""
    import rank_memo as rank_memo_mod

    captured: list = []
    original = engine.rank

    def capture(catalog, evidence):
        captured.append(tuple(evidence))
        return original(catalog, evidence)

    async def drive() -> None:
        now = datetime(2026, 8, 28, 12, 0, 0, tzinfo=timezone.utc)
        main.ch = MockCH()
        seq = 0
        for i in range(args.arrival_epochs):
            batch = make_signals(args.signals, args.devices,
                                 t_end=now + timedelta(seconds=30 * i),
                                 span_s=args.span_s, seq0=seq, burst=args.burst)
            load(batch)
            seq += args.signals
            del batch
            epoch = await main._begin_epoch(now + timedelta(seconds=60 * i))
            if args.storm:
                epoch.storm = True
            cohorts = 0
            for _ in range(args.cohorts):
                await main.engine_cycle(epoch)
                epoch.cohorts = cohorts = cohorts + 1
                if not epoch.pending():
                    break
            await main._epoch_lifecycle(epoch, main._make_loop_yield()[0])
            main._close_epoch(epoch)
            print(f"  [calibrate] epoch {i + 1}/{args.arrival_epochs}: "
                  f"{len(captured)} rank() calls, open={len(main.OPEN_OBJECTS)}, "
                  f"rss={rss_kib()['VmRSS'] // 1024} MiB",
                  file=sys.stderr, flush=True)

    engine.rank = capture
    try:
        asyncio.run(drive())
    finally:
        engine.rank = original

    version = main.CATALOG.version_hash()
    seen_keys: set[str] = set()
    distinct: list = []
    for evidence in captured:
        key = rank_memo_mod.rank_key("global", version, evidence)
        if key is None or key in seen_keys:
            continue
        seen_keys.add(key)
        distinct.append(evidence)
    print(f"  [calibrate] {len(distinct)} distinct rank keys of "
          f"{len(captured)} rank() calls", file=sys.stderr)
    captured.clear()
    return distinct[:args.calib_results]


def _drop_working_set() -> None:
    if main.RANK_MEMO is not None:
        main.RANK_MEMO.clear()
    main.OPEN_OBJECTS.clear()
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear()
    main._PROCESSED_IDS.clear()
    main._TENANT_EDGES.clear()
    main._ARCHIVE_SLICE_HASH.clear()
    gc.collect()


def _estimator_at_5c035667(obj, _fields: dict | None = None) -> int:
    """The estimator EXACTLY as it shipped at 5c035667 — no id-`seen` set, no
    ownership test, no per-instance `__dict__`. Kept here (not imported) so the
    A/B survives the fix: it is the baseline the over-count is measured against,
    and it must not silently track a later edit to rank_memo.py."""
    if _fields is None:
        _fields = _OLD_FIELDS
    t = type(obj)
    if t is str:
        return sys.getsizeof("") + len(obj)
    if t is float or t is int or t is bool:
        return 24
    if obj is None:
        return 0
    if t is tuple or t is list or t is set or t is frozenset:
        return sys.getsizeof(obj) + sum(_estimator_at_5c035667(i, _fields)
                                        for i in obj)
    if t is dict:
        return sys.getsizeof(obj) + sum(
            _estimator_at_5c035667(k, _fields) + _estimator_at_5c035667(v, _fields)
            for k, v in obj.items())
    names = _fields.get(t)
    if names is None:
        names = (tuple(f.name for f in dataclasses.fields(obj))
                 if dataclasses.is_dataclass(obj) and not isinstance(obj, type)
                 else ())
        _fields[t] = names
    if not names:
        return 0 if isinstance(obj, Enum) else sys.getsizeof(obj)
    return sys.getsizeof(obj) + sum(
        _estimator_at_5c035667(getattr(obj, n), _fields) for n in names)


_OLD_FIELDS: dict = {}


def _variant_bytes(obj, *, id_seen: bool, ownership: bool, inst_dict: bool,
                   owned: frozenset = frozenset(), seen=None) -> int:
    """One term of the over-count decomposition: the SAME walk with each of the
    three corrections switchable, so `estimate_result_bytes`'s improvement can
    be attributed to a rule instead of asserted as a total."""
    if seen is None:
        seen = set() if id_seen else None
    t = type(obj)
    if t is str:
        if seen is not None or ownership:
            oid = id(obj)
            if ownership and oid in owned:
                return 0
            if seen is not None:
                if oid in seen:
                    return 0
                seen.add(oid)
        return sys.getsizeof("") + len(obj)
    if t is float or t is int or t is bool:
        return 24
    if obj is None:
        return 0
    oid = id(obj)
    if ownership and oid in owned:
        return 0
    if seen is not None:
        if oid in seen:
            return 0
        seen.add(oid)

    def rec(child):
        return _variant_bytes(child, id_seen=id_seen, ownership=ownership,
                              inst_dict=inst_dict, owned=owned, seen=seen)

    if t is tuple or t is list or t is set or t is frozenset:
        return sys.getsizeof(obj) + sum(rec(i) for i in obj)
    if t is dict:
        return sys.getsizeof(obj) + sum(rec(k) + rec(v) for k, v in obj.items())
    names = _OLD_FIELDS.get(t)
    if names is None:
        names = (tuple(f.name for f in dataclasses.fields(obj))
                 if dataclasses.is_dataclass(obj) and not isinstance(obj, type)
                 else ())
        _OLD_FIELDS[t] = names
    if not names:
        return 0 if isinstance(obj, Enum) else sys.getsizeof(obj)
    total = sys.getsizeof(obj)
    if inst_dict:
        d = getattr(obj, "__dict__", None)
        if type(d) is dict:
            total += sys.getsizeof(d)
    return total + sum(rec(getattr(obj, n)) for n in names)


def calibrate(args) -> dict:
    """The estimator against the tracemalloc reference over N REAL results."""
    import rank_memo as rank_memo_mod
    from scoring import rank as scoring_rank

    evidence_sets = _capture_evidence(args)
    if len(evidence_sets) < 2:
        raise SystemExit("calibration needs at least 2 distinct rank keys; "
                         "raise --signals / --arrival-epochs")
    _drop_working_set()

    catalog = main.CATALOG
    # Warm every lazily-built structure the FIRST rank()/estimate() would
    # allocate — the catalog plan, the witness-clause intern, the estimator's
    # field table and its per-catalog ownership set — so none of it lands in
    # the traced window and gets charged to the results.
    warm = [scoring_rank(catalog, ev) for ev in evidence_sets[:20]]
    rank_memo_mod.estimate_result_bytes(warm[0])
    _estimator_at_5c035667(warm[0])
    del warm
    gc.collect()

    tracemalloc.start(1)
    gc.collect()
    before = tracemalloc.get_traced_memory()[0]
    results = [scoring_rank(catalog, ev) for ev in evidence_sets]
    gc.collect()
    held = tracemalloc.get_traced_memory()[0]

    n = len(results)
    owned = rank_memo_mod._owned_ids(catalog.version_hash())
    calibrated = sum(rank_memo_mod.estimate_result_bytes(r) for r in results)
    no_ownership = sum(rank_memo_mod.estimate_result_bytes(r, frozenset())
                       for r in results)
    original = sum(_estimator_at_5c035667(r) for r in results)
    # Each correction switched on ALONE, so the total is attributable per rule.
    seen_only = sum(_variant_bytes(r, id_seen=True, ownership=False,
                                   inst_dict=False) for r in results)
    seen_dict = sum(_variant_bytes(r, id_seen=True, ownership=False,
                                   inst_dict=True) for r in results)

    del results
    gc.collect()
    after = tracemalloc.get_traced_memory()[0]
    tracemalloc.stop()
    marginal = held - after

    # COST IS MEASURED OUTSIDE THE TRACED WINDOW. tracemalloc instruments every
    # allocation, which roughly triples a walk that allocates a `seen` set per
    # call; timing inside it would report a number the engine never pays.
    timing_set = [scoring_rank(catalog, ev) for ev in evidence_sets]

    def timed(fn, batch: list) -> float:
        best = float("inf")
        for _ in range(3):
            t0 = time.perf_counter()
            for r in batch:
                fn(r)
            best = min(best, (time.perf_counter() - t0) / n * 1000.0)
        return best

    ms_new = timed(rank_memo_mod.estimate_result_bytes, timing_set)
    ms_old = timed(_estimator_at_5c035667, timing_set)
    sample = evidence_sets[:100]
    t0 = time.perf_counter()
    for ev in sample:
        scoring_rank(catalog, ev)
    ms_rank = (time.perf_counter() - t0) / len(sample) * 1000.0
    timing_set.clear()
    gc.collect()

    budget = rank_memo_mod.DEFAULT_MAX_BYTES
    return {
        "n": n, "before": before, "held": held, "after": after,
        "marginal_bytes": marginal,
        "calibrated_bytes": calibrated,
        "no_ownership_bytes": no_ownership,
        "seen_only_bytes": seen_only,
        "seen_dict_bytes": seen_dict,
        "original_bytes": original,
        "catalog_owned_objects": len(owned),
        "ms_new": ms_new, "ms_old": ms_old, "ms_rank": ms_rank,
        "budget": budget,
        "admits_calibrated": budget // max(1, calibrated // n),
        "admits_original": budget // max(1, original // n),
    }


def calib_report(res: dict) -> str:
    n = res["n"]
    k = 1024.0
    marginal = res["marginal_bytes"]

    def row(label: str, total: int) -> str:
        return (f"{label:<38}{total:>14,}{total / n / k:>12.2f}"
                f"{total / marginal:>11.3f}x")

    def step(label: str, total: int, prev: int | None) -> str:
        delta = "" if prev is None else f"{(total - prev) / n:>+11,.0f}"
        return f"  {label:<46}{total / n:>10,.0f}{delta}"

    w = [f"CALIBRATION over {n} REAL, rank-key-distinct storm-shaped results",
         "",
         f"{'instrument':<38}{'total B':>14}{'KiB/entry':>12}{'vs true':>12}",
         row("tracemalloc TRUE marginal (ref)", marginal),
         row("estimate_result_bytes (calibrated)", res["calibrated_bytes"]),
         row("  mutant: ownership test removed", res["no_ownership_bytes"]),
         row("  estimator as shipped at 5c035667", res["original_bytes"]),
         "",
         "DECOMPOSITION, one correction at a time (B/entry, cumulative)",
         step("5c035667", res["original_bytes"], None),
         step("(a) + id-seen set (double charge removed)",
              res["seen_only_bytes"], res["original_bytes"]),
         step("(b) + per-instance __dict__ (was UNDER-charged)",
              res["seen_dict_bytes"], res["seen_only_bytes"]),
         step(f"(c) + catalog ownership ({res['catalog_owned_objects']:,} owned ids)",
              res["calibrated_bytes"], res["seen_dict_bytes"]),
         step("residual vs the tracemalloc reference",
              marginal, res["calibrated_bytes"]),
         "",
         (f"cost: calibrated {res['ms_new']:.4f} ms/entry, "
          f"5c035667 {res['ms_old']:.4f} ms/entry, "
          f"rank() {res['ms_rank']:.3f} ms/call "
          f"({100 * res['ms_new'] / res['ms_rank']:.1f} % of the call it only "
          f"runs on a MISS)"),
         "",
         (f"CORR_RANK_MEMO_BYTES_MAX = {res['budget'] / 1048576:.0f} MiB admits "
          f"{res['admits_calibrated']:,} entries at this shape "
          f"(was {res['admits_original']:,} under the 5c035667 estimator)")]
    return "\n".join(w)


# ═══════════════════════════════════════════════════════════════════════════
# reporting
# ═══════════════════════════════════════════════════════════════════════════

def _mib(kib: int) -> str:
    return f"{kib / 1024:.1f}"


def report(res: dict) -> str:
    pts = res["points"]
    light = "census" not in pts[0]
    w = []
    w.append(f"{'point':<24}{'RSS MiB':>10}{'HWM MiB':>10}"
             f"{'open objs':>12}{'window':>10}{'memo':>10}")
    for p in pts:
        o = p["owners"]
        w.append(f"{p['label']:<24}{_mib(p['rss']['VmRSS']):>10}"
                 f"{_mib(p['rss']['VmHWM']):>10}"
                 f"{o['open_objects']['count']:>12}"
                 f"{o['window_buffer']['count']:>10}"
                 f"{o['rank_memo']['entries']:>10}")
    if light:
        return "\n".join(w)
    w.append("")
    names = ["open_objects", "window_buffer", "processed_ids", "buffered_ids",
             "archive_slice_hash", "tenant_edges", "window_index_cache",
             "grounding_interns", "signal_interns", "catalog", "rank_memo",
             "clause_kinds_cache"]
    w.append("DEEP BYTES, EXCLUSIVE (each object charged once, working set walked first)")
    w.append(f"{'owner':<24}" + "".join(f"{p['label'][:14]:>18}" for p in pts))
    for n in names:
        row = f"{n:<24}"
        for p in pts:
            b = p["owners"][n].get("deep_bytes_exclusive", 0)
            row += f"{b / 1048576:>17.2f}M"
        w.append(row)
    row = f"{'signal_id_cache (uuid)':<24}"
    for p in pts:
        row += f"{p['owners']['signal_id_cache']['uuid_bytes'] / 1048576:>17.2f}M"
    w.append(row)
    w.append("")
    w.append("LIVE OBJECT CENSUS (count / shallow MiB)")
    w.append(f"{'type':<20}" + "".join(f"{p['label'][:16]:>20}" for p in pts))
    for t in CENSUS_TYPES:
        if all(p["census"][t]["count"] == 0 for p in pts):
            continue
        row = f"{t:<20}"
        for p in pts:
            c = p["census"][t]
            row += f"{c['count']:>11} /{c['bytes'] / 1048576:>7.1f}"
        w.append(row)
    return "\n".join(w)


def tm_report(res: dict, top: int = 20) -> str:
    pts = [p for p in res["points"] if "_tm" in p]
    if len(pts) < 3:
        return ""
    by_label = {p["label"]: p for p in pts}
    out = []
    for a, b in (("input_stopped", "drained"),
                 ("drained", "memo_cleared"),
                 ("drained", "working_set_dropped")):
        if a not in by_label or b not in by_label:
            continue
        out.append(f"\ntracemalloc delta {a} -> {b} (top {top} by line)")
        diff = by_label[b]["_tm"].compare_to(by_label[a]["_tm"], "lineno")
        for st in diff[:top]:
            out.append(f"  {st.size_diff / 1048576:+8.2f}M  "
                       f"{st.count_diff:+8d} blocks  {st.traceback[0]}")
        out.append(f"\ntracemalloc delta {a} -> {b} (by file)")
        diff = by_label[b]["_tm"].compare_to(by_label[a]["_tm"], "filename")
        for st in diff[:12]:
            out.append(f"  {st.size_diff / 1048576:+8.2f}M  "
                       f"{st.count_diff:+8d} blocks  {st.traceback[0]}")
    return "\n".join(out)


def main_cli() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--devices", type=int, default=400)
    ap.add_argument("--signals", type=int, default=4000,
                    help="signals loaded before each ARRIVAL epoch")
    ap.add_argument("--arrival-epochs", type=int, default=3)
    ap.add_argument("--cohorts", type=int, default=8,
                    help="cohorts drained per epoch (an epoch stops early once "
                         "pending is empty)")
    ap.add_argument("--cohort-size", type=int, default=1000)
    ap.add_argument("--max-drain-epochs", type=int, default=8)
    ap.add_argument("--span-s", type=float, default=300.0)
    ap.add_argument("--burst", type=int, default=6)
    ap.add_argument("--storm", dest="storm", action="store_true", default=True)
    ap.add_argument("--no-storm", dest="storm", action="store_false")
    ap.add_argument("--tracemalloc", action="store_true")
    ap.add_argument("--light", action="store_true",
                    help="RSS + counts only: no deep walk, no census. THE RSS "
                         "CURVE MUST COME FROM A LIGHT RUN (see measure())")
    ap.add_argument("--tm-frames", type=int, default=1)
    ap.add_argument("--calibrate", action="store_true",
                    help="measure estimate_result_bytes against a tracemalloc "
                         "marginal over --calib-results REAL results, and exit")
    ap.add_argument("--calib-results", type=int, default=400,
                    help="how many rank-key-distinct results to calibrate over "
                         "(the brief's floor is 200)")
    ap.add_argument("--label", default="run")
    ap.add_argument("--log-level", default="ERROR")
    ap.add_argument("--json", default="")
    args = ap.parse_args()

    logging.getLogger("correlation").setLevel(getattr(logging, args.log_level))
    logging.getLogger().setLevel(getattr(logging, args.log_level))

    main.CORR_ENGINE_COHORT_SIZE = args.cohort_size
    main.CORR_STORM_COHORT_SIZE = args.cohort_size
    main.CORR_ENGINE_DRAIN_COHORTS = args.cohorts
    main.CORR_LIFECYCLE_EPOCH_CADENCE = True
    main.OPEN_OBJECTS = {}
    main.VERSIONS_PERSISTED = 0
    main.VERSIONS_DAMPED = 0
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_IDS.clear()
    main._BUFFERED_ID_ORDER.clear()
    main._PROCESSED_IDS.clear()
    main.TENANT_WATERMARK.clear()
    main._TENANT_EDGES.clear()
    main._ARCHIVE_SLICE_HASH.clear()

    flags = {
        "CORR_RANK_MEMO": main.CORR_RANK_MEMO,
        "CORR_RANK_MEMO_MAX": main.CORR_RANK_MEMO_MAX,
        "CORR_COHORT_TOUCH_GATE": main.CORR_COHORT_TOUCH_GATE,
        "CORR_BLOB_CYCLE_CACHE": engine.CORR_BLOB_CYCLE_CACHE,
        "CORR_CLAUSE_KINDS_CACHE": catalog_mod.CORR_CLAUSE_KINDS_CACHE,
        "CORR_SIGNAL_ID_CACHE": signals_mod.CORR_SIGNAL_ID_CACHE,
        "CORR_OPEN_OBJECTS_MAX": main.CORR_OPEN_OBJECTS_MAX,
    }
    print(f"label={args.label}  flags={json.dumps(flags)}", file=sys.stderr)

    if args.calibrate:
        print(f"label={args.label}  CALIBRATE", file=sys.stderr)
        res = calibrate(args)
        print()
        print(calib_report(res))
        if args.json:
            with open(args.json, "w") as fh:
                json.dump(res, fh, indent=2, default=str)
            print(f"\nwrote {args.json}")
        return 0

    if args.tracemalloc:
        tracemalloc.start(args.tm_frames)
    t0 = time.perf_counter()
    res = asyncio.run(sweep(args))
    res["total_wall_s"] = round(time.perf_counter() - t0, 2)
    res["config"] = vars(args) | {"flags": flags,
                                  "python": sys.version.split()[0],
                                  "cpu_count": os.cpu_count()}
    print(f"\nlabel={args.label}  wall={res['total_wall_s']}s  "
          f"flags={json.dumps(flags)}\n")
    print(report(res))
    if args.tracemalloc:
        print(tm_report(res))
    if args.json:
        for p in res["points"]:
            p.pop("_tm", None)
        with open(args.json, "w") as fh:
            json.dump(res, fh, indent=2, default=str)
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main_cli())
