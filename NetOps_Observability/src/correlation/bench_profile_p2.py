#!/usr/bin/env python3
"""P2 brief — per-stage, per-cohort cost breakdown of ONE drain sweep, OFFLINE.

WHAT THIS IS FOR
    `docs/scale/P1_2P5K_VERDICT_2026-08-28.md` §4 says the remaining 2.5K cost is
    "engine compute, GIL-bound Python", 20 cohorts x ~190 s per epoch, with 61 %
    of the epoch's component evaluations ranked despite being untouched (the memo
    is intra-epoch). It does NOT say WHICH stage of a cohort burns the 190 s.
    This script answers that, so the Decision/Evidence plane split (P2) is
    designed against measured shares instead of intuition.

WHAT IT RUNS
    The REAL drain sweep — `main._begin_epoch` -> N x `main.engine_cycle(epoch)`
    -> `main._epoch_lifecycle` -> `main._close_epoch` — i.e. the same code path
    `engine_loop` runs, over a 2,500-device-SHAPED synthetic signal stream built
    by the REAL syslog producer (`producers.syslog_control_signal`) from the
    scale harness's ratified `EVENT_MIX_REALISTIC` weights
    (`scripts/scale-miniladder.py`). Nothing in engine.py / main.py is modified:
    every measurement is a wrapper installed around a public callable for the
    duration of the run, and every wrapper is removed at the end.

    PERSISTENCE IS MOCKED. `main.ch` is a stub that counts rows and serialized
    bytes per table instead of talking to ClickHouse. Row BUILDING (to_object_row,
    hypotheses_blob, the edge/evidence row pages, the archive slice) is real and
    measured — that is CPU the engine pays whether or not the insert lands. The
    stub's byte accounting is timed separately and excluded from every share.

HOW TIME IS ATTRIBUTED
    A thread-local span stack records INCLUSIVE and EXCLUSIVE (self) time per
    stage, so a stage nested inside another (rank inside run_window) is never
    double-counted. Spans are installed on the engine's own functions, so the
    exclusive column sums to the sweep's CPU wall minus glue.

    Everything runs on the asyncio default executor exactly as in production
    (`_offload` / `_snap_call`), one awaited call at a time — no two spans are
    ever open concurrently on different threads, which is what makes the
    exclusive arithmetic sound.

RUN
    cd src/correlation && python3 bench_profile_p2.py            # calibrated default
    python3 bench_profile_p2.py --devices 2500 --signals 35000   # live shape (SLOW)
    python3 bench_profile_p2.py --json /tmp/p2.json --cprofile
"""

from __future__ import annotations

import argparse
import asyncio
import cProfile
import hashlib
import io
import json
import os
import pstats
import statistics
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone

# main.py is imported for its REAL cycle/persist path; it must not think it has
# a broker or a ClickHouse. Set before import — these are read at import time.
os.environ.setdefault("CORR_SIGNALS_ENABLED", "true")
os.environ.setdefault("CORR_ENGINE_ENABLED", "true")

import logging

import engine
import main
import producers
from engine import ObjectSnapshot

# ── the ratified realistic syslog mix (scripts/scale-miniladder.py) ───────────
# (weight, appname, message template, syslog severity) -> engine kind.
EVENT_MIX_REALISTIC = (
    (46, "LINK-3-UPDOWN",
     "%LINK-3-UPDOWN: Interface GigabitEthernet0/{if_n}, changed state to {state}",
     "err"),                                                    # link_state_change
    (18, "BGP-5-ADJCHANGE",
     "%BGP-5-ADJCHANGE: neighbor 10.{oct2}.{oct3}.1 {State} Interface flap",
     "notice"),                                                 # bgp_adjacency_change
    (12, "OSPF-5-ADJCHG",
     ("%OSPF-5-ADJCHG: Process 1, Nbr 10.{oct2}.{oct3}.2 on GigabitEthernet0/{if_n} "
     "from FULL to {STATE}"), "notice"),                         # ospf_adjacency_change
    (9, "LLDP-5-NEIGHBOR",
     "%LLDP-5-NEIGHBOR: neighbor {verb} on interface GigabitEthernet0/{if_n}",
     "notice"),                                                 # lldp_neighbor_change
    (8, "SPANTREE-6-INTERFACE",
     "%SPANTREE-6-INTERFACE: GigabitEthernet0/{if_n} moved to {stp_state}",
     "info"),                                                   # stp_topology_change
    (7, "ENVMON-4-FAN_FAILED",
     "%ENVMON-4-FAN_FAILED: Fan {if_n} failed", "warning"),     # device_alarm
)


def _mix_table():
    table = []
    for weight, app, tpl, sev in EVENT_MIX_REALISTIC:
        table.extend([(app, tpl, sev)] * weight)
    return tuple(table)


MIX = _mix_table()


# ═══════════════════════════════════════════════════════════════════════════
# span profiler — inclusive + exclusive, thread-local stack
# ═══════════════════════════════════════════════════════════════════════════

class Prof:
    def __init__(self) -> None:
        self._tl = threading.local()
        self._lock = threading.Lock()
        # name -> [calls, inclusive_s, exclusive_s]
        self.data: dict[str, list] = {}
        self.enabled = True
        self._epoch_marks: list[dict] = []

    def _stack(self) -> list:
        st = getattr(self._tl, "st", None)
        if st is None:
            st = self._tl.st = []
        return st

    def record(self, name: str, incl: float, excl: float) -> None:
        with self._lock:
            row = self.data.get(name)
            if row is None:
                self.data[name] = [1, incl, excl]
            else:
                row[0] += 1
                row[1] += incl
                row[2] += excl

    def span(self, name: str):
        return _Span(self, name)

    def wrap(self, name: str, fn):
        prof = self

        def wrapped(*a, **kw):
            if not prof.enabled:
                return fn(*a, **kw)
            with _Span(prof, name):
                return fn(*a, **kw)
        wrapped.__name__ = getattr(fn, "__name__", name)
        wrapped.__wrapped__ = fn
        return wrapped

    def wrap_async(self, name: str, fn):
        prof = self

        async def wrapped(*a, **kw):
            if not prof.enabled:
                return await fn(*a, **kw)
            t0 = time.perf_counter()
            try:
                return await fn(*a, **kw)
            finally:
                el = time.perf_counter() - t0
                prof.record(name, el, 0.0)   # coroutine: inclusive only
        wrapped.__name__ = getattr(fn, "__name__", name)
        wrapped.__wrapped__ = fn
        return wrapped

    def snapshot(self) -> dict:
        with self._lock:
            return {k: list(v) for k, v in self.data.items()}


class _Span:
    __slots__ = ("_child", "_n", "_p", "_t0")

    def __init__(self, prof: Prof, name: str) -> None:
        self._p = prof
        self._n = name
        self._t0 = 0.0
        self._child = 0.0

    def __enter__(self):
        self._t0 = time.perf_counter()
        self._child = 0.0
        self._p._stack().append(self)
        return self

    def __exit__(self, *exc):
        el = time.perf_counter() - self._t0
        st = self._p._stack()
        st.pop()
        if st:
            st[-1]._child += el
        self._p.record(self._n, el, el - self._child)
        return False


PROF = Prof()


# ═══════════════════════════════════════════════════════════════════════════
# mocked persistence — counts rows + serialized bytes, inserts nothing
# ═══════════════════════════════════════════════════════════════════════════

class MockCH:
    """`main.ch` stand-in. Counts rows and serialized bytes per table.

    The json.dumps that measures bytes is CPU this profile INVENTED, so it runs
    inside its own span (`MOCK.byte_accounting`) and is subtracted from every
    share reported. The real sink serializes too, of course — but over HTTP, on
    a different cost curve, and the measured live number (17.5 % of persist wall
    across all corr_* inserts) is already known from the A/B."""

    def __init__(self, insert_sleep_s: float = 0.0) -> None:
        self.rows: dict[str, int] = defaultdict(int)
        self.bytes: dict[str, int] = defaultdict(int)
        self.calls: dict[str, int] = defaultdict(int)
        # P2 step 4: the mocked sink can be given the LIVE per-insert latency
        # (--insert-sleep-ms; the 2.5K run measured 149,590 inserts / 1,840 s,
        # i.e. ~7 ms p50 sequential). Without it this bench measures Python CPU
        # only, and the whole Decision/Evidence question — who WAITS behind
        # whom on an awaited insert — is invisible.
        self.insert_sleep_s = max(0.0, insert_sleep_s)

    async def insert(self, table, rows, **kw):
        rows = list(rows)
        self.calls[table] += 1
        self.rows[table] += len(rows)
        with _Span(PROF, "MOCK.byte_accounting"):
            n = 0
            for r in rows:
                n += len(json.dumps(r, default=str))
            self.bytes[table] += n
        if self.insert_sleep_s:
            # Outside the byte-accounting span on purpose: this is modelled I/O
            # WAIT, not invented CPU, and it must land in the cohort wall.
            await asyncio.sleep(self.insert_sleep_s)
        return True


# ═══════════════════════════════════════════════════════════════════════════
# fixture — a 2,500-device-SHAPED signal stream through the REAL producer
# ═══════════════════════════════════════════════════════════════════════════

def make_signals(n: int, devices: int, *, t_end: datetime, span_s: float,
                 seq0: int = 0, tenant: str = "global", burst: int = 6) -> list:
    """`n` promoted control-plane signals over `devices` devices.

    Device pick and mix pick are DECORRELATED exactly as the harness does it
    (`_syslog_event`'s mix_seq): `seq % devices` and `seq % len(MIX)` share
    factors, so a shared counter would starve fixed devices of whole kinds.
    Timestamps are spread evenly over `span_s` ending at `t_end`, deterministic,
    no RNG — two runs of the same parameters are byte-comparable.

    `burst` is the ONE deliberate departure from the harness's uniform
    round-robin (`device = seq % n_devices`): a device emits `burst` CONSECUTIVE
    events before the stream moves on. Real syslog is bursty per device (a link
    flap is a cluster, not one line), and — the reason it matters here — the
    round-robin stream makes every cohort touch every component, which would
    pin the cohort-touch gate's hit rate at 0 and profile a shape the live run
    does not have. The live 2.5K epoch touched 178 components per 1,000-signal
    cohort (5.6 signals per touched component), which `burst=6` reproduces."""
    out = []
    step = span_s / max(1, n)
    burst = max(1, burst)
    for i in range(n):
        seq = seq0 + i
        dev = f"dev{(seq // burst) % devices:05d}"
        app, tpl, sev = MIX[(seq * 7) % len(MIX)]
        if_n = (seq // (burst * devices)) % 48
        msg = tpl.format(if_n=if_n, state="down" if seq % 2 == 0 else "up",
                         State="Down" if seq % 2 == 0 else "Up",
                         STATE="DOWN" if seq % 2 == 0 else "UP",
                         oct2=(seq // 251) % 251, oct3=seq % 251,
                         verb="added" if seq % 2 else "removed",
                         stp_state="forwarding" if seq % 2 else "blocking")
        ts = t_end - timedelta(seconds=span_s - i * step)
        ev = {"hostname": dev, "appname": app, "message": msg, "severity": sev,
              "timestamp": ts.isoformat()}
        sig = producers.syslog_control_signal(ev, tenant, ts)
        if sig is not None:
            out.append(sig)
    return out


def load(signals) -> None:
    for s in signals:
        sid = str(s.signal_id)
        if sid in main._BUFFERED_IDS:
            continue
        main.WINDOW_BUFFER.append(s)
        main._BUFFERED_ID_ORDER.append(sid)
        main._BUFFERED_IDS.add(sid)
        main._advance_watermark(s, 0.0)


# ═══════════════════════════════════════════════════════════════════════════
# instrumentation install / remove
# ═══════════════════════════════════════════════════════════════════════════

_ORIG: list[tuple] = []


def _patch(obj, attr, name, *, is_async=False):
    fn = getattr(obj, attr)
    _ORIG.append((obj, attr, fn))
    setattr(obj, attr, (PROF.wrap_async if is_async else PROF.wrap)(name, fn))


def install() -> None:
    # ── stage 1: window preparation (once per epoch, hoisted by tracker 166) ──
    _patch(main, "prepare_run_window", "1.prepare_run_window")
    # ── stage 2: candidate generation + edge admission ───────────────────────
    _patch(engine, "build_edges", "2.build_edges")
    # ── stage 3: component formation ─────────────────────────────────────────
    _patch(engine, "_components", "3.components")
    _patch(engine, "_fold_seam_bridged_components", "3.components_seam_fold")
    # ── stage 4: ranking / verdict ───────────────────────────────────────────
    _patch(engine, "rank", "4.rank(scoring)")
    _patch(engine, "_break_ties_by_seam_affinity", "4.rank_tiebreak")
    _patch(engine, "_cap_verdict", "4.verdict_cap")
    _patch(engine, "worst_data_class", "4.worst_data_class")
    # ── stage 5: snapshot materialization ────────────────────────────────────
    _patch(engine, "_identities_for", "5.materialize_identities")
    _patch(engine, "_storm_dedup_comp", "5.materialize_storm_dedup")
    # ── stage 6: digests ─────────────────────────────────────────────────────
    _patch(ObjectSnapshot, "content_hash", "6.content_hash")
    _patch(ObjectSnapshot, "material_hash", "6.material_hash")
    _patch(ObjectSnapshot, "hypotheses_blob", "6.hypotheses_blob")
    # ── stage 7: persist row building ────────────────────────────────────────
    _patch(ObjectSnapshot, "to_object_row", "7.to_object_row")
    _patch(ObjectSnapshot, "edge_row_page", "7.edge_row_page")
    _patch(ObjectSnapshot, "evidence_row_page", "7.evidence_row_page")
    _patch(ObjectSnapshot, "evidence_row_count", "7.evidence_row_count")
    _patch(main, "_archive_slice", "7.archive_slice")
    _patch(main, "_archive_row", "7.archive_row")
    _patch(main, "_current_badges", "7.current_badges")
    # ── stage 8: reconciliation (main.py, per snapshot) ──────────────────────
    _patch(main, "find_continuation", "8.find_continuation")
    # ── stage 9: lifecycle ───────────────────────────────────────────────────
    _patch(main, "find_merges", "9.find_merges")
    # ── coroutine-level phases (inclusive only) ──────────────────────────────
    _patch(main, "run_window", "P.run_window(total)")
    _patch(main, "_persist_snapshot", "P.persist(total)", is_async=True)
    _patch(main, "_engine_cycle_inner", "P.cohort(total)", is_async=True)
    _patch(main, "_epoch_lifecycle", "P.epoch_lifecycle(total)", is_async=True)
    _patch(main, "ch_insert", "P.ch_insert(total)", is_async=True)


def remove() -> None:
    for obj, attr, fn in reversed(_ORIG):
        setattr(obj, attr, fn)
    _ORIG.clear()


# ═══════════════════════════════════════════════════════════════════════════
# the sweep
# ═══════════════════════════════════════════════════════════════════════════

def _decision_key(snap) -> str:
    """The P2 design's content-addressed DecisionKey
    (`docs/design/DECISION_EVIDENCE_SPLIT_P2_2026-08-28.md` §3), computed from a
    materialized snapshot: node keys + their signal ids, plus the carried-edge
    identities. Catalog/topology/engine/policy versions and the storm/stale flags
    are per-epoch constants in this bench and are folded in via engine_ver /
    topology_version so a version move would still separate two keys.

    NOTE: the design computes it from `comp` (the pre-dedup component); a
    storm-declared snapshot stores the DEDUPED node signal list, so this reads
    the deduped ids. Both are pure functions of the same evidence — the
    comparison across epochs is apples-to-apples either way."""
    parts = [f"{n.key}:{','.join(sorted(str(s.signal_id) for s in n.signals))}"
             for n in snap.nodes]
    edges = [f"{e.from_node}>{e.to_node}|{e.grounding.kind}|{e.grounding.ref}"
             for e in snap.edges]
    blob = "\n".join(sorted(parts) + sorted(edges) +
                      [snap.engine_ver, snap.topology_version,
                       str(snap.storm_mode), str(snap.topology_stale)])
    return hashlib.sha256(blob.encode()).hexdigest()


def _rank_key(snap) -> str:
    """A COARSER key than §3's DecisionKey: the projection of the component's
    evidence that `scoring.rank` can actually see — (node, kind, severity,
    entity) as a SET, plus the catalog version. It is deliberately the same
    projection `material_hash` already uses for its "evidence" field.

    Why it matters: rank is the single most expensive stage, and a component
    that gains a new INSTANCE of evidence it already had (the sustained-incident
    case that #100 damping exists for) keeps this key while its DecisionKey —
    which hashes signal IDs — moves. The run records every (rank_key ->
    ranking digest) pair it produces and reports COLLISIONS, so the claim "this
    key is sufficient for rank" is measured on this workload, never assumed."""
    ev = sorted({f"{n.key}|{s.kind}|{s.severity.value}|{s.entity_type.value}|"
                 f"{s.entity_id}|{s.deviation}" for n in snap.nodes for s in n.signals})
    return hashlib.sha256(("\n".join(ev) + "|" +
                           snap.ranking.catalog_version).encode()).hexdigest()


def _ranking_digest(snap) -> str:
    return hashlib.sha256(
        json.dumps(snap.ranking.to_dict(), sort_keys=True,
                   default=str).encode()).hexdigest()


RANK_KEY_MAP: dict[str, set] = {}


def _memo_keys(epoch) -> dict:
    """{node-key-set: (material_hash, content_hash, cid, nodes, edges,
    decision_key)} for every component this epoch MATERIALIZED (the memo is
    written only on a miss, i.e. on a real rank+materialize), across tenants.
    Digests are instance-cached, so reading them here does not re-pay the hash."""
    out = {}
    for memo in epoch.memos.values():
        for key, snap in memo._by_key.items():
            rk = _rank_key(snap)
            RANK_KEY_MAP.setdefault(rk, set()).add(_ranking_digest(snap))
            out[key] = (snap.material_hash(), snap.content_hash(),
                        snap.correlation_id, len(snap.nodes), len(snap.edges),
                        _decision_key(snap), rk)
    return out


async def sweep(args) -> dict:
    now = datetime(2026, 8, 28, 12, 0, 0, tzinfo=timezone.utc)
    per_epoch: list[dict] = []
    memo_by_epoch: list[dict] = []
    ch = MockCH(args.insert_sleep_ms / 1000.0)
    main.ch = ch

    base = make_signals(args.signals, args.devices, t_end=now, span_s=args.span_s,
                        burst=args.burst)
    load(base)
    seq = args.signals

    for e in range(args.epochs):
        if e > 0 and args.arrivals:
            # Live epochs are not fed a frozen buffer: the burst keeps arriving.
            # Continuing the same stream re-touches the SAME devices with LATER
            # timestamps, which is what makes the cross-epoch question non-trivial
            # (same node-key set, different content).
            # ...but only onto a SUBSET of the estate: the incidents that are
            # still evolving. The rest of the fleet goes quiet, which is the
            # population whose components a later epoch could reuse. This share
            # is a FIXTURE PARAMETER, not a measurement — see the report.
            n_dev = max(1, int(args.devices * args.arrival_device_share))
            extra = make_signals(args.arrivals, n_dev,
                                 t_end=now + timedelta(seconds=30 * (e + 1)),
                                 span_s=args.span_s, seq0=seq, burst=args.burst)
            load(extra)
            seq += args.arrivals
        t_epoch = time.perf_counter()
        # P2 step 2: the LEVEL-1 rank memo is process-lifetime, so its counters
        # are read as per-epoch DELTAS (the level-2 ComponentMemo's are already
        # per-epoch by construction).
        rm_before = dict(main.rank_memo_stats())
        t0 = time.perf_counter()
        epoch = await main._begin_epoch(now + timedelta(seconds=60 * e))
        prep_s = time.perf_counter() - t0
        if args.storm:
            epoch.storm = True          # the live 2.5K leg ran storm-declared
        cohorts = []
        keys_prev = 0
        pend0 = len(epoch.pending())
        for k in range(args.cohorts):
            snap_before = (main.VERSIONS_PERSISTED, main.VERSIONS_DAMPED,
                           sum(ch.rows.values()))
            memo = epoch.memos.get("global")
            mb = ((memo.components, memo.touched, memo.hits, memo.misses)
                  if memo else (0, 0, 0, 0))
            d_before = engine.digest_cache_stats()
            t0 = time.perf_counter()
            await main.engine_cycle(epoch)
            # P2 step 4: the cohort returns when its DECISION rows are all
            # written; the Evidence rows may still be queued. Both numbers are
            # reported — decision wall is the operator's TTUR term, evidence
            # wall is the T7 term. With CORR_EVIDENCE_ASYNC=0 they are equal by
            # construction (the Evidence write is inline), which is what makes
            # the A/B readable.
            decision_s = time.perf_counter() - t0
            ev_depth = main.evidence_stats()["depth"]
            await main.evidence_drain(600.0)
            wall = time.perf_counter() - t0
            epoch.cohorts = k + 1
            memo = epoch.memos.get("global")
            ma = ((memo.components, memo.touched, memo.hits, memo.misses)
                  if memo else (0, 0, 0, 0))
            # Component IDENTITY churn inside the epoch. The memo is keyed on the
            # node-key SET, and it only ever grows within an epoch — so the number
            # of NEW keys after a cohort is the number of components whose identity
            # this cohort changed (a merge, a first sighting, a split). This is the
            # mechanism behind a low intra-epoch hit rate: a component whose key
            # moved cannot be served from the memo even though nothing touched it.
            keys_now = len(memo._by_key) if memo else 0
            d_after = engine.digest_cache_stats()
            cohorts.append({
                "cohort": k + 1,
                "wall_s": round(wall, 3),
                "decision_s": round(decision_s, 3),
                "evidence_s": round(wall - decision_s, 3),
                "evidence_queued_at_decision": ev_depth,
                "pending_before": pend0,
                "components": ma[0] - mb[0],
                "touched": ma[1] - mb[1],
                "memo_hits": ma[2] - mb[2],
                "ranked": ma[3] - mb[3],
                "versions_persisted": main.VERSIONS_PERSISTED - snap_before[0],
                "versions_damped": main.VERSIONS_DAMPED - snap_before[1],
                "rows": sum(ch.rows.values()) - snap_before[2],
                "memo_keys": keys_now,
                "new_memo_keys": keys_now - keys_prev,
                "digest": {k2: d_after[k2] - d_before[k2] for k2 in d_after},
            })
            keys_prev = keys_now
            print(f"  epoch {e + 1} cohort {k + 1}/{args.cohorts}: "
                  f"decision={decision_s:.2f}s evidence=+{wall - decision_s:.2f}s "
                  f"queued={ev_depth} total={wall:.2f}s "
                  f"components={ma[0] - mb[0]} touched={ma[1] - mb[1]} "
                  f"hits={ma[2] - mb[2]} ranked={ma[3] - mb[3]} keys={keys_now}",
                  file=sys.stderr, flush=True)
            pend0 = len(epoch.pending())
            if not pend0:
                break
        memo_by_epoch.append(_memo_keys(epoch))
        t0 = time.perf_counter()
        await main._epoch_lifecycle(epoch, main._make_loop_yield()[0])
        life_s = time.perf_counter() - t0
        memo = epoch.memos.get("global")
        rm_after = main.rank_memo_stats()
        rm_d = {k: rm_after[k] - rm_before.get(k, 0)
                for k in ("hits", "misses", "evicted", "unkeyable")}
        rm_lookups = rm_d["hits"] + rm_d["misses"]
        per_epoch.append({
            "epoch": e + 1,
            # ── level-1 (rank) memo, this epoch ─────────────────────────────
            "rank_memo_hits": rm_d["hits"],
            "rank_memo_misses": rm_d["misses"],
            "rank_memo_evicted": rm_d["evicted"],
            "rank_memo_unkeyable": rm_d["unkeyable"],
            "rank_memo_entries": rm_after["entries"],
            "rank_memo_hit_share": round(rm_d["hits"] / max(1, rm_lookups), 4),
            "prep_s": round(prep_s, 3),
            "lifecycle_s": round(life_s, 3),
            "epoch_wall_s": round(time.perf_counter() - t_epoch, 3),
            "cohorts_drained": len(cohorts),
            "window_signals": len(main.WINDOW_BUFFER),
            "nodes": sum(len(p.nodes) for p in epoch.preps.values() if p),
            "components_total": memo.components if memo else 0,
            "touched_total": memo.touched if memo else 0,
            "memo_hits_total": memo.hits if memo else 0,
            "ranked_total": memo.misses if memo else 0,
            "open_objects": len(main.OPEN_OBJECTS),
            "cohorts": cohorts,
        })
        main._close_epoch(epoch)

    # ── cross-epoch reuse: identical node-key set, ranked in BOTH epochs ──────
    reuse = {}
    if len(memo_by_epoch) >= 2:
        a, b = memo_by_epoch[0], memo_by_epoch[1]
        shared = set(a) & set(b)
        same_mat = sum(1 for k in shared if a[k][0] == b[k][0])
        same_cont = sum(1 for k in shared if a[k][1] == b[k][1])
        same_cid = sum(1 for k in shared if a[k][2] == b[k][2])
        same_dkey = sum(1 for k in shared if a[k][5] == b[k][5])
        dkey_a = {v[5] for v in a.values()}
        dkey_hits = sum(1 for v in b.values() if v[5] in dkey_a)
        rkey_a = {v[6] for v in a.values()}
        rkey_hits = sum(1 for v in b.values() if v[6] in rkey_a)
        same_rkey = sum(1 for k in shared if a[k][6] == b[k][6])
        collisions = sum(1 for v in RANK_KEY_MAP.values() if len(v) > 1)
        reuse = {
            "epoch1_materialized_components": len(a),
            "epoch2_materialized_components": len(b),
            "identical_node_key_set": len(shared),
            "identical_key_share_of_epoch2": round(len(shared) / max(1, len(b)), 4),
            "of_those_identical_material_hash": same_mat,
            "of_those_identical_content_hash": same_cont,
            "of_those_identical_correlation_id": same_cid,
            "material_hash_stable_share": round(same_mat / max(1, len(shared)), 4),
            # The P2 §3 memo's ACTUAL hit predicate, and the gap to an
            # outcome-keyed memo: a component can keep its material identity
            # (same verdict, same object) while its DecisionKey moves, because a
            # new signal id landed on one of its nodes.
            "of_those_identical_decision_key": same_dkey,
            "decision_key_hits_epoch2_any": dkey_hits,
            "decision_key_hit_share_of_epoch2": round(dkey_hits / max(1, len(b)), 4),
            # The coarser rank-only key (see _rank_key): what a memo that skips
            # rank() but still rebuilds the snapshot could serve.
            "of_those_identical_rank_key": same_rkey,
            "rank_key_hits_epoch2_any": rkey_hits,
            "rank_key_hit_share_of_epoch2": round(rkey_hits / max(1, len(b)), 4),
            "rank_keys_distinct": len(RANK_KEY_MAP),
            "rank_key_collisions_two_rankings": collisions,
        }

    return {
        "epochs": per_epoch,
        "cross_epoch_reuse": reuse,
        "persistence": {
            "rows": dict(ch.rows), "bytes": dict(ch.bytes),
            "insert_calls": dict(ch.calls),
            "versions_persisted": main.VERSIONS_PERSISTED,
            "versions_damped": main.VERSIONS_DAMPED,
        },
    }


# ═══════════════════════════════════════════════════════════════════════════
# reporting
# ═══════════════════════════════════════════════════════════════════════════

STAGE_LABEL = {
    "1.prepare_run_window": "prepare_run_window (epoch prologue)",
    "2.build_edges": "build_edges / candidates",
    "3.components": "components (union-find)",
    "3.components_seam_fold": "components (seam fold)",
    "4.rank(scoring)": "rank / score_template / verdicts.assess",
    "4.rank_tiebreak": "rank tie-break (seam affinity)",
    "4.verdict_cap": "verdict cap (contract gates)",
    "4.worst_data_class": "data-class gate",
    "5.materialize_identities": "snapshot materialization (app identity)",
    "5.materialize_storm_dedup": "snapshot materialization (storm dedup)",
    "6.content_hash": "content_hash",
    "6.material_hash": "material_hash",
    "6.hypotheses_blob": "hypotheses_blob",
    "7.to_object_row": "to_object_row",
    "7.edge_row_page": "edge row pages",
    "7.evidence_row_page": "evidence row pages",
    "7.evidence_row_count": "evidence row count",
    "7.archive_slice": "archive slice select",
    "7.archive_row": "archive row build",
    "7.current_badges": "corr_current badges",
    "8.find_continuation": "reconciliation: find_continuation",
    "9.find_merges": "lifecycle: find_merges",
    "P.run_window(total)": "run_window body (residual: comp/edge assembly, cid, "
                           "orientations, ObjectSnapshot ctor)",
}


def report(res: dict, prof: dict, args, total_wall: float) -> str:
    mock = prof.get("MOCK.byte_accounting", [0, 0.0, 0.0])[2]
    net = total_wall - mock
    rows = []
    for name, (calls, incl, excl) in sorted(prof.items(), key=lambda kv: -kv[1][2]):
        if name.startswith("MOCK"):
            continue
        if name.startswith("P.") and name != "P.run_window(total)":
            continue
        rows.append((STAGE_LABEL.get(name, name), calls, incl, excl,
                     100.0 * excl / net if net else 0.0))
    accounted = sum(r[3] for r in rows)
    out = io.StringIO()
    w = out.write
    w(f"total sweep wall (s)           : {total_wall:.2f}\n")
    w(f"byte-accounting overhead (s)   : {mock:.2f} (excluded)\n")
    w(f"net measured wall (s)          : {net:.2f}\n")
    w(f"attributed to stages (s)       : {accounted:.2f} "
      f"({100.0 * accounted / net:.1f} %)\n\n")
    w(f"{'stage':<46}{'calls':>10}{'incl s':>10}{'excl s':>10}{'% net':>8}\n")
    w("-" * 84 + "\n")
    for label, calls, incl, excl, pct in rows:
        w(f"{label:<46}{calls:>10}{incl:>10.2f}{excl:>10.2f}{pct:>8.2f}\n")
    w("-" * 84 + "\n")
    w(f"{'UNATTRIBUTED (loop, glue, asyncio)':<46}{'':>10}{'':>10}"
      f"{net - accounted:>10.2f}{100.0 * (net - accounted) / net:>8.2f}\n\n")
    for name in ("P.cohort(total)", "P.run_window(total)", "P.persist(total)",
                 "P.epoch_lifecycle(total)", "P.ch_insert(total)"):
        if name in prof:
            c, incl, _ = prof[name]
            w(f"phase {name:<34}{c:>10}{incl:>10.2f}"
              f"{'':>10}{100.0 * incl / net:>8.2f}\n")
    w(_persistence_table(res))
    return out.getvalue()


# P2 step 4c: INSERT CALLS per table is the number ClickHouse actually feels —
# every statement is a level-0 part, and the measured 241x merge write
# amplification is a function of how many of them arrive, not of how many rows
# they carry. Rows and BYTES sit beside it because they are what must NOT move
# between an A/B's legs: same rows, same bytes, fewer calls.
def _persistence_table(res: dict) -> str:
    pers = res.get("persistence", {})
    rows, byts, calls = (pers.get("rows", {}), pers.get("bytes", {}),
                         pers.get("insert_calls", {}))
    if not calls:
        return ""
    out = io.StringIO()
    w = out.write
    w(f"\n{'table':<34}{'rows':>10}{'bytes':>12}{'inserts':>10}"
      f"{'rows/ins':>10}{'B/ins':>10}\n")
    w("-" * 86 + "\n")
    for table in sorted(calls):
        n = calls[table]
        r, b = rows.get(table, 0), byts.get(table, 0)
        w(f"{table:<34}{r:>10}{b:>12}{n:>10}{r / max(1, n):>10.1f}"
          f"{b / max(1, n):>10.0f}\n")
    w("-" * 86 + "\n")
    w(f"{'TOTAL insert calls':<34}{'':>10}{'':>12}{sum(calls.values()):>10}\n")
    ev = sum(n for t, n in calls.items()
             if t in ("netops.corr_edges", "netops.corr_evidence",
                      "netops.corr_signals_archive", "netops.corr_path_edges"))
    dec = sum(n for t, n in calls.items()
              if t in ("netops.corr_objects", "netops.corr_current"))
    w(f"{'  of which Evidence tables':<34}{'':>10}{'':>12}{ev:>10}\n")
    w(f"{'  of which Decision tables':<34}{'':>10}{'':>12}{dec:>10}\n")
    return out.getvalue()


def main_cli() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--devices", type=int, default=250)
    ap.add_argument("--signals", type=int, default=3500,
                    help="signals in the first epoch's window (live 2.5K: ~35,000)")
    ap.add_argument("--arrivals", type=int, default=-1,
                    help="new signals loaded before each epoch after the first "
                         "(default: signals // 2)")
    ap.add_argument("--cohorts", type=int, default=20)
    ap.add_argument("--epochs", type=int, default=2)
    ap.add_argument("--cohort-size", type=int, default=-1,
                    help="default mirrors live: pending // 35 (20 cohorts admit "
                         "~57 %% of pending, as on run 08281911)")
    ap.add_argument("--span-s", type=float, default=300.0)
    ap.add_argument("--burst", type=int, default=6,
                    help="consecutive events one device emits before the stream "
                         "moves on (live ratio: 5.6 signals per touched component)")
    ap.add_argument("--arrival-device-share", type=float, default=0.4,
                    help="share of the estate the next epoch's arrivals land on")
    ap.add_argument("--storm", dest="storm", action="store_true", default=True)
    ap.add_argument("--no-storm", dest="storm", action="store_false")
    ap.add_argument("--gate", dest="gate", action="store_true", default=True,
                    help="P1 cohort-touch gate ON (default)")
    ap.add_argument("--no-gate", dest="gate", action="store_false")
    ap.add_argument("--insert-sleep-ms", type=float, default=0.0,
                    help="per-insert latency for the mocked ClickHouse sink "
                         "(the live 2.5K p50 is ~7; 0 = CPU-only, the pre-step-4 "
                         "default)")
    ap.add_argument("--evidence-async", dest="evidence_async",
                    action="store_true", default=True,
                    help="P2 step 4: defer the Evidence write onto the bounded "
                         "priority queue (the shipped default)")
    ap.add_argument("--no-evidence-async", dest="evidence_async",
                    action="store_false",
                    help="write the Evidence rows inline, as before step 4")
    ap.add_argument("--evidence-batch", dest="evidence_batch",
                    action="store_true", default=True,
                    help="P2 step 4c: accumulate Evidence rows PER TABLE across "
                         "versions and flush on items/bytes/age (the shipped "
                         "default). The number it moves is INSERT CALLS per "
                         "table — see the persistence table below.")
    ap.add_argument("--no-evidence-batch", dest="evidence_batch",
                    action="store_false",
                    help="one INSERT per (version, table, page), as before 4c")
    ap.add_argument("--decision-batch", dest="decision_batch",
                    action="store_true", default=False,
                    help="also batch corr_objects/corr_current (DEFAULT OFF — it "
                         "buffers the operator's verdict and trades T1 TTUR)")
    ap.add_argument("--decision-offload", dest="decision_offload",
                    action="store_true", default=True,
                    help="P2 step 4d: badges parse, archive slice+hash and byte "
                         "estimate off the loop thread (the shipped default)")
    ap.add_argument("--no-decision-offload", dest="decision_offload",
                    action="store_false",
                    help="build them on the loop thread, as before step 4d")
    ap.add_argument("--cprofile", action="store_true",
                    help="also cProfile ONE synchronous run_window (top 30)")
    ap.add_argument("--log-level", default="WARNING")
    ap.add_argument("--json", default="")
    args = ap.parse_args()
    # The engine logs one INFO line per persisted version. Writing 1,300 lines
    # to a terminal is I/O this profile did not come to measure (and in the
    # container it goes to a file handler on a different cost curve), so it is
    # silenced — and declared, because it IS real production cost.
    logging.getLogger("correlation").setLevel(getattr(logging, args.log_level))
    logging.getLogger().setLevel(getattr(logging, args.log_level))
    if args.arrivals < 0:
        args.arrivals = args.signals // 2
    if args.cohort_size < 0:
        args.cohort_size = max(1, args.signals // 35)

    main.CORR_ENGINE_COHORT_SIZE = args.cohort_size
    main.CORR_STORM_COHORT_SIZE = args.cohort_size
    main.CORR_ENGINE_DRAIN_COHORTS = args.cohorts
    main.CORR_COHORT_TOUCH_GATE = args.gate
    main.CORR_LIFECYCLE_EPOCH_CADENCE = True
    main.CORR_EVIDENCE_ASYNC = args.evidence_async
    main.CORR_EVIDENCE_BATCH = args.evidence_batch
    main.CORR_DECISION_BATCH = args.decision_batch
    main.CORR_DECISION_OFFLOAD = args.decision_offload
    main._EVIDENCE_QUEUE = None
    main._EVIDENCE_TASK = None
    main._EVIDENCE_LOOP = None
    main._EVIDENCE_BATCHER = None
    main._EVIDENCE_FLUSHER = None
    main._LIFECYCLE_SEEN_WINDOW.clear()
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

    install()
    t0 = time.perf_counter()
    try:
        res = asyncio.run(sweep(args))
    finally:
        total = time.perf_counter() - t0
        prof = PROF.snapshot()
        remove()

    res["config"] = vars(args) | {
        "retention_required_s": main.RETENTION_REQUIRED_S,
        "engine_reach_s": main.ENGINE_REACH_S,
        "python": sys.version.split()[0],
        "cpu_count": os.cpu_count(),
    }
    res["stages"] = {k: {"calls": v[0], "inclusive_s": round(v[1], 4),
                         "exclusive_s": round(v[2], 4)}
                     for k, v in sorted(prof.items(), key=lambda kv: -kv[1][2])}
    res["total_wall_s"] = round(total, 3)
    print(report(res, prof, args, total))

    per = [c["wall_s"] for e in res["epochs"] for c in e["cohorts"]]
    dec = [c["decision_s"] for e in res["epochs"] for c in e["cohorts"]]
    evd = [c["evidence_s"] for e in res["epochs"] for c in e["cohorts"]]
    if per:
        print(f"cohort wall: n={len(per)} mean={statistics.mean(per):.2f}s "
              f"min={min(per):.2f}s max={max(per):.2f}s")
        # P2 step 4's headline: how long the OPERATOR waits for the verdict rows
        # of a cohort, versus how long the full graph takes to materialize.
        print(f"  decision-complete : mean={statistics.mean(dec):.2f}s "
              f"min={min(dec):.2f}s max={max(dec):.2f}s "
              f"(share of cohort wall {100.0 * sum(dec) / max(1e-9, sum(per)):.1f} %)")
        print(f"  evidence-complete : +mean={statistics.mean(evd):.2f}s "
              f"max=+{max(evd):.2f}s  [evidence_async="
              f"{args.evidence_async}, evidence_batch={args.evidence_batch}, "
              f"decision_batch={args.decision_batch}, "
              f"decision_offload={args.decision_offload}, "
              f"insert_sleep_ms={args.insert_sleep_ms}]")
    print("\nevidence plane:", json.dumps(main.evidence_stats(), indent=2))
    print("\ncross-epoch reuse:", json.dumps(res["cross_epoch_reuse"], indent=2))
    print("\npersistence (mocked):", json.dumps(res["persistence"], indent=2))
    for e in res["epochs"]:
        print(f"\nepoch {e['epoch']}: prep={e['prep_s']}s lifecycle={e['lifecycle_s']}s "
              f"wall={e['epoch_wall_s']}s cohorts={e['cohorts_drained']} "
              f"nodes={e['nodes']} components={e['components_total']} "
              f"touched={e['touched_total']} hits={e['memo_hits_total']} "
              f"ranked={e['ranked_total']} open={e['open_objects']}")
        print(f"          level-1 rank memo: hits={e['rank_memo_hits']} "
              f"misses={e['rank_memo_misses']} "
              f"hit_share={e['rank_memo_hit_share']} "
              f"entries={e['rank_memo_entries']} "
              f"evicted={e['rank_memo_evicted']} "
              f"unkeyable={e['rank_memo_unkeyable']}")

    if args.cprofile:
        print("\n" + _cprofile_run_window(args))

    if args.json:
        with open(args.json, "w") as fh:
            json.dump(res, fh, indent=2, default=str)
        print(f"\nwrote {args.json}")
    return 0


def _cprofile_run_window(args) -> str:
    """cProfile ONE synchronous run_window over a freshly prepared window.

    cProfile only sees the calling thread, and the sweep runs run_window on the
    executor — so this is a separate, deliberately synchronous call rather than
    an attempt to profile the sweep itself."""
    from catalog import builtin_catalog
    now = datetime(2026, 8, 28, 12, 0, 0, tzinfo=timezone.utc)
    sigs = make_signals(args.signals, args.devices, t_end=now, span_s=args.span_s,
                        burst=args.burst)
    prep = engine.prepare_run_window(tuple(sigs), (), main.ENGINE_CFG)
    keys = frozenset(list({n.key for n in prep.nodes})[:max(1, len(prep.nodes) // 20)])
    pr = cProfile.Profile()
    pr.enable()
    engine.run_window(tuple(sigs), builtin_catalog(), (), main.ENGINE_CFG,
                      storm_mode=args.storm, cohort_keys=keys, prep=prep,
                      memo=engine.ComponentMemo())
    pr.disable()
    s = io.StringIO()
    pstats.Stats(pr, stream=s).sort_stats("tottime").print_stats(30)
    return s.getvalue()


if __name__ == "__main__":
    raise SystemExit(main_cli())
