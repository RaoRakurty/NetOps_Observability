"""P2 step 4 — the Evidence plane's bounded, priority-ordered work queue.

Spec: `docs/design/DECISION_EVIDENCE_SPLIT_P2_2026-08-28.md` §1, §4, §9 item 4.
Measured brief: `docs/scale/P2_STEPS012_2P5K_VERDICT_2026-08-29.md` §4.3 — on the
live 2.5K leg a 5,000-signal cohort costs ~1,000 s, essentially all of it in the
per-version persist path (`run_window` is 104 s TOTAL over 33 cohorts, p50 34 ms),
and the operator's verdict (the `corr_objects` + `corr_current` rows) already
exists in the first ~100 ms of that cohort. It waits ~1,000 s because it is
written behind the Evidence rows — edges, typed edges, evidence, archive slice —
of every earlier object in the same cohort.

WHAT THIS MODULE IS
    The pure data structures for deferring that Evidence work: an `EvidenceItem`
    (one persisted version's Evidence payload, already frozen) and an
    `EvidenceQueue` (a bounded priority queue with byte accounting, blocking
    backpressure, and a cohort HOLD). It deliberately knows nothing about
    ClickHouse, `main.py` or the engine — the writer lives in `main.py` next to
    the functions whose bytes it must not move, and this module is what the
    tests can drive without a stack.

DETERMINISM (spec §1, owner memo §21 — non-negotiable)
    Runtime conditions decide WHEN an item is written, never WHAT it contains.
    Every field of an item is fixed at enqueue time by the Decision plane, from a
    frozen snapshot; the queue only reorders and paces. In particular the
    archive-slice DAMPING decision (`_ARCHIVE_SLICE_HASH`, "same membership as
    the last archived version ⇒ skip") is made SYNCHRONOUSLY, in version order,
    by the Decision plane and carried on the item as a done deal — if it were
    made in the consumer, the drain ORDER (a runtime condition) would decide
    which archive slices exist, which is exactly what §1 forbids.

ORDERING
    `(priority_class, window_start, correlation_id, version)`, entirely
    content-derived:
      * 0 — a new incident (v1) or a MATERIAL verdict change (`material_hash`
            moved). The rows a forensic reader needs first.
      * 1 — a terminal version: closed (quiesce or the 163 cap) or merged.
      * 2 — a heartbeat / unchanged re-persist (`material_hash` did NOT move).
    `window_start` is the snapshot's own window start, `version` its own version;
    nothing here reads a wall clock, a queue depth or an arrival order. A
    monotonic `seq` is appended ONLY as a heap tie-break so `EvidenceItem`
    instances are never compared with `<` — two real items can never share the
    whole 4-tuple (one (cid, version) is persisted once).

BOUNDS AND BACKPRESSURE (spec §4, owner memo §22 — lossless always)
    Two bounds, both hard: `max_items` and `max_bytes` (a calibrated STANDALONE
    estimate of the snapshot/slice bytes an item keeps reachable — see
    `estimate_bytes`). A `put` into a full queue BLOCKS the Decision plane until
    the consumer has made room. Nothing is ever dropped, sampled or summarised;
    the only thing that degrades under pressure is latency, and it is counted
    (`backpressure_total`) and measured (`oldest_age_s`, `lag_s`).

    Both bounds are MEASURED, not chosen: a pinned 5,000-item queue was walked
    at **142.3 MiB standalone / 29.9 KiB per item**, so the defaults
    `main.CORR_EVIDENCE_QUEUE_MAX` = 2,000 (measured 55.2 MiB) and
    `CORR_EVIDENCE_QUEUE_BYTES_MAX` = 64 MiB agree with each other at ~2,200
    items and either can hold the line
    (`docs/scale/P2_MEMFLAT_EVIDENCE_QUEUE_2026-08-29.md` §6a).

THE COHORT HOLD IS GENERATIONAL — and that is a correction, not a detail
    Spec §1's rule is precise: a cohort's Decision rows land before the Evidence
    rows OF THE SAME COHORT. It says nothing about EARLIER cohorts' Evidence.

    The first implementation held the consumer globally for the duration of a
    decision pass, which is strictly stronger than the rule — and on the live
    2.5K leg (`p2-s04-08290653`) that difference was the whole story: a drain
    sweep runs cohorts back to back with a single `asyncio.sleep(0)` between
    them, so the consumer got one scheduling slot per cohort, drained ONE item,
    and was held again. Measured offline on the same shape: 8 cohorts produced
    61 items and materialized 7. The queue climbed to its 5,000 bound and stayed
    there, and the only thing that ever let the consumer run was the bound
    lifting the hold (backpressure_total 8,767).

    So the hold is now per GENERATION. `hold()` opens a generation; everything
    `put` during it lands in `_open`; `release()` closes it and merges `_open`
    into `_ready`. The consumer always drains `_ready` — items from cohorts that
    have finished their decision pass — and only touches `_open` when nothing is
    held, when a bound demands it, or when the hold has expired. The ordering
    guarantee is unchanged and the Evidence plane now uses the decision path's
    own I/O waits instead of starving until the queue is full.

    Two liveness escapes, both counted, because a stuck hold would silently
    starve the Evidence plane:
      * a bound always wins over the ordering preference (a cohort that produces
        more items than the queue can hold cannot deadlock on its own
        backpressure);
      * a hold older than `hold_max_s` EXPIRES: the consumer drains the open
        generation anyway and `hold_expired_total` records it. `held_since_s`
        makes the bare `held` bool interpretable — a scrape that lands inside a
        cohort's decision pass legitimately sees `held=True`, and only a
        `held_since_s` that keeps growing is a defect.
"""
from __future__ import annotations

import asyncio
import hashlib
import heapq
import json
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

# The byte estimator's two reusable pieces, imported rather than re-derived so
# the Evidence plane and the rank memo can never drift into two different
# answers to "what does holding this graph cost?":
#   * `_owned_ids(catalog_version)` — the ids of everything the CATALOG owns
#     (template titles, owner strings, first_steps tuples, the shared
#     `inapplicable` HypothesisScore objects), cached per catalog version and
#     revalidated in O(1);
#   * `estimate_result_bytes(obj, owned)` — the id-`seen`, ownership-aware deep
#     walk itself, which is generic over any value graph and is used here on an
#     `ObjectSnapshot` instead of a `RankingResult`.
# Neither is modified by this module; `rank_memo` imports nothing from here, so
# there is no cycle.
from rank_memo import _owned_ids as _catalog_owned_ids
from rank_memo import estimate_result_bytes as _deep_bytes

__all__ = [
    "EVIDENCE_CLASS_DECISION",
    "EVIDENCE_CLASS_HEARTBEAT",
    "EVIDENCE_CLASS_TERMINAL",
    "EvidenceItem",
    "EvidencePutAborted",
    "EvidenceQueue",
    "RowBatcher",
    "batch_token",
    "estimate_bytes",
    "loose_slice_signals",
]


class EvidencePutAborted(RuntimeError):
    """`EvidenceQueue.put` stopped waiting because the caller's `abort`
    predicate fired (ultra #15: the consumer that would have made room is
    gone). The item was NOT enqueued — nothing was mutated — so the caller
    decides what happens next (revive the consumer and retry, or write
    inline). Never raised unless the caller passed `abort`."""

# Priority classes. Content-derived: the class is a property of what the version
# IS, never of how busy the process was when it was minted.
EVIDENCE_CLASS_DECISION = 0     # v1, or material_hash moved
EVIDENCE_CLASS_TERMINAL = 1     # closed / merged terminal version
EVIDENCE_CLASS_HEARTBEAT = 2    # unchanged re-persist (material_hash held)

# ── the byte estimator's two constants (everything else is MEASURED) ─────────
#
# `_BYTES_ITEM_OVERHEAD` — the item dataclass, its heap entry tuple and the
# small strings it owns outright (correlation_id, tok, slice_hash). Measured at
# 0.4-0.6 KiB; kept at 512 B.
#
# `_BYTES_PER_LOOSE_SLICE_SIGNAL` — one `Signal` the item is the ONLY holder of.
# MEASURED (tracemalloc, 2,000 real fixture signals dropped): 1,006 B standalone.
# Kept at 1,024 B, which is also the "~1 KB per archive row" figure
# `main._archive_slice`'s chunking note already records.
_BYTES_ITEM_OVERHEAD = 512
_BYTES_PER_LOOSE_SLICE_SIGNAL = 1024

_EMPTY_OWNED: frozenset[int] = frozenset()


# One heap entry: (content key, monotonic tie-break, item). The tie-break exists
# only so `EvidenceItem` instances are never compared with `<`.
_Entry = tuple[tuple[int, float, str, int], int, "EvidenceItem"]


@dataclass(slots=True)
class EvidenceItem:
    """One persisted version's Evidence payload, frozen at enqueue time.

    `snap` is the SAME `ObjectSnapshot` the Decision plane wrote its object row
    from — a reference, not a copy, so an item costs no serialization until it
    drains. While the object is open, `main.OPEN_OBJECTS[cid]["snapshot"]` holds
    that reference anyway; for a terminal version the item holds the last one,
    which is what makes a closed object's archive slice writable after its
    registry entry is gone.

    `slice_sigs` is the archive slice MEMBERSHIP, computed synchronously by
    `main._archive_slice` because it needs the epoch's window (which is dropped
    at `_close_epoch`, before this item can drain). It is a list of references
    to `Signal` objects the snapshot's own nodes already hold, PLUS the "loose"
    signals (kind `*_clear`, `source=app_identity`) and matched identity signals
    that live only in the window — only the LOOSE ones are an RSS cost the
    snapshot has not already paid, and only they are charged (see
    `loose_slice_signals`). `None` means "this version writes no
    archive slice" (a terminal persist with an empty window, or a slice whose
    membership is unchanged since the last archived version — the damping
    decision, made by the Decision plane in version order, see the module
    docstring).
    """

    correlation_id: str
    tenant_id: str
    version: int
    state: str
    tok: str
    snap: Any                       # engine.ObjectSnapshot (not imported: this
                                    # module stays free of engine dependencies)
    priority_class: int
    window_start_ts: float
    slice_sigs: list | None = None
    slice_hash: str = ""
    enqueued_mono: float = field(default_factory=time.monotonic)
    # The queue's byte bound, in the queue's own currency: what this item keeps
    # reachable if NOTHING ELSE holds it (`estimate_bytes`). 0 on an item built
    # while no queue is active — nothing reads it then.
    est_bytes: int = 0

    @property
    def key(self) -> tuple[int, float, str, int]:
        """The content-derived ordering key (spec §4)."""
        return (self.priority_class, self.window_start_ts,
                self.correlation_id, self.version)


def loose_slice_signals(snap: Any, slice_sigs: list | None) -> int:
    """How many of an archive slice's signals the item alone would hold.

    `main._archive_slice` builds the slice as "every signal of every COMPONENT
    node, PLUS the loose ones" (`*_clear`, `source=app_identity`, and the
    identity signals this object matched). The first part is a SECOND REFERENCE
    to signals `snap.nodes` already holds, so charging it is a pure double
    count — measured at 100 % of the slice on the offline 600-device fixture
    (`docs/scale/P2_MEMFLAT_EVIDENCE_QUEUE_2026-08-29.md` §5), where the mix
    emits no clears and no app-identity signals at all.

    That is a property of the FIXTURE, not of the code: on a live estate with
    clears and app-identity enrichment the loose term is > 0, and it is the one
    part of the slice the queue genuinely retains once `_prune_buffer` drops the
    window. So it is counted rather than assumed away — by ARITHMETIC, O(nodes),
    with no second walk:

        n_loose = len(slice_sigs) - Σ len(node.signals)   (floored at 0)

    The floor matters: a snapshot whose nodes were built from a DIFFERENT window
    object than the slice (never true on the persist path, but cheap to survive)
    would otherwise produce a negative charge."""
    if not slice_sigs:
        return 0
    held = 0
    for node in getattr(snap, "nodes", ()) or ():
        held += len(node.signals)
    return max(0, len(slice_sigs) - held)


def estimate_bytes(snap: Any, slice_sigs: list | None = None) -> int:
    """The bytes one queued item keeps reachable, STANDALONE — measured, not
    guessed (see `docs/scale/P2_MEMFLAT_EVIDENCE_QUEUE_2026-08-29.md` §4/§6b).

    THE MODEL, and why it is a walk rather than three constants. The predecessor
    charged `2048 B/node + 768 B/edge + 1024 B/slice signal`. Measured against
    the same items that estimate read **2.84x the true marginal and 25 % UNDER
    the standalone worst case** — wrong in both directions at once, because it
    modelled neither: the dominant cost of an item is the per-VERSION snapshot
    payload (its ranking, hypotheses and verdict), which is near-constant at
    ~29 KiB/item across 3.1-5.7 nodes and 7.3-11.5 edges, while the three
    constants swung 14.5 -> 22.5 KiB/item with component size.

    So the payload is now CHARGED ONCE PER ITEM by the same id-`seen`,
    ownership-aware walk `rank_memo` was calibrated to at `a75b73f8`, plus the
    loose-slice term above.

    THE THREE RULES, and the one that is deliberately INVERTED w.r.t. the memo:

    1. **id-`seen` walk** — an object reachable twice from one item (a signal
       held by a node and by the slice, a grounding shared by two edges) is
       charged once.
    2. **Catalog ownership -> ZERO.** Everything reachable from the `Catalog`
       and from `scoring._catalog_plan`'s outputs outlives every item that
       points at it, so evicting an item frees none of it. MEASURED WORTH:
       dropping this rule moves the estimate from 1.07x to 1.41x of the
       tracemalloc standalone on the calibration fixture (1.10x -> 1.49x on a
       second, wider one) — straight out of the band either way.
    3. **`OPEN_OBJECTS` ownership -> NOT discounted, on purpose.** This is where
       an Evidence item differs from a memo entry. Whether the item's snapshot
       is ALSO held by a live open object is a RUNTIME CONDITION that stops
       being true exactly when it matters: input stops, objects quiesce and
       close, and the queue becomes the sole holder. Measured: 45 % of a pinned
       5,000-item queue shared its snapshot with `OPEN_OBJECTS` at `drained`,
       0 % once those objects closed — the same 5,000 items costing 37.7 MiB
       marginal and 142.2 MiB standalone. A bound sized on the marginal would be
       correct right up to the moment it had to hold. `est_bytes` is therefore a
       STANDALONE figure and `max_bytes` a conservative bound.

    CALIBRATION (tracemalloc, ">= 200" real snapshots, the procedure pinned by
    `test_p2_evidence_async.py::test_E11a`): **1.03x-1.10x** of the memory the
    process gives back when the items are dropped and nothing else holds them,
    over three fixture shapes (14.9 / 20.9 / 22.9 KiB per item). The two mutants
    that test executes land at **1.41x** (ownership off) and **1.42x** (slice
    double count restored). Cross-checked against the SECOND instrument — the
    bench's `gc.get_referents` walker, `--evidence parked --evidence-probe-order
    ws-first` — at **1.15x** of its inclusive (standalone) reading.

    COST: **0.24-0.38 ms/item**, i.e. ~13-14 us per KiB walked — the SAME
    per-byte cost as `rank_memo`'s calibrated walk (0.24-0.30 ms on a ~20 KiB
    entry), and split evenly across the graph (ranking 40 %, nodes 38 %, edges
    9 %), so there is no hotspot to prune. It is paid on the Decision path only
    when the queue is actually active (`main._persist_snapshot`), against a
    persist path measured at ~7 ms/version.

    Takes the SNAPSHOT, not counts: the walk needs the graph. `snap=None` (a
    synthetic item in a test) costs the overhead alone."""
    owned = _EMPTY_OWNED
    ranking = getattr(snap, "ranking", None)
    version = getattr(ranking, "catalog_version", None)
    if type(version) is str and version:
        # Fails OPEN: an unresolvable catalog gives an EMPTY ownership set, and
        # the walk then charges everything — the conservative direction for a
        # memory bound (rank_memo._owned_ids, same rule).
        owned = _catalog_owned_ids(version)
    return (_BYTES_ITEM_OVERHEAD + _deep_bytes(snap, owned)
            + loose_slice_signals(snap, slice_sigs) * _BYTES_PER_LOOSE_SLICE_SIGNAL)


class EvidenceQueue:
    """Bounded, priority-ordered, blocking-on-full, never-dropping work queue.

    One `asyncio.Condition` guards the heap, both bounds and the hold, so there
    is exactly one place where "may I add?" and "may I take?" are decided and no
    way for the two to disagree. `asyncio.PriorityQueue` was not used directly
    because it bounds only ITEM COUNT — the second bound (referenced bytes) and
    the cohort hold both need to be evaluated inside the same wait predicate,
    and layering a second condition over a Queue is how deadlocks are written.
    """

    __slots__ = ("_cond", "_hold", "_hold_expired", "_hold_since", "_hold_timer",
                 "_inflight", "_loop", "_open", "_ready", "_seq", "_wake_task",
                 "backpressure_total", "bytes", "hold_expired_total", "hold_max_s",
                 "lag_s", "max_bytes", "max_items")

    def __init__(self, max_items: int, max_bytes: int,
                 hold_max_s: float = 5.0) -> None:
        self.max_items = max(1, int(max_items))
        self.max_bytes = max(1, int(max_bytes))
        self.hold_max_s = max(0.0, float(hold_max_s))
        # `_ready` = generations whose decision pass is over, drainable always.
        # `_open` = the generation being produced right now. Both are heaps on
        # the same content key; `release()` merges open into ready.
        self._ready: list[_Entry] = []
        self._open: list[_Entry] = []
        self._seq = 0
        self._hold = 0
        self._hold_since = 0.0
        self._hold_expired = False
        self._hold_timer: asyncio.TimerHandle | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._wake_task: asyncio.Task | None = None
        self._inflight = 0
        self.bytes = 0
        self.backpressure_total = 0
        self.hold_expired_total = 0
        self.lag_s = 0.0
        self._cond = asyncio.Condition()

    # ── bounds ───────────────────────────────────────────────────────────────
    def full(self) -> bool:
        """At a bound. Also the predicate that LIFTS the cohort hold: under
        pressure, draining beats ordering preference (see the module docstring)."""
        return self.qsize() >= self.max_items or self.bytes >= self.max_bytes

    def qsize(self) -> int:
        return len(self._ready) + len(self._open)

    def oldest_age_s(self, now: float | None = None) -> float:
        """Age of the OLDEST queued item. The heaps are ordered by the content
        key, not by arrival, so this is a linear scan — bounded by `max_items`
        and paid only at scrape time, never on the hot path."""
        if not (self._ready or self._open):
            return 0.0
        now = time.monotonic() if now is None else now
        return now - min(e[2].enqueued_mono
                         for e in (*self._ready, *self._open))

    # ── the cohort hold ──────────────────────────────────────────────────────
    def hold(self) -> None:
        """Open a generation: everything `put` from here until the matching
        `release` belongs to the cohort now running its decision pass, and the
        consumer will not touch it. Items ALREADY queued stay drainable — that
        is the difference from the first implementation, and the reason the
        Evidence plane no longer starves between back-to-back cohorts.

        Re-entrant by count so a nested/overlapping cohort cannot release early.
        """
        self._hold += 1
        if self._hold != 1:
            return
        self._hold_since = time.monotonic()
        self._hold_expired = False
        if self.hold_max_s <= 0:
            return
        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:            # no loop (direct construction in a test)
            self._loop = None
            return
        self._hold_timer = self._loop.call_later(self.hold_max_s, self._expire_hold)

    def _expire_hold(self) -> None:
        """A hold older than `hold_max_s` stops being honoured.

        A leaked hold would starve the Evidence plane in total silence — the
        exact failure this class was just debugged for. It is cheaper to make it
        self-healing AND counted than to prove no path can ever leak one."""
        if not self._hold or self._hold_expired:
            return
        self._hold_expired = True
        self.hold_expired_total += 1
        if self._loop is not None:
            self._wake_task = self._loop.create_task(self._wake())

    def _cancel_hold_timer(self) -> None:
        if self._hold_timer is not None:
            self._hold_timer.cancel()
            self._hold_timer = None

    async def release(self) -> None:
        """Close the generation and WAKE the consumer.

        Async because the wake-up needs the condition's lock — scheduling it as
        a detached task instead would leave the release racing the next cohort's
        hold, which is the one ordering this class exists to guarantee."""
        self._hold = max(0, self._hold - 1)
        if self._hold == 0:
            self._cancel_hold_timer()
            self._hold_expired = False
            self._hold_since = 0.0
            # The generation is complete: its items become drainable in content
            # order alongside everything else already waiting.
            if self._open:
                self._ready.extend(self._open)
                heapq.heapify(self._ready)
                self._open = []
        await self._wake()

    def held_since_s(self, now: float | None = None) -> float:
        """How long the current hold has been open. `held` alone is a bare bool
        that a scrape can legitimately catch True mid-cohort; this is what tells
        an operator whether it is a cohort or a leak."""
        if not self._hold:
            return 0.0
        now = time.monotonic() if now is None else now
        return max(0.0, now - self._hold_since)

    async def _wake(self) -> None:
        async with self._cond:
            self._cond.notify_all()

    @property
    def held(self) -> bool:
        return self._hold > 0

    # ── producer / consumer ──────────────────────────────────────────────────
    async def put(self, item: EvidenceItem, *,
                  abort: Callable[[], bool] | None = None,
                  recheck_s: float = 0.0) -> None:
        """Enqueue, BLOCKING the caller while the queue is at a bound.

        Never drops, never samples, never summarises (owner memo §22). One
        `backpressure_total` increment per put that actually had to wait — the
        number of times the Decision plane was slowed by the Evidence plane, not
        the number of times a condition variable woke up.

        `abort` + `recheck_s` (ultra #15): a parked put waits on the consumer
        to make room, so a consumer that DIED would park it forever. When the
        caller passes an `abort` predicate it is consulted before every wait
        and again whenever the wait wakes; `recheck_s > 0` additionally bounds
        each individual wait, so the predicate is re-evaluated even if every
        wake-up is lost. A firing predicate raises `EvidencePutAborted` with
        NOTHING mutated (the wait loop precedes the enqueue, and a cancelled
        `Condition.wait` reacquires the lock before propagating). Under a
        healthy consumer the behaviour is byte-identical to the plain form:
        the put still blocks, lossless, until room appears — the timeout only
        re-checks the predicate and goes back to waiting."""
        async with self._cond:
            waited = False
            while self.full():
                if abort is not None and abort():
                    raise EvidencePutAborted(
                        "evidence queue full and its consumer is gone")
                if not waited:
                    waited = True
                    self.backpressure_total += 1
                # Wake a consumer parked on the hold predicate: `full()` is now
                # true, so the hold no longer applies and it can make room.
                self._cond.notify_all()
                if recheck_s > 0:
                    try:
                        await asyncio.wait_for(self._cond.wait(), recheck_s)
                    except asyncio.TimeoutError:
                        # asyncio's class, NOT the builtin: they are distinct
                        # on 3.10 (unified only in 3.11+, where this still
                        # matches). The cancelled `wait` has reacquired the
                        # lock before this is raised.
                        continue        # re-check abort() and full()
                else:
                    await self._cond.wait()
            self._seq += 1
            entry = (item.key, self._seq, item)
            # The OPEN generation only while a decision pass is running: those
            # are the items spec §1 says must not precede their own cohort's
            # Decision rows. Everything else is immediately drainable.
            heapq.heappush(self._open if self._hold else self._ready, entry)
            self.bytes += item.est_bytes
            self._cond.notify_all()

    def _open_is_drainable(self) -> bool:
        """The open generation may be drained when nothing holds it, when a
        bound demands it (pressure beats ordering preference), or when the hold
        has outlived `hold_max_s`."""
        return not self._hold or self._hold_expired or self.full()

    async def get(self) -> EvidenceItem:
        """Take the highest-priority DRAINABLE item.

        `_ready` first — closed generations are always drainable, which is what
        lets the consumer use the decision path's own I/O waits instead of
        waiting for a bound."""
        async with self._cond:
            while not (self._ready or (self._open and self._open_is_drainable())):
                await self._cond.wait()
            heap = self._ready if self._ready else self._open
            _key, _seq, item = heapq.heappop(heap)
            self.bytes = max(0, self.bytes - item.est_bytes)
            self._cond.notify_all()
            return item

    def get_nowait(self) -> EvidenceItem | None:
        """Take an item without waiting and WITHOUT honouring the hold — the
        shutdown drain's accessor, where ordering preference is irrelevant and a
        parked consumer would simply lose the item."""
        heap = self._ready if self._ready else self._open
        if not heap:
            return None
        _key, _seq, item = heapq.heappop(heap)
        self.bytes = max(0, self.bytes - item.est_bytes)
        return item

    def pending(self) -> list[EvidenceItem]:
        """Everything still queued, in DRAIN order — the shutdown "what was
        left" report. Non-destructive."""
        return [e[2] for e in sorted((*self._ready, *self._open),
                                     key=lambda e: (e[0], e[1]))]

    def begin(self) -> None:
        """The consumer has taken an item and is writing it. `idle()` must stay
        False across that write, or a drain would declare victory while an
        item's rows are still in flight."""
        self._inflight += 1

    def done(self) -> None:
        self._inflight = max(0, self._inflight - 1)

    @property
    def inflight(self) -> int:
        return self._inflight

    def idle(self) -> bool:
        """Nothing queued AND nothing being written."""
        return not (self._ready or self._open) and self._inflight == 0

    def note_written(self, item: EvidenceItem, finished_mono: float) -> None:
        """Record the materialization lag of the item that just landed."""
        self.lag_s = max(0.0, finished_mono - item.enqueued_mono)

    async def wake(self) -> None:
        """Public wake-up (shutdown / drain helpers)."""
        await self._wake()

    def stats(self) -> dict[str, float | int | bool]:
        return {
            "depth": self.qsize(),
            "depth_ready": len(self._ready),
            "depth_open": len(self._open),
            "inflight": self._inflight,
            "bytes": self.bytes,
            # The LIVE calibration readout: the estimator's per-item mean, next
            # to the measured 29.9 KiB/item standalone the defaults were sized
            # against. A mean that drifts far from it on a real estate is the
            # signal to re-run the ws-first probe, and it is the only way to see
            # the estimator without a bench.
            "est_bytes_mean": (round(self.bytes / self.qsize(), 1)
                               if self.qsize() else 0.0),
            "oldest_age_seconds": round(self.oldest_age_s(), 3),
            "lag_seconds": round(self.lag_s, 3),
            "backpressure_total": self.backpressure_total,
            "max_items": self.max_items,
            "max_bytes": self.max_bytes,
            "held": self.held,
            "held_since_seconds": round(self.held_since_s(), 3),
            "hold_expired_total": self.hold_expired_total,
            "hold_max_s": self.hold_max_s,
        }


# ═══════════════════════════════════════════════════════════════════════════
# CROSS-VERSION ROW BATCHING (P2 step 4c)
# docs/scale/P2_CLICKHOUSE_MEMFLAT_2026-08-29.md §3(a) — the measured brief.
#
# THE MEASUREMENT. On run `p2-s04b-08290858` the Evidence tables issued 63,701
# INSERT statements in 75 minutes at 16.9 / 16.9 / 4.8 rows each, because
# `_emit_child_rows` batches only WITHIN one object version. Every one of those
# statements is a level-0 part, and folding that trickle into ClickHouse's
# accumulated part re-wrote the same bytes over and over: 1.40 GiB inserted
# against **337.6 GiB merged (≈241x write amplification)**, with merge memory
# peaking at 3,978 MiB — 83 % of `max_server_memory_usage` on its own.
#
# WHAT THIS CLASS IS. A per-table accumulator that spans VERSIONS: rows from
# many `EvidenceItem`s land in one buffer and one INSERT. It flushes on the
# FIRST of three triggers — member count, an estimated byte size, or the AGE of
# the oldest buffered row — so a burst flushes on size and a trickle still
# flushes on time. Nothing is ever dropped or reordered: rows are appended in
# the consumer's drain order, which is the content order the queue guarantees,
# and concatenating a table's blocks reproduces exactly the row sequence the
# unbatched path writes.
#
# THE DEDUP TOKEN, and why it keeps `ch_insert`'s contract.
# `insert_deduplication_token` is per BLOCK, so a batch needs exactly one:
# `"batch:" + sha256("|".join(member_keys))[:32]`, members in flush order. Every
# member key is content-derived (`obj:<cid>:v<n>:<state>:<hash16>:<part>`), so
# the block token is a pure function of the block's content and ORDER. That is
# precisely what `ch_insert`'s in-process bounded retry needs: a retry re-sends
# the IDENTICAL list under the IDENTICAL token, so ClickHouse drops the
# duplicate exactly as it does for a single-version insert today.
#
# What it does NOT preserve is cross-RESTART replay dedup, because the batch
# composition depends on drain timing. The async Evidence plane already gave
# that up in step 4 (a failed item is "lost and loud", never replayed), so this
# takes nothing that still existed.
#
# WHY NOT ClickHouse's SERVER-SIDE asynchronous insert mode. It would cut
# parts without any app change — but on 24.8 the deduplication token is NOT
# honoured on that path for non-replicated MergeTree, so enabling it would
# silently drop the idempotency `ch_insert`'s retry relies on. App-side batching
# gives the same part cut and KEEPS the token, which is why the server setting
# stays at 0 (and why `test_ch_exclusions_guard` still forbids naming it).
#
# FAILURE GRANULARITY — the one honest regression, stated plainly. Unbatched, a
# rejected `corr_edges` insert raises out of `_write_evidence_inner` and that
# item's later tables (evidence, archive) are never written. Batched, those rows
# are already buffered when the edges block fails, so they may still land. The
# direction is "more rows survive a failure, never fewer", every row is still
# content-derived and idempotent within its own block, and the ITEM is still
# counted failed once per member. Nothing about a SUCCESSFUL run moves.
# ═══════════════════════════════════════════════════════════════════════════

# The flush triggers of one table, as (max members, max estimated bytes,
# max age in seconds). A trigger set to 0 is DISABLED (never fires), which is
# how a table can be time-only or size-only without a second code path.
BatchLimits = tuple[int, int, float]

_InsertFn = Callable[[str, list, str, dict], Awaitable[bool]]
_FlushCb = Callable[[str, list, list, list, bool, BaseException | None], None]


def batch_token(member_keys: list[str]) -> str:
    """The one dedup token a flushed block carries.

    A pure function of the member keys AND their order, so the same block
    re-sent by `ch_insert`'s retry hashes to the same token and ClickHouse
    dedups it. An empty member list yields "" — no key, no token, and the
    insert then behaves exactly as an untokened one does today.
    """
    if not member_keys:
        return ""
    return "batch:" + hashlib.sha256(
        "|".join(member_keys).encode()).hexdigest()[:32]


def _row_bytes(rows: list) -> int:
    """A cheap ESTIMATE of a chunk's serialized size — for bounding only.

    ONE row is serialized and multiplied by the chunk length. Every chunk handed
    to `add` comes from a single table's single row builder, so its rows are
    homogeneous by construction and the sample is representative; serializing
    all of them would make the batcher pay the cost the sink is about to pay
    again over HTTP. Same rule as `estimate_bytes`: a bound, never an accounting
    figure.
    """
    if not rows:
        return 0
    try:
        return len(json.dumps(rows[0], default=str)) * len(rows)
    except (TypeError, ValueError):
        # A row the sampler cannot serialize must not stop the write; charge a
        # conservative constant so the byte trigger still moves.
        return 1024 * len(rows)


@dataclass(slots=True)
class _Buffer:
    """One table's pending block."""
    rows: list = field(default_factory=list)
    keys: list[str] = field(default_factory=list)
    members: list = field(default_factory=list)
    member_ids: set = field(default_factory=set)
    est_bytes: int = 0
    oldest_mono: float = 0.0
    # How many chunks each member has already contributed TO THIS BLOCK, so an
    # untokened chunk can be given a deterministic key. Scoped to the buffer on
    # purpose: the buffer holds a strong reference to every member, so an id()
    # cannot be recycled inside it, and the counter dies with the block instead
    # of surviving as a process-lifetime map whose keys a freed member's id can
    # collide with (which is exactly how a "deterministic" key stops being one).
    seq_by_member: dict = field(default_factory=dict)


@dataclass(slots=True)
class _TableGate:
    """One table's WRITE ORDER and its in-flight bound.

    THE DEFECT THIS EXISTS FOR (2026-08-29 storm regression). `_flush_locked`
    awaited the INSERT while holding the batcher's single lock, so one slow
    block stopped the whole plane: `persist.batch_flush` max 116,507 ms on the
    live run is one `corr_signals_archive` block retrying behind a struggling
    ClickHouse, and for those 116 seconds no producer could append a row and no
    OTHER table could flush. The block is now taken out under the lock and
    written outside it.

    What still has to hold is per-table ORDER: concatenating a table's blocks
    must reproduce the row sequence the unbatched path writes, so block N of a
    table may not be inserted before block N-1. A ticket gate says exactly that
    and nothing more — `next_seq` is handed out under the batcher lock (so the
    order of tickets IS the order the blocks were taken out), `turn` is the
    ticket allowed to insert, and a block waits on its own future rather than
    on a shared condition, so a wakeup can never go to the wrong waiter.

    Different tables hold different gates and never wait on each other.

    `inflight` is the bound. Writes no longer block their producer, so without
    one a stalled table would let the consumer build blocks forever with the
    rows of every one of them resident. At the bound the producers OF THAT
    TABLE wait — the honest backpressure — and every other table is untouched.
    """
    next_seq: int = 0
    turn: int = 0
    inflight: int = 0
    turn_waiters: dict = field(default_factory=dict)   # seq -> Future
    room_waiters: list = field(default_factory=list)   # Futures, FIFO


class RowBatcher:
    """Per-table, cross-version INSERT accumulator.

    `insert(table, rows, dedup_token, ctx) -> bool` is injected so this class
    stays free of ClickHouse and of `main` — the same reason `EvidenceQueue`
    knows nothing about either. `on_flush(table, rows, keys, members, ok, exc)`
    is where the CALLER does its accounting: it owns the counters, the archive
    row tally and the per-member failure bookkeeping, because those are facts
    about the engine, not about buffering.

    One `asyncio.Lock` serializes the BUFFER — `add`'s append and every path
    that takes a block out — so a background age-flusher can never interleave
    with a producer's append and split a block in an order no reader expects.
    It is NOT held across the INSERT (see `_TableGate`): the block is taken out
    under the lock, given a per-table ticket, and written by its own task, so a
    slow or retrying block delays only its own table's LATER blocks — never a
    producer, never another table.

    `max_rows` is the FOURTH bound and the only one a single producer cannot
    overshoot (2026-08-29 storm regression, `docs/scale/RCA_LATENCY_BASELINE`).
    The other three are checked AFTER the append, so one `add` of a
    10,000-row archive chunk landed WHOLE in a buffer that was already near its
    byte bound: the block ClickHouse then had to accept was tens of MB, and
    every step that walks a block once — `insert_scope`, the NDJSON encode, the
    HTTP send — was sized by the largest member instead of by the bound. With
    `max_rows` the chunk is SPLIT across blocks, so a giant member is written in
    bounded blocks of its own and no block is ever larger than the cap.

    SPLIT AND THE BLOCK TOKEN. A block's dedup token is `batch_token(keys)`, so
    two blocks may never present the same key list. The first part of a split
    chunk keeps the key it would have had unsplit (so nothing moves when no
    split happens); every later part appends `#p<n>`, `n` being its index within
    THIS `add`. That is a pure function of the chunk, the cap and the buffer's
    fill — the same inputs that decided the split — so a retry of the identical
    block re-derives the identical token and ClickHouse still dedups it.
    """

    __slots__ = ("_bufs", "_default", "_gates", "_insert", "_limits", "_lock",
                 "_max_inflight", "_max_rows", "_on_flush", "_on_join", "_tasks",
                 "age_max_s", "blocks_failed", "blocks_inflight_peak", "flushes",
                 "rows_flushed", "writer_waits")

    def __init__(self, *, insert: _InsertFn, on_flush: _FlushCb | None = None,
                 on_join: Callable[[str, Any], None] | None = None,
                 default: BatchLimits = (200, 8 * 1024 * 1024, 2.0),
                 limits: dict[str, BatchLimits] | None = None,
                 max_rows: int = 0, max_inflight: int = 4) -> None:
        self._insert = insert
        self._on_flush = on_flush
        # Called the FIRST time a member contributes rows to a table's buffer,
        # BEFORE any flush that append may trigger. The caller uses it to count
        # the blocks an item is still waiting on; doing it from the return value
        # of `add` would be too late, because the flush that settles the block
        # can happen inside that same call.
        self._on_join = on_join
        self._default = default
        self._limits = dict(limits or {})
        # 0 disables the cap (every pre-existing caller), exactly like a 0 in
        # any other trigger slot.
        self._max_rows = max(0, int(max_rows))
        # Blocks taken out but not yet written, per table. At least 1 — a bound
        # of 0 would mean "never write".
        self._max_inflight = max(1, int(max_inflight))
        self._bufs: dict[str, _Buffer] = {}
        self._gates: dict[str, _TableGate] = {}
        self._tasks: set = set()
        self._lock = asyncio.Lock()
        self.flushes: dict[str, int] = {}
        self.rows_flushed: dict[str, int] = {}
        self.age_max_s = 0.0
        self.blocks_failed = 0
        self.blocks_inflight_peak = 0
        self.writer_waits = 0

    # ── configuration ────────────────────────────────────────────────────────
    def limits_for(self, table: str) -> BatchLimits:
        return self._limits.get(table, self._default)

    def inflight_for(self, table: str) -> int:
        """Blocks of `table` taken out and not yet written."""
        g = self._gates.get(table)
        return g.inflight if g is not None else 0

    def rows_for(self, table: str) -> int:
        """The hard ROW cap of one block (0 = uncapped). Table-independent
        today; the accessor exists so a per-table cap is a one-line change and
        every caller already reads it through one place."""
        return self._max_rows

    @staticmethod
    def _member_key(buf: _Buffer, member: Any, table: str,
                    dedup_token: str) -> str:
        """The key this chunk contributes to its block's token.

        The caller's own dedup token when it has one (that token is already the
        content-derived, page-numbered string `_emit_child_rows` mints). When it
        has none — `corr_signals_archive` is written untokened today — a
        deterministic one is derived from the member's own token plus the number
        of chunks it has already put IN THIS BLOCK, so the block token stays a
        pure function of the block's content and order and of nothing else.
        """
        if dedup_token:
            return dedup_token
        key = id(member)
        seq = buf.seq_by_member.get(key, 0)
        buf.seq_by_member[key] = seq + 1
        return f"{getattr(member, 'tok', '')}:{table}:{seq}"

    # ── producing ────────────────────────────────────────────────────────────
    async def add(self, table: str, rows: list, *, member: Any,
                  dedup_token: str = "") -> None:
        """Buffer one chunk, flushing the table if a trigger fires.

        No per-chunk context is carried: a block spans versions, so the caller's
        `corr_id`/`version` describe one of its members and would MISATTRIBUTE a
        block failure to whichever version happened to open the buffer. The
        block's own shape is built at flush time instead, and the member tokens
        are what name the versions (`on_flush`).

        A chunk larger than the row cap (or larger than the room left in the
        open block) is SPLIT across consecutive blocks — see the class
        docstring for the key/token rule. Rows are appended in the order they
        arrive and never reordered, so concatenating a table's blocks still
        reproduces exactly the sequence the unbatched path writes.
        """
        if not rows:
            return
        # BEFORE the lock, never inside it: a producer that has to wait for
        # write room must not hold the buffer lock while it does, or a stalled
        # table would freeze every other table's appends — the exact coupling
        # this change exists to remove.
        await self._await_room(table)
        taken: list[tuple[_Buffer, int]] = []
        async with self._lock:
            cap = self.rows_for(table)
            max_members, max_bytes, _max_age = self.limits_for(table)
            total = len(rows)
            off = 0
            part = 0
            while off < total:
                buf = self._bufs.get(table)
                if buf is None:
                    buf = self._bufs[table] = _Buffer(oldest_mono=time.monotonic())
                room = (cap - len(buf.rows)) if cap else (total - off)
                if room <= 0:
                    # The open block is already at the cap (a caller lowered it
                    # mid-flight; the trigger below normally takes a full block
                    # the moment it fills): take it out and open a fresh one.
                    # `_take_locked` pops the buffer, so the next turn of the
                    # loop creates it.
                    block = self._take_locked(table)
                    if block is not None:
                        taken.append(block)
                    continue
                take = min(room, total - off)
                # The whole list when nothing is split — same object, no copy,
                # so the un-split path is byte- and allocation-identical.
                chunk = rows if (off == 0 and take == total) else rows[off:off + take]
                buf.rows.extend(chunk)
                key = self._member_key(buf, member, table, dedup_token)
                buf.keys.append(key if part == 0 else f"{key}#p{part}")
                if id(member) not in buf.member_ids:
                    buf.member_ids.add(id(member))
                    buf.members.append(member)
                    if self._on_join is not None:
                        self._on_join(table, member)
                buf.est_bytes += _row_bytes(chunk)
                off += take
                part += 1
                if ((cap and len(buf.rows) >= cap)
                        or (max_members and len(buf.members) >= max_members)
                        or (max_bytes and buf.est_bytes >= max_bytes)):
                    block = self._take_locked(table)
                    if block is not None:
                        taken.append(block)
        # Outside the lock. One `add` that splits a giant chunk can take several
        # blocks; their tickets are already in order, so scheduling them here
        # writes them in that order however long any one of them takes.
        for buf, seq in taken:
            self._schedule(table, buf, seq)

    # ── flushing ─────────────────────────────────────────────────────────────
    async def flush(self, table: str) -> None:
        """Write `table`'s pending block and WAIT for it (plus anything already
        queued ahead of it, which is what its turn means)."""
        async with self._lock:
            block = self._take_locked(table)
        if block is not None:
            self._schedule(table, *block)
        await self.quiesce(table)

    async def flush_all(self) -> None:
        """Flush every table AND wait for every in-flight block.

        The shutdown/drain accessor. `evidence_drain` reads it as "the rows are
        in ClickHouse", so it must quiesce the writers too — a partial block
        left buffered, or a scheduled block left unawaited, is the one way
        batching could lose a row. Tables are flushed CONCURRENTLY: a stalled
        one must not hold up the drain of the others.
        """
        async with self._lock:
            taken = [(t, self._take_locked(t)) for t in list(self._bufs)]
        for table, block in taken:
            if block is not None:
                self._schedule(table, *block)
        await self.quiesce()

    async def flush_due(self, now: float | None = None) -> None:
        """Flush every table whose OLDEST buffered row has aged out.

        Schedules and returns. The flusher task must stay responsive: waiting
        here for a retrying block would stop it ageing out every OTHER table,
        which is precisely the trickle bound it exists to provide.
        """
        now = time.monotonic() if now is None else now
        taken: list[tuple[str, _Buffer, int]] = []
        async with self._lock:
            for table in list(self._bufs):
                buf = self._bufs.get(table)
                if buf is None or not buf.rows:
                    continue
                max_age = self.limits_for(table)[2]
                if max_age and (now - buf.oldest_mono) >= max_age:
                    block = self._take_locked(table, now=now)
                    if block is not None:
                        taken.append((table, *block))
        for table, buf, seq in taken:
            self._schedule(table, buf, seq)

    async def quiesce(self, table: str | None = None) -> None:
        """Wait until every scheduled write has finished (never raises — a
        write task reports its own failure through `on_flush`)."""
        while True:
            pending = [t for t in list(self._tasks)
                       if table is None or getattr(t, "_batch_table", None) == table]
            if not pending:
                return
            await asyncio.gather(*pending, return_exceptions=True)

    def due_in_s(self, now: float | None = None) -> float:
        """Seconds until the next age trigger fires (inf when nothing is
        buffered) — so the flusher task can sleep instead of spinning."""
        now = time.monotonic() if now is None else now
        best = float("inf")
        for table, buf in self._bufs.items():
            if not buf.rows:
                continue
            max_age = self.limits_for(table)[2]
            if max_age:
                best = min(best, max_age - (now - buf.oldest_mono))
        return best

    # ── take (under the lock) / schedule / write (outside it) ───────────────
    def _take_locked(self, table: str, now: float | None = None
                     ) -> tuple[_Buffer, int] | None:
        """Take `table`'s pending block out and TICKET it. Synchronous, and it
        must stay so: it runs under the batcher lock, and the whole point of
        this design is that nothing awaits there."""
        buf = self._bufs.pop(table, None)
        if buf is None or not buf.rows:
            return None
        now = time.monotonic() if now is None else now
        self.age_max_s = max(self.age_max_s, now - buf.oldest_mono)
        g = self._gates.get(table)
        if g is None:
            g = self._gates[table] = _TableGate()
        seq = g.next_seq
        g.next_seq += 1
        g.inflight += 1
        self.blocks_inflight_peak = max(self.blocks_inflight_peak, g.inflight)
        return buf, seq

    def _schedule(self, table: str, buf: _Buffer, seq: int) -> asyncio.Task:
        """Hand one ticketed block to its own task. Fire-and-forget by design —
        the producer's job ended when the rows left the buffer."""
        task = asyncio.get_running_loop().create_task(
            self._write_block(table, buf, seq))
        # Tagged so `quiesce(table)` can wait on one table without touching the
        # others; an attribute rather than a per-table set because a task must
        # be discoverable from the single set the done-callback prunes.
        task._batch_table = table          # type: ignore[attr-defined]
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    async def _write_block(self, table: str, buf: _Buffer, seq: int) -> None:
        """Issue ONE insert for one ticketed block. Never raises.

        A flush can be triggered by a producer that has nothing to do with the
        block being written (that is the whole point of batching across
        versions), so an exception here must NOT surface as that producer's
        failure — and it no longer could, because this runs in its own task. It
        is captured, handed to `on_flush` with the block's members, and
        accounted there, which is the only place that knows how many ITEMS the
        failure cost.

        CANCELLATION is reported like any other failure rather than requeued.
        With the insert out from under the lock a requeue would have to merge
        into a buffer a producer may already have opened — reordering its rows
        and double-counting the members that joined both — so the block is
        counted failed, named in the log by its member tokens, and settled. That
        is the plane's documented durability model (step 4: lost and LOUD, never
        silently replayed), applied to the one path that used to be exempt.
        """
        g = self._gates[table]
        ok: bool = False
        exc: BaseException | None = None
        try:
            await self._await_turn(g, seq)
            token = batch_token(buf.keys)
            ctx = {"row_count": len(buf.rows), "batch_members": len(buf.members)}
            ok = await self._insert(table, buf.rows, token, ctx) is not False
        except asyncio.CancelledError as e:
            exc = e
        except Exception as e:  # noqa: BLE001 — reported to on_flush, never swallowed
            exc = e
        finally:
            self.flushes[table] = self.flushes.get(table, 0) + 1
            self.rows_flushed[table] = (
                self.rows_flushed.get(table, 0) + len(buf.rows))
            if not ok:
                self.blocks_failed += 1
            if self._on_flush is not None:
                # Inside the turn, so a table's blocks are ACCOUNTED in the same
                # order they were written.
                self._on_flush(table, buf.rows, buf.keys, buf.members, ok, exc)
            self._end_turn(g, seq)
            self._release_room(g)

    # ── the per-table ticket gate ───────────────────────────────────────────
    async def _await_turn(self, g: _TableGate, seq: int) -> None:
        if g.turn == seq:
            return
        fut = asyncio.get_running_loop().create_future()
        g.turn_waiters[seq] = fut
        try:
            await fut
        finally:
            g.turn_waiters.pop(seq, None)

    @staticmethod
    def _end_turn(g: _TableGate, seq: int) -> None:
        """Advance past `seq` however it ended — a block that failed, raised or
        was cancelled must still let its successors write, or one bad insert
        wedges its table forever."""
        if g.turn == seq:
            g.turn = seq + 1
            fut = g.turn_waiters.get(g.turn)
            if fut is not None and not fut.done():
                fut.set_result(None)

    async def _await_room(self, table: str) -> None:
        g = self._gates.get(table)
        while g is not None and g.inflight >= self._max_inflight:
            self.writer_waits += 1
            fut = asyncio.get_running_loop().create_future()
            g.room_waiters.append(fut)
            await fut
            g = self._gates.get(table)

    @staticmethod
    def _release_room(g: _TableGate) -> None:
        g.inflight -= 1
        while g.room_waiters:
            fut = g.room_waiters.pop(0)
            if not fut.done():
                fut.set_result(None)
                return

    # ── abandonment (ultra #17) ──────────────────────────────────────────────
    def abandon(self) -> list[tuple[str, list, list[str], list]]:
        """Take EVERY buffered (unflushed, unscheduled) block out WITHOUT
        writing it, returning `(table, rows, keys, members)` per table so the
        caller can ACCOUNT for the loss — the one legitimate caller is the
        plane-replacement path, where this batcher's loop is dead and nothing
        can ever flush these rows.

        Synchronous on purpose: that caller cannot await (its own lock, its
        flusher and its write tasks all belong to the dead loop, so a flush
        from the new loop is not "unsafe", it is impossible). Blocks already
        taken out (`_take_locked`) are owned by their own — equally dead —
        write tasks and were reported through `on_flush` if they ever ran;
        they are not reachable from the buffers and are not returned here.
        """
        out: list[tuple[str, list, list[str], list]] = []
        for table, buf in list(self._bufs.items()):
            if buf.rows:
                out.append((table, buf.rows, buf.keys, buf.members))
        self._bufs.clear()
        return out

    # ── observability ────────────────────────────────────────────────────────
    def buffered(self) -> int:
        return sum(len(b.rows) for b in self._bufs.values())

    def oldest_age_s(self, now: float | None = None) -> float:
        now = time.monotonic() if now is None else now
        ages = [now - b.oldest_mono for b in self._bufs.values() if b.rows]
        return max(ages) if ages else 0.0

    def stats(self) -> dict[str, Any]:
        flushes = sum(self.flushes.values())
        rows = sum(self.rows_flushed.values())
        return {
            "flushes_total": dict(self.flushes),
            "rows_flushed_total": dict(self.rows_flushed),
            "flushes": flushes,
            "rows_per_flush_mean": round(rows / flushes, 2) if flushes else 0.0,
            "batch_age_seconds_max": round(self.age_max_s, 3),
            "buffered_rows": self.buffered(),
            "buffered_tables": len([t for t, b in self._bufs.items() if b.rows]),
            "block_rows_max": self._max_rows,
            "blocks_inflight": sum(g.inflight for g in self._gates.values()),
            "blocks_inflight_max": self._max_inflight,
            "blocks_inflight_peak": self.blocks_inflight_peak,
            "writer_waits_total": self.writer_waits,
            "blocks_failed_total": self.blocks_failed,
        }
