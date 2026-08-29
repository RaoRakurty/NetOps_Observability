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
import heapq
import time
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
    "EvidenceQueue",
    "estimate_bytes",
    "loose_slice_signals",
]

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
    async def put(self, item: EvidenceItem) -> None:
        """Enqueue, BLOCKING the caller while the queue is at a bound.

        Never drops, never samples, never summarises (owner memo §22). One
        `backpressure_total` increment per put that actually had to wait — the
        number of times the Decision plane was slowed by the Evidence plane, not
        the number of times a condition variable woke up."""
        async with self._cond:
            waited = False
            while self.full():
                if not waited:
                    waited = True
                    self.backpressure_total += 1
                # Wake a consumer parked on the hold predicate: `full()` is now
                # true, so the hold no longer applies and it can make room.
                self._cond.notify_all()
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
