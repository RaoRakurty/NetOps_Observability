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
    Two bounds, both hard: `max_items` and `max_bytes` (an ESTIMATE of the
    snapshot/slice bytes an item keeps reachable — see `EvidenceItem.est_bytes`).
    A `put` into a full queue BLOCKS the Decision plane until the consumer has
    made room. Nothing is ever dropped, sampled or summarised; the only thing
    that degrades under pressure is latency, and it is counted
    (`backpressure_total`) and measured (`oldest_age_s`, `lag_s`).

THE COHORT HOLD
    Spec §1: the Decision plane emits "synchronously, per cohort, BEFORE any
    Evidence write of the same cohort". `hold()` suspends the consumer for the
    duration of a cohort's decision pass so the cohort's verdict rows are not
    interleaved with — and therefore not queued behind — its own Evidence
    inserts. The hold is LIFTED AUTOMATICALLY while the queue is at a bound, so
    a cohort that produces more items than the queue can hold can never deadlock
    against its own backpressure: pressure always wins over ordering preference.
"""
from __future__ import annotations

import asyncio
import heapq
import time
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "EVIDENCE_CLASS_DECISION",
    "EVIDENCE_CLASS_HEARTBEAT",
    "EVIDENCE_CLASS_TERMINAL",
    "EvidenceItem",
    "EvidenceQueue",
]

# Priority classes. Content-derived: the class is a property of what the version
# IS, never of how busy the process was when it was minted.
EVIDENCE_CLASS_DECISION = 0     # v1, or material_hash moved
EVIDENCE_CLASS_TERMINAL = 1     # closed / merged terminal version
EVIDENCE_CLASS_HEARTBEAT = 2    # unchanged re-persist (material_hash held)

# Rough per-element byte weights for the RSS bound. These are an ESTIMATE used
# ONLY to bound the queue — never an accounting figure, never persisted. The
# constants are the orders of magnitude the code already records elsewhere: an
# archive row is "~1 KB" (see main._archive_slice's chunking note), and a node /
# edge carries its signals, tokens and grounding context.
_BYTES_PER_NODE = 2048
_BYTES_PER_EDGE = 768
_BYTES_PER_SLICE_SIGNAL = 1024
_BYTES_ITEM_OVERHEAD = 512


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
    that live only in the window — those are the item's genuine RSS cost, and
    they are what `est_bytes` bounds. `None` means "this version writes no
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
    est_bytes: int = 0

    @property
    def key(self) -> tuple[int, float, str, int]:
        """The content-derived ordering key (spec §4)."""
        return (self.priority_class, self.window_start_ts,
                self.correlation_id, self.version)


def estimate_bytes(n_nodes: int, n_edges: int, n_slice: int) -> int:
    """Bound-only estimate of the bytes an item keeps reachable. See the module
    constants: this exists to make `max_bytes` meaningful, not to be accurate."""
    return (_BYTES_ITEM_OVERHEAD + n_nodes * _BYTES_PER_NODE
            + n_edges * _BYTES_PER_EDGE + n_slice * _BYTES_PER_SLICE_SIGNAL)


class EvidenceQueue:
    """Bounded, priority-ordered, blocking-on-full, never-dropping work queue.

    One `asyncio.Condition` guards the heap, both bounds and the hold, so there
    is exactly one place where "may I add?" and "may I take?" are decided and no
    way for the two to disagree. `asyncio.PriorityQueue` was not used directly
    because it bounds only ITEM COUNT — the second bound (referenced bytes) and
    the cohort hold both need to be evaluated inside the same wait predicate,
    and layering a second condition over a Queue is how deadlocks are written.
    """

    __slots__ = ("_cond", "_heap", "_hold", "_inflight", "_seq",
                 "backpressure_total", "bytes", "lag_s", "max_bytes", "max_items")

    def __init__(self, max_items: int, max_bytes: int) -> None:
        self.max_items = max(1, int(max_items))
        self.max_bytes = max(1, int(max_bytes))
        self._heap: list[tuple[tuple[int, float, str, int], int, EvidenceItem]] = []
        self._seq = 0
        self._hold = 0
        self._inflight = 0
        self.bytes = 0
        self.backpressure_total = 0
        self.lag_s = 0.0
        self._cond = asyncio.Condition()

    # ── bounds ───────────────────────────────────────────────────────────────
    def full(self) -> bool:
        """At a bound. Also the predicate that LIFTS the cohort hold: under
        pressure, draining beats ordering preference (see the module docstring)."""
        return len(self._heap) >= self.max_items or self.bytes >= self.max_bytes

    def qsize(self) -> int:
        return len(self._heap)

    def oldest_age_s(self, now: float | None = None) -> float:
        """Age of the OLDEST queued item. The heap is ordered by the content key,
        not by arrival, so this is a linear scan — bounded by `max_items` and
        paid only at scrape time, never on the hot path."""
        if not self._heap:
            return 0.0
        now = time.monotonic() if now is None else now
        return now - min(e[2].enqueued_mono for e in self._heap)

    # ── the cohort hold ──────────────────────────────────────────────────────
    def hold(self) -> None:
        """Suspend the consumer (spec §1: the cohort's Decision rows land first).
        Re-entrant by count so a nested/overlapping cohort cannot release early."""
        self._hold += 1

    async def release(self) -> None:
        """Drop one hold and WAKE the consumer parked on the hold predicate.
        Async because the wake-up needs the condition's lock — scheduling it as
        a detached task instead would leave the release racing the next cohort's
        hold, which is the one ordering this class exists to guarantee."""
        self._hold = max(0, self._hold - 1)
        await self._wake()

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
            heapq.heappush(self._heap, (item.key, self._seq, item))
            self.bytes += item.est_bytes
            self._cond.notify_all()

    async def get(self) -> EvidenceItem:
        """Take the highest-priority item, waiting for one to exist and for the
        cohort hold to clear (or for a bound to lift it)."""
        async with self._cond:
            while not self._heap or (self._hold and not self.full()):
                await self._cond.wait()
            _key, _seq, item = heapq.heappop(self._heap)
            self.bytes = max(0, self.bytes - item.est_bytes)
            self._cond.notify_all()
            return item

    def get_nowait(self) -> EvidenceItem | None:
        """Take an item without waiting and WITHOUT honouring the hold — the
        shutdown drain's accessor, where ordering preference is irrelevant and a
        parked consumer would simply lose the item."""
        if not self._heap:
            return None
        _key, _seq, item = heapq.heappop(self._heap)
        self.bytes = max(0, self.bytes - item.est_bytes)
        return item

    def pending(self) -> list[EvidenceItem]:
        """Everything still queued, in DRAIN order — the shutdown "what was
        left" report. Non-destructive."""
        return [e[2] for e in sorted(self._heap, key=lambda e: (e[0], e[1]))]

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
        return not self._heap and self._inflight == 0

    def note_written(self, item: EvidenceItem, finished_mono: float) -> None:
        """Record the materialization lag of the item that just landed."""
        self.lag_s = max(0.0, finished_mono - item.enqueued_mono)

    async def wake(self) -> None:
        """Public wake-up (shutdown / drain helpers)."""
        await self._wake()

    def stats(self) -> dict[str, float | int | bool]:
        return {
            "depth": len(self._heap),
            "inflight": self._inflight,
            "bytes": self.bytes,
            "oldest_age_seconds": round(self.oldest_age_s(), 3),
            "lag_seconds": round(self.lag_s, 3),
            "backpressure_total": self.backpressure_total,
            "max_items": self.max_items,
            "max_bytes": self.max_bytes,
            "held": self.held,
        }
