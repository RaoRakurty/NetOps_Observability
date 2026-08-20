# Correlation engine — buffering, expiration, ownership, backpressure

Source review at `44101e59`, with measurements from the 2026-08-19/20 forensic
and A/B runs. Every claim cites code or a measured number.

**Core answer: mostly yes, with three real gaps.** Correlix already gets the two
hardest things right — Kafka holds the backlog, and window expiration is
structurally O(expired) rather than a scan. The gaps are (1) housekeeping can
still monopolise the loop in one unyielded burst, (2) `OPEN_OBJECTS` has no count
bound, and (3) the offload path uses an unbounded executor queue.

---

## 1. How buffering and state work today

`WINDOW_BUFFER` (`main.py:890`) is a `deque` with
`maxlen=max(50_000, CORR_WINDOW_BUFFER)` holding canonical `Signal` objects in
**arrival order**. `_BUFFERED_IDS` (`main.py:897`) is the redelivery-dedup set,
and `_BUFFERED_ID_ORDER` is the same ids in window order so eviction never
recomputes one.

`buffer_signal` (`main.py:1403`) is the single window-entry chokepoint: it drops
platform-self-check probes, canonicalises the global tenant, clamps
future-dated device clocks, dedups by id, evicts the head when the deque is
full, and appends.

`engine_cycle` (`main.py:1912`) prunes, partitions the window by tenant, runs
the pure `run_window` **in a thread executor** (`main.py:2028`), then persists
version increments and closes quiesced objects.

## 2. `_prune_buffer` — implementation and complexity

```python
def _prune_buffer(now):
    horizon = now.timestamp() - ENGINE_CFG.window_s
    _sync_buffered_id_order()
    while WINDOW_BUFFER and WINDOW_BUFFER[0].ts.timestamp() < horizon:
        _BUFFERED_IDS.discard(_BUFFERED_ID_ORDER.popleft())
        WINDOW_BUFFER.popleft()
```

| | complexity | measured (50,000-signal full eviction) |
|---|---|---|
| before | O(expired × uuid5) | **770.0 ms**, 50,000 uuid5 |
| after | O(expired) | **60.3 ms**, 0 uuid5 |

**Correlix already implements Pattern B.** The buffer is a deque popped from the
left while `ts < horizon` — expiration is proportional to what expired, never to
the window. It was never a scan. What made it dangerous was the constant factor:
a SHA-1 per evicted signal.

**Pattern C (time buckets) is not indicated.** RCA windows here are *sliding* and
*event-time* based (`ENGINE_CFG.window_s`, horizon computed per cycle), evidence
routinely spans any bucket boundary, and `correlation_id` derives from the
earliest node plus onset (`main.py:2041` comment) — so dropping a whole bucket
would change which signals co-occur and therefore change RCA identity. Bucketing
would trade a real correctness risk for a constant factor that is already gone.

## 3. Is identity computed once?

Tracing one signal `consume → handle → buffer → engine → archive → prune`:

| stage | before this wave | now |
|---|---|---|
| `handle_syslog` → producer | 1 × uuid5 (construction) | same |
| `to_ch_row` | `str(signal_id)` per call, **once per (object, window signal)** in the archive | base row cached per CYCLE (`_CYCLE_ROW_CACHE`) |
| `_archive_slice` sort key | `str(signal_id)` per object | precomputed ordinal in `_window_index` |
| slice hash | `str(signal_id)` per object | `idx.sid` |
| `buffer_signal` | 1 × uuid5 (the dedup key) | same — genuinely needed once |
| **`_prune_buffer`** | **1 × uuid5 per evicted signal** | **0** |

**Why did prune ever compute it?** Because the id was not stored anywhere
addressable from the deque — `_BUFFERED_IDS` is a set, so there was no way to ask
"what was the head's id". The fix stores the ids in window order alongside the
buffer.

Per-signal instance caching was measured and rejected: a second non-field key in
a ~25-field dataclass's `__dict__` converts it from key-sharing to standalone at
**+944 bytes per signal** (~47 MB across the window). The chosen structures are
therefore cycle-scoped caches and a compact side deque holding *pointers* to
strings that already exist in `_BUFFERED_IDS` (~400 KB at 50k).

## 4. Unbounded synchronous work on the event loop

| code path | trigger | complexity | on loop? | bounded? | risk |
|---|---|---|---|---|---|
| `_prune_buffer` (`main.py:1520`) | every cycle | O(expired) | **yes** | by window maxlen; one call may evict all 50k | ⚠ 60 ms measured; no yield inside |
| tenant partition (`main.py:1981`) | every cycle | O(window) | **yes** | 50k; yields *after* (`await asyncio.sleep(0)`, 1986) | ⚠ |
| `find_continuation` (`main.py:2063`) | per NEW snapshot | **O(open_objects) each → O(snapshots × open_objects)** | **yes** | only by quiesce | ❌ quadratic |
| quiesce sweep (`main.py:2133`) | every cycle | O(open_objects) | **yes** | quiesce only | ⚠ |
| `run_window` (`main.py:2028`) | per tenant | O(n²) candidate pairs | **no** — executor | — | ✅ offloaded |
| `_ndjson_body`, `_batch_token` | per insert | O(rows) | offloaded ≥2000 elements | ✅ | |
| `_persist_snapshot` serializers | per object version | O(nodes+edges) | offloaded ≥2000 | ✅ | |
| archive row build | per chunk | O(chunk) | yes | `CORR_ARCHIVE_CHUNK_ROWS`=10k | ✅ |

**`find_continuation` is the remaining quadratic on live state** and nothing
bounds `OPEN_OBJECTS` by count.

## 5. State bounds

| state | bounded by | maximum | expiration | owner |
|---|---|---|---|---|
| `WINDOW_BUFFER` | count | 50,000 (`CORR_WINDOW_BUFFER`) | age + maxlen head-drop | global |
| `_BUFFERED_IDS` / `_BUFFERED_ID_ORDER` | count | tracks the window | lockstep | global |
| **`OPEN_OBJECTS`** | **nothing** | **unbounded** | `CORR_QUIESCE_S` only | global |
| `_ARCHIVE_SLICE_HASH` | follows OPEN_OBJECTS | unbounded | popped on close/merge | global |
| `SIGNAL_BATCH` | rows | `CORR_BATCH_QUEUE_MAX`=5,000 | flush | global |
| `QUARANTINE` | ring | 200 | ring | global |
| `SERIES` | LRU | `SERIES_MAX` | LRU | global |
| Observer cache | LRU | 20,000 | LRU | global |
| Relation/Grounding caches | LRU | 50,000 each | LRU | global |

**`OPEN_OBJECTS` is the one whose only bound is "until objects quiesce."** At 1k
devices it stayed small (0–8 observed). It is the structure most likely to
misbehave at 10k under a broad correlated storm, and it is also the input to the
quadratic `find_continuation`.

## 6. Does Kafka hold the backlog? ✅ Yes — measured

`build_consumer` (`main.py:3707`) sets no fetch-sizing knobs, so aiokafka
defaults apply: `fetch_max_bytes` **52,428,800 (50 MiB)**,
`max_partition_fetch_bytes` **1,048,576**. Consumption is
`async for msg in consumer` (`main.py:3845`) — one record at a time, not
`getmany`. `enable_auto_commit=False`; offsets advance only after the handler
returns.

So under overload the Python-side prefetch is capped around 50 MiB and the
backlog stays in Kafka. The A/B confirms it behaviourally: **433k and 444k
events remained un-consumed in Kafka** while correlation's own RSS plateaued —
backlog in the broker, not the heap. This principle is genuinely satisfied.

## 7. Backpressure model — implicit, and one silent-loss edge

Today: ingress > processing ⇒ **Kafka lag grows** (durable, correct) and the
window keeps only its newest 50,000 signals. There is no explicit signal — no
pause/resume, no shed, no alarm keyed to sustained lag growth.

The `maxlen` head-drop (`main.py:1489`) is a *correlation-horizon* loss, not a
data loss: the signal is already persisted to `corr_signals`, and its id is
removed from the dedup set in lockstep so a redelivery is not wrongly swallowed.
It is nonetheless a silent degradation of RCA completeness under storm with no
counter — the one place the "no silent state loss" rule is not fully met.

## 8. Partition-owned state? ❌ — this is tracker 155

`OPEN_OBJECTS` (`main.py:910`) and `WINDOW_BUFFER` are **process-global**, not
partition-keyed. Kafka assigns partitions per replica with `RangePartitionAssignor`
for tenant co-partitioning, but the in-memory state has no partition dimension,
no rehydration and no transfer: `on_partitions_revoked` flushes durable output
and evicts no window state. This is exactly the open GA correctness gate. **Not
touched in this wave.**

## 9. Housekeeping separation ⚠ — the executor is unbounded

`_offload` (`main.py:1610`) uses `run_in_executor(None, …)` — the **default**
`ThreadPoolExecutor`: `max_workers = min(32, cpu_count+4)` = **8** in this
container, with an **unbounded work queue**. Threads are bounded; the queue is
not. Under a storm every oversized object serialization enqueues without limit.

This is the anti-pattern to name explicitly: moving unbounded work off the loop
is an improvement in *latency* but not in *boundedness*. A dedicated executor
with an explicit worker count and a bounded queue (rejecting or awaiting when
full) would make it a real bound.

## 10. Cleanup observability ❌

There is **no prune metric of any kind** — no call count, elements examined or
removed, duration, or percentile. The only reason the stall was found at all is
the generic `loop_lag_watchdog` plus the stack capture built during this
programme. Minimum viable, all low-cardinality: `corr_prune_calls_total`,
`corr_prune_evicted_total`, `corr_prune_seconds` (histogram),
`corr_window_signals` (exists), `corr_open_objects` (exists).

---

## Scorecard

| principle | today | evidence | rating |
|---|---|---|---|
| bounded foreground work | prune/partition bounded by window; `find_continuation` quadratic | `main.py:1520/1981/2063` | ⚠ |
| compute identity once | now yes on every hot path | 770→60 ms, 50,000→0 uuid5 | ✅ |
| incremental cleanup | not chunked; one prune may evict 50k with no yield | `main.py:1520` | ⚠ |
| structural/time-window expiration | ordered-deque expiration already in place | `main.py:1520` | ✅ |
| bounded in-memory state | all bounded except `OPEN_OBJECTS` | table §5 | ⚠ |
| Kafka holds backlog | 50 MiB prefetch cap, one-at-a-time, 433k left in broker | `main.py:3707/3845` | ✅ |
| explicit backpressure | implicit lag growth; silent horizon drop | `main.py:1489` | ⚠ |
| partition-owned state | global, no rehydration | `main.py:910`, tracker 155 | ❌ |
| background housekeeping | offloaded but unbounded queue | `main.py:1610` | ⚠ |
| state-store readiness | ~170 MB live at a full window; Level 1 fine | A/B measurement | ✅ |
| cleanup observability | none | no prune metrics | ❌ |

## Recommendations, separated

### MUST FIX before 1K GA
1. **`_prune_buffer` uuid5** — done (`febcef18`), 770→60 ms, byte-identical, 7/7 mutants.
2. **Prune/housekeeping metrics** — a stall must be visible without a bespoke forensic build.

### MUST FIX before 10K
3. **Bound `OPEN_OBJECTS` by count**, with defined behaviour at the bound (degrade + counter, never silent).
4. **`find_continuation` quadratic** — index candidates by tenant/entity instead of scanning all open objects.
5. **Bounded executor** for `_offload` — explicit workers + bounded queue.
6. **Counter on the maxlen head-drop**, so horizon loss under storm stops being silent.
7. **Tracker 155** — partition-owned state.

### FUTURE 100K
8. Time-bucketed window state — only if the sliding event-time semantics are revisited; today it would risk RCA identity.
9. Local state backend (RocksDB/etc.) — **not justified by evidence**. Trigger criterion: measured active state per replica exceeding ~1 GB after `OPEN_OBJECTS` is bounded, or replay/recovery requirements that RAM cannot meet. Measured today: ~170 MB live at a full 50k window.

## Proposed architectural invariant

> No maintenance operation — pruning, archiving, hashing, serialization,
> cleanup, checkpointing, topology maintenance or state expiration — may perform
> unbounded synchronous work on the correlation event loop.

Testable, which is the condition for adopting it:
* a worst-case synthetic window (50k signals, full eviction) asserting bounded
  wall-clock — **already added** (`test_prune_buffer_156.py`);
* mutation tests that remove the bound/yield and must fail — **7/7 killed**;
* per-maintenance duration metrics (recommendation 2), so the invariant is
  observable in production and not only in CI.
