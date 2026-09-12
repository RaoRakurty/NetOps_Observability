# P2 step 4 — the Evidence queue as a `memflat` owner (offline, measured)

**Date** 2026-08-29 · **Code** `a75b73f8` (detached worktree, read-only w.r.t. the
main tree) · **Tool** `src/correlation/bench_memflat_p2.py` + the changes in
`bench_memflat_evidence.patch` (next to this file; verified `git apply --check`
clean against `a75b73f8`) · `ruff check --isolated` clean (ruff 0.16.0, the CI pin).

**Question.** P2 step 4 landed an async Evidence plane. On the live 2.5K run
(`p2-s04-08290653`) a hold-leak kept the consumer parked and the queue sat pinned
at **5,000 items ≈ 101 MiB** (its own `est_bytes` estimate) for the whole drain,
while `memflat` failed **503 → 728 MiB (×1.45)** with the rank memo capped at
~100 MB. How much of that is the queue, and what bound would hold it under
~64 MiB on the 1.25 GiB (`mem_limit: 1280m`) container?

**Answer in one line.** A pinned 5,000-item queue costs **+37.7 MiB of true
marginal retention and +22.9 MiB of extra post-input RSS growth** offline — about
**half of all post-input owner growth** — but its *worst case*, which is what a
memory bound must be sized against, is **142 MiB** (29 KiB/item, measured), and
`evidence_plane.estimate_bytes` is **2.84× too high against the marginal and 25 %
too low against that worst case**, so today's `_BYTES_MAX` (512 MiB) is inert and
only the 5,000-item bound binds. Recommendation: **`CORR_EVIDENCE_QUEUE_MAX=2000`,
`CORR_EVIDENCE_QUEUE_BYTES_MAX=64 MiB`, and yes — the estimator needs the
`rank_memo`-style calibration, but with the opposite ownership rule (§6).**

---

## 1. What was run

Same fixture and sweep shape as `P2_MEMFLAT_ATTRIBUTION_2026-08-29.md`
(`bench_profile_p2.make_signals`, ratified `EVENT_MIX_REALISTIC`, `burst=6`,
storm-declared, deterministic, persistence mocked). **Scaled down and said so:**

| | offline | live 2.5K |
|---|--:|--:|
| devices | 600 | 2,500 |
| signals loaded | 20,000 (5 × 4,000) | — |
| window at input stop | 17,840 | — |
| open objects | 2,899 | — |
| versions persisted | **5,833 (identical in all legs)** | — |
| pinned queue | **5,000 items / 107.1 MiB `est_bytes`** | **5,000 items / ~101 MiB** |
| RSS at `drained` | 264–304 MiB | 728 MiB |

The queue's *item shape* reproduces live almost exactly (21.9 vs 21.2 KiB
`est_bytes`/item, 6 % apart) even though the RSS level is ~0.4× — that is what
makes the per-item numbers below transferable and the MiB totals not.

New `--evidence` modes (all in the patch):

| mode | what |
|---|---|
| `keepup` | the **real** `main._evidence_consumer`, drained to idle before every measurement → queue at **0 items**. The shape step 4 is supposed to have. |
| `parked` | a **pinning consumer** that materializes an item only while the queue is deeper than `--evidence-pin`, so the queue sits at exactly that depth for the whole sweep → the **live pinned shape**. Items go through the real `main._write_evidence`; only the resident `pin` are never materialized. |
| `inline` | `CORR_EVIDENCE_ASYNC=0`, no queue (available, not used below). |

`--evidence-probe-order` decides what the reclaimability probe measures:
`queue-first` drops the queue while the working set is live (→ **true marginal**),
`ws-first` drops the working set first (→ **standalone**). Both were run.

Legs: `keepup`, `parked --evidence-pin 5000`, `parked --evidence-pin 2000`,
`parked 5000 --evidence-probe-order ws-first`, plus `--tracemalloc` and `--light`
legs. ~18 min CPU total on 4 cores.

**Determinism check:** all legs produced **5,833 versions** and byte-identical
numbers in *every* owner except `evidence_queue`. The parked legs write fewer
rows (58 k vs 191 k) purely because the resident `pin` items are never
materialized — a memory shape, not a row-count shape.

---

## 2. RSS — the number the gate reads (`--light` legs only)

The deep walker's `seen` id-set is tens of MiB at this heap size and pollutes the
*next* RSS reading, so — as in the previous attribution — **the RSS curve comes
from `--light` runs and the byte attribution from full runs, never mixed.**

| leg | start | **input_stopped** | **drained** | **Δ post-input** | **ratio** |
|---|--:|--:|--:|--:|--:|
| `keepup` (queue at 0) | 65.6 | 241.5 | 264.3 | **+22.8** | **1.094** |
| `parked` @ 5,000 | 65.7 | 258.0 | 303.7 | **+45.7** | **1.177** |

The pinned queue therefore costs, at this scale:

* **+16.5 MiB of LEVEL** already at `input_stopped` (3,739 items resident), and
* **+22.9 MiB of extra POST-INPUT GROWTH** — it *doubles* the growth the gate
  measures, moving the offline ratio 1.094 → 1.177.
* **+39.4 MiB at `drained`** in total.

`evidence_dropped` does not move RSS (303.7 → 303.7): freed Python objects return
to the allocator's arenas, not to the OS. RSS proves the queue *costs*; only the
walker and `tracemalloc` prove what it *retains*.

---

## 3. Owner × bytes × mode — deep, EXCLUSIVE (each object charged once)

Owners are walked working-set-first and the **Evidence queue LAST**, so anything
it shares with a live `OPEN_OBJECTS` entry is charged to the working set and the
queue's column is its **true marginal**. MiB.

| owner | keepup `input_stopped` | keepup `drained` | parked@5000 `input_stopped` | parked@5000 `drained` | parked@2000 `drained` |
|---|--:|--:|--:|--:|--:|
| `OPEN_OBJECTS` | 97.63 | 106.39 | 97.63 | 106.39 | 106.39 |
| `WINDOW_BUFFER` | 4.76 | 4.76 | 4.76 | 4.76 | 4.76 |
| `_PROCESSED_IDS` | 0.99 | 1.95 | 0.99 | 1.95 | 1.95 |
| `_BUFFERED_IDS` + order | 2.09 | 2.09 | 2.09 | 2.09 | 2.09 |
| `_ARCHIVE_SLICE_HASH` | 0.32 | 0.32 | 0.32 | 0.32 | 0.32 |
| `_TENANT_EDGES` | 0.92 | 3.86 | 0.92 | 3.86 | 3.86 |
| signal interns | 0.09 | 0.09 | 0.09 | 0.09 | 0.09 |
| catalog + plan caches | 0.91 | 0.91 | 0.91 | 0.91 | 0.91 |
| `RankMemo` | 32.67 | 39.70 | 32.67 | 39.70 | 39.70 |
| `Clause.kinds` cache | 0.16 | 0.16 | 0.16 | 0.16 | 0.16 |
| `signal_id` cache | 5.51 | 5.51 | 5.51 | 5.51 | 5.51 |
| **`EvidenceQueue`** | **0.00** | **0.00** | **17.61** | **37.69** | **9.65** |
| **TOTAL live** | **146.05** | **165.74** | **163.65** | **203.42** | **175.39** |
| **Δ post-input** | | **+19.69** | | **+39.77** | **+25.03** |
| **ratio** | | **1.135** | | **1.243** | **1.166** |

Two readings:

1. **The queue is the single largest contributor to post-input growth once
   pinned.** It adds **+20.08 MiB** of the parked leg's +39.77 MiB — **50.5 %** of
   all post-input owner growth, against `OPEN_OBJECTS`'s +8.76 and the memo's
   +7.03. With the consumer keeping up it contributes exactly **zero**.
2. **Nothing else moves.** Every other owner is byte-identical across the three
   legs. The queue is a clean additive term, not a perturbation of the engine.

### Cross-check, two independent instruments
On the `--tracemalloc` leg (pin 2,000, reduced scale) the traced
`drained → evidence_dropped` delta sums to **−7.90 MiB** against the walker's
**7.62 MiB** exclusive — **3.7 % apart**, and the freed lines are exactly the
snapshot payload (`<string>:3` dataclass `__init__`, `engine.py:1363`,
`path_graph.py:719-722`, `main.py:3899` = the `EvidenceItem` construction,
`evidence_plane.py:135/231` = the item + its heap tuple). The queue's marginal is
**snapshot payload**, not queue overhead.

---

## 4. Per-EvidenceItem: true marginal vs `est_bytes`

Measured at `drained` (the point the gate reads, working set whole).

| pin | instrument | total | **B/item** | vs marginal |
|--:|---|--:|--:|--:|
| 5,000 | **true MARGINAL** (excl. of the working set) | 39,517,568 | **7,904** | 1.00× |
| 5,000 | **STANDALONE** (nothing else holding it) | 149,249,393 | **29,850** | **3.78×** |
| 5,000 | `evidence_plane.estimate_bytes` | 112,296,448 | **22,459** | **2.84×** |
| 2,000 | true MARGINAL | 10,123,895 | **5,062** | 1.00× |
| 2,000 | STANDALONE | 57,910,504 | **28,955** | **5.72×** |
| 2,000 | `estimate_bytes` | 32,171,776 | **16,086** | **3.18×** |
| 3,739¹ | true MARGINAL | 18,462,281 | **4,938** | 1.00× |
| 3,739¹ | STANDALONE | 127,913,508 | **34,211** | 6.93× |
| 3,739¹ | `estimate_bytes` | 54,254,336 | **14,510** | 2.94× |

¹ the pin-5000 leg at `input_stopped`, where the queue had not yet filled.

Three facts fall straight out:

* **The estimator over-charges the marginal by ~3×** (2.84–3.18×) — the same
  *direction* the `RankMemo` estimator was wrong in before `a75b73f8`.
* **…and under-charges the worst case by ~25 %** (22.5 vs 29.9 KiB/item at
  pin 5,000; 16.1 vs 29.0 at pin 2,000). It is wrong in *both* directions
  depending on which question you ask it, because it models neither.
* **The measured STANDALONE cost is near-constant at ~29 KiB/item** (28,955 /
  29,850 / 34,211 across three shapes) while the estimator swings 14.5 → 22.5
  KiB/item with component size. The estimator's per-node / per-edge scaling does
  not track anything real; the dominant cost is **per-VERSION** (the snapshot's
  ranking, hypotheses and verdict payload), not per-node.

### Where the estimate goes, decomposed (400 items sampled, pin 5,000, `drained`)

| term | measured | estimator charges |
|---|--:|--:|
| nodes/item | 5.67 | 11.3 KiB (`2048 B` each) |
| edges/item | 11.46 | 8.6 KiB (`768 B` each) |
| slice signals/item | 6.08 | 6.1 KiB (`1024 B` each) |
| item overhead | — | 0.5 KiB |

---

## 5. How much of a pinned queue is genuinely NEW retention?

Measured directly by the `ws-first` probe order — drop the working set, keep the
queue, and read what the queue then holds alone.

| pin 5,000, `drained` | MiB | share |
|---|--:|--:|
| total reachable from the queue (STANDALONE) | **142.34** | 100 % |
| — references to objects the working set already holds | **104.65** | **73.5 %** |
| — **genuinely NEW retention** (true marginal) | **37.69** | **26.5 %** |
| the same queue after the working set is dropped | **142.15** | (it holds *all* of it) |

**What the new 26.5 % is made of** (400 items sampled at `drained`):

| | value |
|---|--:|
| items whose `snap` is *also* in `OPEN_OBJECTS` (free) | **180 / 400 = 45.0 %** |
| items holding a **SUPERSEDED or CLOSED** snapshot (item is the only holder) | **220 / 400 = 55.0 %** |
| duplicate snapshot refs inside the queue | 0 |
| slice signals already held by the item's **own snapshot nodes** | **100.0 %** |
| slice signals still in `WINDOW_BUFFER` | 0.0 % |
| **slice signals the item alone holds ("loose")** | **0.0 %** |

So, offline: **all** of the queue's new retention is **superseded/closed
`ObjectSnapshot` payload**, and **none** of it is loose archive-slice signals. The
`slice_sigs` list is, in this fixture, **100 % a second reference to signals the
item's own snapshot already holds** — every one of the 6.1 KiB/item the estimator
charges for it is a pure double count.

And the sharing is a **runtime condition, not a property of the item**: at
pin 2,000 it is 56 % shared, at pin 5,000 45 %, and after the working set drops it
is 0 %. The deeper (or the longer-lived) the queue, the more of it converts from
"free reference" to "sole owner". That is the whole reason the bound cannot be
denominated in the marginal (§6).

---

## 6. Recommendation

### 6a. The bounds

| knob | today | **recommend** | why |
|---|--:|--:|---|
| `CORR_EVIDENCE_QUEUE_MAX` | 5,000 | **2,000** | 2,000 items **measured** at 55.2 MiB standalone / 9.65 MiB marginal — under the 64 MiB budget with margin, and directly measured rather than extrapolated. 5,000 items measure **142.3 MiB standalone**, 2.2× the budget. |
| `CORR_EVIDENCE_QUEUE_BYTES_MAX` | 512 MiB | **64 MiB** | Today's bound is **inert**: 512 MiB ÷ 22.5 KiB/item ≈ 23,900 items, so it can never bind before the item bound — confirmed live (5,000 items / 101 MiB, byte bound never approached). At the measured ~29 KiB/item, 64 MiB binds at ≈ 2,200 items, i.e. the two bounds agree by design and either can hold the line. |

The budget must be sized against the **standalone** number, not the marginal:
whether an item's snapshot is also held by `OPEN_OBJECTS` is decided by whether
that object is still open, which is exactly what stops being true during the
`memflat` window (input stopped → objects quiesce and close → the queue becomes
the sole holder). The `ws-first` probe measures that state directly: the same
5,000 items that cost 37.7 MiB marginal cost **142.15 MiB** once the objects close.
A bound sized on 7.9 KiB/item would be correct right up to the moment it matters.

At 2,000 items on the 1.25 GiB container: **≤ 55 MiB worst case (4.3 % of the
limit), ~10 MiB typical.**

**Named trade-off.** A tighter bound converts memory pressure into Decision-plane
latency via blocking backpressure. Offline the pin-2,000 leg counted 2,587
backpressure events vs 337 at pin 5,000 — but those counts are an **artifact of
the parked mode** (the pinning consumer deliberately refuses to drain below the
pin), not a prediction. With a healthy consumer the queue should never sit at the
bound; the bound is a backstop. Watch `corr_evidence_backpressure_total` and
`lag_seconds` against the TTUR SLOs after the change.

**The bound is not the fix.** The hold-leak that parked the consumer is worth
**+22.9 MiB of post-input growth and +39.4 MiB of level** offline — more than any
bound change. Fix the consumer first; then the bound only has to survive a storm,
not a defect.

### 6b. Does `estimate_bytes` need the `rank_memo` calibration? **Yes — with one rule inverted.**

`rank_memo.estimate_result_bytes` got three corrections at `a75b73f8`: an id-`seen`
walk, a catalog-ownership zero, and the per-instance `__dict__`. The Evidence
estimator needs the analogues, plus a structural fix:

1. **Remove the double charge (equivalent of the id-`seen` walk) — required.**
   `slice_sigs` contains every signal of every component node (see
   `main._archive_slice`), and those bytes are already in the node term *and* in
   the snapshot. Measured: **100 % of slice signals** are node-owned. The fix
   needs no walk — the Decision plane already has both lists:
   `n_loose = len(slice_sigs) - sum(len(n.signals) for n in snap.nodes)`, O(nodes),
   computed where `est_bytes` is set in `_persist_snapshot`. Charge only `n_loose`.
2. **Catalog / process-lifetime ownership → charge zero.** Same rule and same
   `_owned_ids` machinery as the rank memo: catalog template objects, shared/seam
   token groundings and the signal interns reachable from a snapshot outlive every
   item, so evicting the item frees none of them.
3. **`OPEN_OBJECTS` ownership → do NOT discount.** This is where the Evidence
   estimator must *differ* from the rank memo's. The catalog is a safe zero
   because it outlives every memo entry; a live open object is **not** — it can
   close while its item is queued, converting a "free" reference into sole
   ownership (measured: 45 % shared at pin 5,000 → 0 % after the objects close).
   `est_bytes` must therefore be a **standalone** figure, and the queue's `bytes`
   bound a **conservative** one.
4. **Re-shape the model, don't just re-tune the constants.** Measured standalone
   is ~29 KiB/item and near-constant across 3.1 → 5.7 nodes and 7.3 → 11.5 edges,
   while the current three-constant formula swings 14.5 → 22.5 KiB/item. Replace
   `_BYTES_PER_NODE`/`_BYTES_PER_EDGE`/`_BYTES_PER_SLICE_SIGNAL` with a calibrated
   **per-version constant** (the snapshot's ranking + hypotheses + verdict payload,
   which dominates) plus a **loose-slice-signal** term, calibrated by the same
   procedure that calibrated the rank memo — which this patch now provides:
   `--evidence parked --evidence-pin N --evidence-probe-order ws-first`.

After (1)–(4), `corr_evidence_queue_bytes` becomes a number a 64 MiB bound can be
written against; until then, **the 2,000-item bound is the one that must hold.**

---

## 7. What this offline shape does NOT reproduce from live

Beyond the caveats already in `P2_MEMFLAT_ATTRIBUTION_2026-08-29.md` §6 (no Kafka
client buffers, no httpx/ClickHouse pools or TLS buffers, no aiohttp sidecar, no
glibc arena fragmentation under the loop+executor pattern — persistence is a
counting stub), specific to this measurement:

1. **No loose archive-slice signals exist in the fixture at all.** `_archive_slice`
   adds `*_clear` and `source=app_identity` signals plus matched identity signals;
   `EVENT_MIX_REALISTIC` emits **none** of those kinds. So the "loose signals the
   item alone holds" term measured **0.0 %** here — it is *structurally absent*,
   not *measured small*. On a live estate with clears and app-identity enrichment
   this term is > 0 and adds to the marginal. The recommended bounds are
   correspondingly a floor, and item (1) of §6b (charge only loose signals) is the
   change that makes the estimate track it.
2. **The window never prunes.** Stream time is frozen during the drain, so
   `_prune_buffer` expires nothing and `WINDOW_BUFFER` keeps every loose signal
   alive. Live, the window prunes while the queue holds — which converts
   `WINDOW_BUFFER`-held signals into queue-only retention. Offline that conversion
   cannot happen; measured "still in `WINDOW_BUFFER`" was 0.0 % only because there
   were no loose signals at all.
3. **Scale.** 600 devices / 2,899 open objects / 264–304 MiB RSS vs 2,500 devices /
   728 MiB. The per-item numbers transfer (the `est_bytes`/item shape matches live
   to 6 %); the MiB totals do not. Offline the pinned queue is 50 % of post-input
   owner growth; whether it is the same share of the live +225 MiB is an
   extrapolation, not a measurement.
4. **The parked consumer is a memory model, not the live defect.** It ignores the
   cohort hold and drains only above the pin, so its ordering, backpressure counts
   and unwritten-row counts are artifacts. It reproduces the live *retention*
   shape (5,000 items, ~101–107 MiB `est_bytes`), not the live hold-leak.
5. **`--tracemalloc` legs cannot be read for RSS.** Tracing inflates RSS by
   hundreds of MiB (538 MiB at `drained` on the pin-2,000 tm leg vs 304 MiB
   untraced). Those legs exist only for the line attribution and the cross-check.

---

## 8. Files

* Patch (apply after the other builder is done):
  `bench_memflat_evidence.patch` — against `a75b73f8`,
  `NetOps_Observability/src/correlation/bench_memflat_p2.py` only.
  Adds: `--evidence {keepup,parked,inline}`, `--evidence-pin/-slack/-items-max/
  -bytes-max/-sample`, `--evidence-probe-order {queue-first,ws-first}`, the pinning
  consumer, the `evidence_queue` owner (walked last, inclusive + exclusive), the
  per-item composition walk, the `evidence_dropped` probe, and the
  `EVIDENCE PLANE per-item` report section. No engine/`main.py` file is touched.
* Raw run outputs + JSON: `out/{light,full}_{keepup,parked,parked_2000,parked_wsfirst}.{txt,json}`,
  `out/tm_parked.{txt,json}`.
