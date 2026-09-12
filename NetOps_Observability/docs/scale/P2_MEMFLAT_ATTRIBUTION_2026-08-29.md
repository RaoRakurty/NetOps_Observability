# P2 `memflat` attribution — offline, measured

**Date** 2026-08-29 · **Code** `b29d34ea` (pristine git worktree; see *Provenance*)
**Tool** `src/correlation/bench_memflat_p2.py` (new; drives the real engine sweep,
mocked persistence, reuses `bench_profile_p2`'s fixture) · **Suite** 1852 passed,
9 skipped.

**Question.** After P2 steps 0–2 the live 2.5K run's `memflat` gate failed: replica
RSS 494 → 753 MiB (×1.53 > ×1.3) *after input stopped*, with ~21k signals still
pending. How much of that post-input growth is (a) working set, (b) the new P2
caches, (c) unexplained / leak?

**Answer in one line.** In the offline shape the post-input growth is **entirely
accounted for by named, live, reclaimable objects** — no leak signature — and it
splits roughly **60 % new caches (dominated by the RankMemo) / 40 % working set**;
the caches move the *level* far more than the *ratio*, and the single number the
live gate should be checked against is **`corr_rank_memo_entries` × ~10–13 KiB per
entry**.

---

## 1. What was run

Fixture: `bench_profile_p2.make_signals` — the real syslog producer over the
ratified `EVENT_MIX_REALISTIC`, `burst=6`, storm-declared epoch, deterministic (no
RNG), persistence mocked (`MockCH` counts rows, retains nothing).

Sweep shape = the live memflat window:

| phase | what |
|---|---|
| arrivals | 3 epochs, each preceded by 4,000 new signals, each draining 2 cohorts of 1,200 — input flowing, engine behind |
| **snapshot `input_stopped`** | ← the live gate's t0 (494 MiB) |
| drain | epochs with **no arrivals** until `epoch.pending()` == 0. Stream time is frozen so `_prune_buffer` expires nothing — the live shape exactly |
| **snapshot `drained`** | ← the live gate's t1 (753 MiB) |
| **snapshot `memo_cleared`** | `RankMemo.clear()` + clause-cache clear + `gc.collect()` |
| **snapshot `working_set_dropped`** | `OPEN_OBJECTS` / window / id-sets cleared + `gc.collect()` |

Scale (scaled down from live, and said so): 600 devices, 12,000 signals, window
10,920, **1,904 open objects**, 3,759 versions persisted, 70,824 rows — about
**~1/3 of the live estate, ~0.4x its RSS level and ~1/29 of its post-input RSS delta**. Four legs,
one image, env-only A/B (every knob is read once at import):

| leg | flags |
|---|---|
| `on` | defaults — all P2 caches on |
| `memo_off` | `CORR_RANK_MEMO=0` |
| `all_off` | `CORR_RANK_MEMO=0 CORR_BLOB_CYCLE_CACHE=0 CORR_CLAUSE_KINDS_CACHE=0 CORR_SIGNAL_ID_CACHE=0` |
| `deep_backlog` | defaults, but 1 cohort/epoch → 8,400 pending at input stop, **7 drain epochs** (tests whether growth tracks drain *work*) |

Byte-for-byte identical outcomes across `on` / `memo_off` / `all_off` (3,759
versions, 70,824 rows) — the caches changed retention and speed, nothing else.

### A measurement trap, named because it inverted the first answer
The deep-size walker keeps one id per live object; at this scale that `seen` set
is **~32 MiB**, and it leaves that much arena behind for the *next* RSS reading to
score as engine growth. The first pass therefore read "+36 MiB post-input, 76 %
unexplained". It was the tool. `bench_memflat_p2.py --light` measures RSS + counts
only; **the RSS curve below comes from `--light` runs and the byte attribution from
full runs**, and the two are never mixed. (Same reason the `set`-bytes row of the
gc census is not reported.)

---

## 2. RSS — the number the gate reads (`--light`, no walker pollution)

| leg | start | input_stopped | drained | **Δ post-input** | **ratio** | memo_cleared | working_set_dropped |
|---|--:|--:|--:|--:|--:|--:|--:|
| `on` | 64.2 | 209.9 | 218.9 | **+9.0** | **1.043** | 218.9 | 171.0 |
| `memo_off` | 64.2 | 182.5 | 188.5 | **+6.0** | **1.033** | 188.5 | 161.7 |
| `all_off` | 64.2 | 177.0 | 182.7 | **+5.7** | **1.032** | 182.7 | 152.3 |
| `deep_backlog` (on) | 64.2 | 185.9 | 206.5 | **+20.6** | **1.111** | 205.5 | 167.6 |

(MiB, VmRSS. VmHWM tracks VmRSS within 1.0 MiB in every light leg — there is no
hidden transient peak; the 355 MiB HWM the first pass reported was the walker.)

Three readings:

1. **The P2 caches cost ~33 MiB of LEVEL at this scale** (209.9 vs 177.0 at input
   stop) — 27.4 MiB of it the rank memo — but only **~3 MiB of the post-input
   GROWTH** (+9.0 vs +5.7). The gate measures the ratio, and the ratio is
   1.043/1.033/1.032: the caches are **not** what failed it.
2. **Growth tracks drain WORK, not time.** Same estate, same retained set, 7 drain
   epochs instead of 2 → +20.6 MiB instead of +9.0. Every drain cohort
   materializes components that were never materialized while input flowed; the
   backlog *is* the growth.
3. **The offline shape reproduces the direction, not the magnitude**: ×1.043 here
   vs ×1.53 live. Do not read these MiB as the live MiB (§6).

---

## 3. Where the bytes are — deep, exclusive, per owner

Deep bytes reachable from each named root, **each object charged once**, owners
walked working-set-first so anything the memo shares with a live `ObjectSnapshot`
is charged to the working set. The memo's number is therefore its **true marginal
retention**. Cross-check: `tracemalloc`'s filtered `input_stopped → drained` delta
sums to **+8.61 MiB**, against the owner table's **+8.62 MiB** — two independent
instruments, same answer.

### leg `on` (all caches on) — MiB

| owner | start | input_stopped | drained | **Δ drain** | memo_cleared | ws_dropped |
|---|--:|--:|--:|--:|--:|--:|
| `OPEN_OBJECTS` (working set) | 0.00 | 64.04 | 66.72 | **+2.69** | 66.72 | 0.00 |
| `WINDOW_BUFFER` | 0.00 | 2.86 | 2.86 | +0.00 | 2.86 | 0.00 |
| `_PROCESSED_IDS` | 0.00 | 1.08 | 1.39 | +0.30 | 1.39 | 0.00 |
| `_BUFFERED_IDS` + order | 0.00 | 1.47 | 1.47 | +0.00 | 1.47 | 0.00 |
| `_ARCHIVE_SLICE_HASH` | 0.00 | 0.19 | 0.19 | +0.00 | 0.19 | 0.00 |
| `_TENANT_EDGES` | 0.00 | 0.78 | 1.04 | +0.26 | 1.04 | 0.00 |
| signal interns (pre-P2) | 0.00 | 0.09 | 0.09 | +0.00 | 0.09 | 0.24 |
| catalog + plan caches | 0.83 | 0.91 | 0.91 | +0.00 | 0.91 | 0.95 |
| **`RankMemo` (P2 step 2)** | 0.00 | **42.93** | **46.87** | **+3.94** | 0.00 | 0.00 |
| **`Clause.kinds` cache (P2 step 0)** | 0.10 | 1.14 | 2.56 | **+1.43** | 0.00 | 0.00 |
| **`signal_id` cache (P2 step 0)** | 0.00 | 3.37 | 3.37 | +0.00 | 3.37 | 0.00 |
| blob cycle cache (P2 step 0) | 0 | 0 | 0 | 0 | 0 | 0 |
| **TOTAL live** | **0.93** | **118.87** | **127.49** | **+8.62** | **78.05** | **1.19** |

`blob_cycle_cache` is 0 at every point by construction — it is opened by
`engine_cycle` and dropped in its `finally`, so it can only be non-zero *inside* a
cycle (bound 64 entries).

### the same table, other legs (drained column, MiB)

| owner | `on` | `memo_off` | `all_off` | `deep_backlog` |
|---|--:|--:|--:|--:|
| `OPEN_OBJECTS` | 66.72 | 66.72 | 65.94 | 69.10 |
| `RankMemo` | 46.87 | — | — | 32.41 |
| `Clause.kinds` cache | 2.56 | 2.55 | — | 2.81 |
| `signal_id` cache | 3.37 | 3.37 | — | 3.37 |
| other working set | 7.95 | 7.95 | 7.69 | 8.48 |
| **TOTAL live** | **127.49** | **80.60** | **73.64** | **116.17** |
| **Δ live over the drain** | **+8.62** | +1.35¹ | +3.26 | **+18.09** |

¹ `memo_off` reads low only because its clause cache hit the 4,096 bound and
self-cleared mid-drain (4.45 → 2.55 MiB); its working-set growth is the same
+3.26 MiB as everywhere else.

### post-input growth, attributed (leg `on` / leg `deep_backlog`)

| bucket | `on` | share | `deep_backlog` | share |
|---|--:|--:|--:|--:|
| (b) caches — RankMemo | +3.94 | 44 % | +11.88 | 58 % |
| (b) caches — Clause.kinds | +1.43 | 16 % | −0.07 | 0 % |
| (a) working set — OPEN_OBJECTS | +2.69 | 30 % | +4.16 | 20 % |
| (a) working set — ids / tenant edges | +0.56 | 6 % | +2.11 | 10 % |
| **(a)+(b) live, named** | **+8.62** | **96 %** | **+18.09** | **88 %** |
| **(c) unexplained** (RSS Δ − live Δ) | **+0.4** | **4 %** | **+2.5** | **12 %** |

The (c) residual is ≤ 5 MiB in every leg, does not grow with drain length, and is
consistent with pymalloc/glibc keeping freed arenas (it *shrinks* in the legs where
a cache self-cleared). **No leak signature.**

### live-object census (counts; `on`)

| type | start | input_stopped | drained | memo_cleared | ws_dropped |
|---|--:|--:|--:|--:|--:|
| `ObjectSnapshot` | 0 | 1,904 | 1,904 | 1,904 | 0 |
| `RankingResult` | 0 | 3,531 | 3,664 | **1,904** | 0 |
| `HypothesisScore` | 0 | 44,374 | 46,366 | **23,024** | 100 |
| `Node` | 0 | 4,541 | 4,926 | 4,926 | 0 |
| `Edge` | 0 | 7,078 | 9,680 | 9,680 | 0 |
| `Signal` | 0 | 10,920 | 10,920 | 10,920 | 0 |
| `frozenset` | 1,338 | 179,431 | 188,699 | **92,936** | 1,240 |

Clearing the memo halves the `RankingResult`, `HypothesisScore` and `frozenset`
populations — i.e. **the memo is the second copy of the verdict graph**, and it is
the `frozenset`/`dict` payload inside `HypothesisScore`/`Verdict`, not the
`RankingResult` header, that carries the bytes.

---

## 4. Reclaimable cache, or leak?

**Reclaimable. Completely.**

| step (`on`) | live heap (deep, MiB) | RSS (MiB, light) |
|---|--:|--:|
| drained | 127.49 | 218.9 |
| after `RankMemo.clear()` + clause clear + `gc.collect()` | **78.05** (−49.4) | 218.9 (**unchanged**) |
| after also dropping `OPEN_OBJECTS` / window / id-sets | **1.19** (−76.9) | 171.0 (−47.9) |
| baseline at `start` | 0.93 | 64.2 |

* Every byte the memo holds is released by `clear()` — 49.4 MiB of live objects,
  100 % of the memo's charged 46.87 MiB plus the clause cache's 2.56 MiB. Nothing
  survives, no reference cycle keeps it, `_close_epoch` needs no help.
* **RSS does not follow.** Freeing 49.4 MiB moved RSS by 0.0 MiB, and after the
  working set went too, the heap was back to its 0.93 MiB baseline while RSS sat
  107 MiB above its own. That is allocator arena retention, not a leak — but it is
  the operationally important half: **clearing the memo in a running replica will
  not lower RSS**; it only lowers the ceiling for further growth.

---

## 5. Two side findings worth a tracker row

1. **`RankMemo` entries are not small: ~10–13 KiB each, marginal.** Clearing 3,663
   entries freed 46.87 MiB (12.8 KiB/entry); the `deep_backlog` leg gives 9.9
   KiB/entry over 3,359. Inclusive of objects shared with live snapshots it is 25.8
   KiB/entry (1,903 of 3,663 entries share their `RankingResult` with an open
   object — those are free; the rest are not). The module docstring's "the value is
   a `RankingResult` and nothing else — no snapshot, no nodes, no signals" is true
   and still leaves `hypotheses` → `HypothesisScore` → `Verdict` → matched-kind
   frozensets. **At the `CORR_RANK_MEMO_MAX=50000` bound that is ~500–650 MiB of
   RSS the process is licensed to hold**, on a box whose whole budget is smaller.
   The bound was sized in entries as though entries were cheap; it wants sizing in
   bytes, or a much lower entry cap (5,000 entries ≈ 50–65 MiB).
2. **The `Clause.kinds` identity cache pins ephemeral clauses it can never serve.**
   `scoring.py:263` and `scoring.py:378` construct a fresh `Clause(kind=st.witness)`
   on every call; the cache is keyed by `id(clause)` and stores a **strong ref**, so
   those entries can never hit (new object each call) and are pinned until the
   4,096-entry bound clears the whole dict. Measured: at `drained` the cache held
   **2,292 Clause objects that the catalog does not own** (the catalog has 426), for
   2.56 MiB, and `memo_off` shows it filling to 4,095 and self-clearing mid-drain.
   Bounded and harmless in magnitude — but it is the only owner in the table whose
   contents are pure waste. The cache itself is excellent where it applies
   (`computed` 31,067 vs `cached` 2,663,744 = 98.8 %; with it off the same sweep
   computes 5,072,921 times), so the fix is to skip caching at those two call sites
   (or hoist the `Clause` to module scope), not to disable it.

---

## 6. What this offline shape does NOT reproduce

* **The real process's RSS.** No Kafka client (fetch buffers, per-partition
  prefetch, the 50k-record window's serialized backlog), no httpx/ClickHouse
  connection pools or TLS buffers, no aiohttp health sidecar, no asyncio task/timer
  churn, no glibc multi-arena fragmentation from the loop+executor thread pair.
  Persistence is a counting stub: **row building is real, the insert is not**, so
  the live sink's queue depth, retry buffers and DLQ are absent — and those are
  exactly the structures that grow while a backlog drains.
* **Magnitude and estate.** 1,904 open objects vs a live run that runs against
  `CORR_OPEN_OBJECTS_MAX=5000` with force-close churn; 10,920-signal window vs
  ~50,000; ×1.043 post-input vs ×1.53. The *ordering* of owners transfers; the MiB
  do not.
* **Multi-tenant and catalog reload.** One tenant, one catalog version for the
  whole run, so neither the per-tenant memo key fan-out nor a version-churn memo
  (old keys aging out under LRU) is exercised.
* **Time.** The live gate's t0→t1 spans minutes of wall clock with idle-tenant
  eviction and quiesce timers armed; here the drain is seconds and neither fires.

### The one live measurement that would close this
The memo is the only named owner whose post-input growth is large, unbounded by
anything but a 50,000-entry cap, and *proportional to drain work*. If the live
`memflat` window's `corr_rank_memo_entries` gauge grew by **N** entries between t0
and t1, then N × 10–13 KiB is the memo's share of the 259 MiB. N ≈ 20,000–26,000
would explain the failure outright; N ≈ 2,000 would exonerate it and point at the
sink/broker buffers this bench cannot see. That gauge is already on `/metrics`
(`main.py:7925`) — no new code needed.

---

## 7. Verdict

**Cache and working set, in that order — not a leak.** In the offline reproduction
the post-input RSS growth is +9.0 MiB (×1.043) and **96 % of it is named, live,
reclaimable objects**: the level-1 `RankMemo` +3.94 MiB (44 %), the `Clause.kinds`
cache +1.43 MiB (16 %), `OPEN_OBJECTS` +2.69 MiB (30 %) and the id/edge bookkeeping
+0.56 MiB (6 %), leaving +0.4 MiB (4 %) unexplained — a residual that does not grow
with drain length and disappears into allocator arena accounting. Lengthening the
drain from 2 to 7 epochs raises the growth to +20.6 MiB with the same estate, of
which the memo is 58 % — the growth tracks **drain work**, because every drained
cohort materializes components the arrival phase never reached, and each one mints
a memo entry. The P2 caches are therefore **not the cause of the gate's failure**
(off, the ratio is 1.032 vs 1.043 on — a 0.011 difference against a 0.3 threshold)
but they are **the largest single contributor to the growth that does occur**, and
they raise the absolute floor by ~33 MiB at 1/5 of live scale. Everything is
reclaimable — `RankMemo.clear()` released 100 % of its 46.9 MiB and the whole heap
returned to its 0.93 MiB baseline — but RSS did not follow (218.9 MiB before and
after the clear), so the live gate's ×1.53 cannot be fixed by dropping caches at
runtime; it has to be prevented by not minting the bytes. The actionable number is
**10–13 KiB per memo entry against a 50,000-entry bound = 500–650 MiB of licensed
RSS**, which the live `corr_rank_memo_entries` delta over the memflat window will
confirm or refute in one query.

---

## Provenance / how to re-run

The repo working tree was being edited by another agent mid-session
(`src/correlation/main.py`, `evidence_plane.py`), so every leg was run in a
detached worktree pinned to `b29d34ea`:

```bash
git worktree add -f --detach /tmp/.../head-wt b29d34ea
cd /tmp/.../head-wt/NetOps_Observability/src/correlation
ARGS="--devices 600 --signals 4000 --arrival-epochs 3 --cohorts 2 --cohort-size 1200"
python3 bench_memflat_p2.py $ARGS --light --label on          # RSS curve
python3 bench_memflat_p2.py $ARGS        --label on           # byte attribution
CORR_RANK_MEMO=0 python3 bench_memflat_p2.py $ARGS --light --label memo_off
CORR_RANK_MEMO=0 CORR_BLOB_CYCLE_CACHE=0 CORR_CLAUSE_KINDS_CACHE=0 \
  CORR_SIGNAL_ID_CACHE=0 python3 bench_memflat_p2.py $ARGS --light --label all_off
python3 bench_memflat_p2.py $ARGS --cohorts 1 --max-drain-epochs 12 --label deep_backlog
python3 bench_memflat_p2.py $ARGS --tracemalloc --tm-frames 1 --label on_tm
```

Raw JSON/text per leg is beside this file (`l_*.json` = light, `h_*.json` = full,
`on_tm.txt` = tracemalloc). Script: `src/correlation/bench_memflat_p2.py` (new,
untracked, ~560 lines, read-only w.r.t. the engine — no engine/main/signals/catalog
file was modified). Total CPU ≈ 22 min including the tracemalloc leg and two full
`pytest src/correlation` runs.
