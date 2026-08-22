# The bottleneck moved again — archive persistence, not scoring

**Date:** 2026-08-22 · **Run:** `082201589waa` · **Overall: FAIL**
**Change under test:** the `run_window` cache fixes (`Catalog.version_hash` and
`_inapplicable_score` memoisation, identity-keyed) — offline **495.86 s →
186.63 s, 2.66×**.

---

## The result

| | post-167 run (`08212335gjeg`) | post-optimisation run (`082201589waa`) |
|---|---:|---:|
| `run_window` (offline, same shape) | 495.86 s | **186.63 s** |
| `epoch_seconds_max` (live) | 582 / 1,334 s | **221 / 230 s** |
| Kafka transport drain | 41 s | **24 s** |
| **cohorts advanced in budget** | 4 | **2** |
| **pending at budget** | 95,618 | **129,220** |
| pending trajectory | rose, then fell via expiry | **completely flat for all 2,160 s** |

**The engine got 2.66× faster at `run_window` and completed fewer cohorts.**
That is not a contradiction — it is the bottleneck moving, and it is the third
time this programme has seen it.

Pending sat at exactly **129,220 for the entire 36-minute gate window**. Not one
signal committed. The engine spent the whole budget inside a single cohort.

## Where the time actually goes now

ClickHouse `system.query_log`, correlation inserts over a 600 s window during the
stall:

| table | inserts | p50 | p95 | **total time** |
|---|---:|---:|---:|---:|
| **`netops.corr_signals_archive`** | **1,130** | **152 ms** | 228 ms | **222.4 s** |
| `netops.corr_current` | 283 | 7 ms | 21 ms | 2.7 s |
| `netops.corr_edges` | 282 | 8 ms | 20 ms | 2.6 s |
| `netops.corr_evidence` | 282 | 7 ms | 22 ms | 2.5 s |
| `netops.corr_objects` | 282 | 7 ms | 15 ms | 2.2 s |

**The archive slice is 98.6 % of all correlation persistence time.**

Object persistence rate: **0.47 objects/sec**. Roughly **4 archive inserts per
object at ~152 ms each** — ~608 ms per object, against ~28 ms for every other
table combined.

Observed slice sizes from the loss warnings: `row_count=8461`, `row_count=8904`.
**Each RCA object archives a slice of ~8,500 rows.**

## Why this is the same story as before, a third time

This is tracker **156**'s residual on-loop `_archive_slice`, whose own tracker
row records the defect precisely:

> `_archive_slice` and its `slice_hash` still run ON the loop and are sized by
> the whole 50k-floor WINDOW rather than by the object — so they do not shrink
> when objects do.

It was assessed then as *"bounded and safe today"*, and it was — because
**pre-168 there was ONE object**, so the window-sized slice was written once.

Tracker 168 corrected the identity defect, which multiplied RCA objects from ~1
to ~1,600. Every per-object cost then became the bottleneck in turn:

1. **template scoring** — 100 templates × every object → fixed by 167
2. **catalog version hashing** — re-serialising the catalog per object → fixed
3. **archive persistence** — a ~8,500-row window-sized slice per object → **now**

At ~1,600 objects that is **~13.6 M archive rows per cohort**, serialised, on the
event loop. At 0.47 objects/s a single cohort needs ~3,400 s — longer than the
entire qualification budget. That is exactly what the flat pending line shows.

## Secondary finding — a ClickHouse timeout discards a whole cohort

Observed once per replica, but structurally important:

```
ch_insert("netops.corr_objects") → ReadTimeout → CHInsertRejected
  → propagates out of _persist_snapshot
  → out of _engine_cycle_inner (main.py:3466)
  → caught only by engine_loop's blanket handler
  → _mark_processed(_cohort) never runs
  → the cohort's entire evaluation is discarded and retried whole
```

The retry-whole behaviour is tracker 166's durability contract working as
designed. What the design did not anticipate is that the cost of one failure is
now an entire cohort's work, and that the probability of at least one insert
timing out scales with the number of objects in the cohort:
**P(cohort commits) = (1 − p)^objects.**

ClickHouse-side `corr_objects` insert latency reached **14,395 ms** max, so the
client timeout is not hypothetical. This did not dominate this run — only one
abort per replica was logged — but it is a real robustness defect that gets
worse as object count grows, and it should be fixed alongside the archive cost,
not after it.

**Correction to an earlier reading in this session:** I first described this as a
livelock in which every cohort aborts. The log counts refute that — one
`engine cycle failed` per replica. The dominant cause is archive persistence
throughput, not repeated aborts.

## Status

Unchanged by this run except where noted:

* **165 = PASS** · **168 = PASS** · **170 = PASS** (failed the run correctly,
  twice now) · **169 = OPEN** · **171 = OPEN non-blocking**
* **167 = PASS offline**, live-deployed, live selectivity still unvalidated
  (single-kind workload)
* **166 = FAIL** — and the classification changes from *"stable but insufficient
  throughput"* to **"cannot complete a single cohort within budget; blocked on
  per-object archive persistence."**
* 1280 MiB floor **unchanged** (memflat PASSED this run, 8/8 containers)
* mini-ladder **BLOCKED** · 72h soak **BLOCKED**

## Next action

**Fix the archive write amplification (tracker 156's residual), then re-run.**

The target is specific and measured: each RCA object writes a window-sized
(~8,500-row) archive slice, 98.6 % of persistence time, at 0.47 objects/s. The
slice should be sized by the OBJECT, not by the window — which is what tracker
156 said in the first place, before 168 made it load-bearing.

Do not optimise `run_window` further. It is now 2.5 % of the cycle's problem.
