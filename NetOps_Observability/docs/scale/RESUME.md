# CORRELIX GA qualification — resume brief

**Read this first when picking the work back up.** One page of orientation, then
the paste-ready prompt at the bottom.

Last updated: 2026-08-22 · branch `feat/observability-platform`

---

## The 30-second version

Two correctness defects were found and fixed and are **live-qualified**: tracker
**168** (a device-local interface name acting as a global correlation identity,
which welded the entire estate into one RCA object) and tracker **170** (the
qualification harness reporting PASS while the engine had evaluated 3 % of the
workload). The harness now tells the truth, and the truth is that **tracker 166
still FAILs**: the engine cannot evaluate the 1K workload inside the
qualification budget.

The bottleneck has moved **four times**, each time to a per-object cost that was
invisible when 168's weld produced a single object. The current one is measured
and specific: **`_archive_slice` writes a ~8,500-row, window-sized slice per RCA
object — 98.6 % of all correlation persistence time, 0.47 objects/sec.**

## Where the bodies are buried

| Tracker | State | Notes |
|---|---|---|
| 165 retention | **PASS — frozen** | 516.527 s is a correctness contract, not a tunable |
| 168 identity scope | **PASS — live-qualified** | 2,586 objects audited, 0 multi-device welds. Do not weaken either defence layer |
| 170 completion gate | **PASS — validated live twice** | it failed both post-168 runs correctly |
| 167 template index | **PASS offline**, live-deployed | live selectivity **NOT** validated — the harness is single-kind |
| **166 scheduler** | **FAIL** | *cannot complete one cohort in budget*; blocked on archive persistence |
| 171 maintenance | OPEN, non-blocking | worst prune gap 1,363 s vs ~180 s intended; catch-up always succeeded |
| 169 CI | **OPEN — merge blocker** | see below; re-pinned 2026-08-22, currently green |
| 156 archive slice | **now the blocker** | its own row predicted this: "sized by the whole WINDOW rather than by the object" |
| 72h soak | **BLOCKED** | |

## The one thing to understand before touching anything

Every bottleneck so far has been the same defect in a different place: **work
performed per RCA object whose size is set by something global — the catalog,
the window — rather than by the object.**

1. `build_edges` candidate explosion → fixed by **168**
2. 100 templates scored per object → fixed by **167**
3. `Catalog.version_hash` re-serialising the catalog per object (48.6 % of a
   cycle) → fixed 2026-08-22
4. **`_archive_slice` writing a window-sized slice per object → CURRENT**

Pre-168 there was one object, so all four were harmless. 168 corrected the
identity model, the real shape is ~1,000 small objects, and each of these became
O(objects × global) in turn.

**Do not point-fix #4 and re-run.** An architectural review was recommended and
not yet done — see the next section. Three waves have been spent discovering the
next bottleneck by running an hour-long qualification.

## Recommended next action: a narrow architectural review (3 questions)

1. **State and enforce the invariant** — "per-object work must be sized by the
   object, not the window or the catalog" — then audit every per-object path
   (object construction, content hashing, continuation, merge detection,
   attribution, archive slice) and table its true sizing. This says whether a
   fifth bottleneck is already waiting.
2. **Bounded cohorts × object formation.** Nodes not yet scored have no edges and
   can form singleton objects that are persisted, then merged later. Live it
   looks contained (~800 objects vs 1,000 devices, the severity open-floor
   filters most) but 166 and 156 were designed independently and their
   interaction has never been reviewed.
3. **Persistence model vs the new object shape.** ~8 ClickHouse inserts per
   object, serialised, on the event loop, at 0.47 objects/sec. Reasonable for a
   handful of large objects; never examined for a thousand small ones. Batching
   / offload / one archive write per cohort are all plausible — choosing is an
   architecture call, not an optimisation.

Then fix, then re-run. Not before.

## Measured numbers you will want

Latest run `082201589waa` (2026-08-22, 1000 devices / 12 min / 182 eps):

* Kafka transport drain **24 s** · devices **1000/1000** · injected **131,041**
* **cohorts advanced 2**, pending **129,220 and completely flat for all 2,160 s**
* `corr_signals_archive`: 1,130 inserts, p50 **152 ms**, **222.4 s of 232.4 s**
  total correlation insert time (**98.6 %**); every other corr table ~2.5 s
* object persistence **0.47/sec**; slice sizes observed **8,461** and **8,904** rows
* `epoch_seconds_max` **221 / 230 s** (was 3,956 s pre-167)
* RSS **338 / 328 MiB of 1280** · 0 CommitFailed / UnknownMember / restarts / rebalances
* offline `run_window` **495.86 → 186.63 s (2.66×)** from the cache fixes — and
  the run still got *worse* on the gate, because the bottleneck had moved

Secondary defect, real but not dominant (1 abort/replica): a ClickHouse
`ReadTimeout` raises `CHInsertRejected` out of `_persist_snapshot` past
`_mark_processed`, so the whole cohort is discarded and retried.
`P(cohort commits) = (1 − p)^objects`; CH-side insert latency reached 14,395 ms.

## Two things that are still unratified

* **The GA workload contract.** 182 eps at ~100 % promotion is a synthetic
  figure. The planner says 5,000 raw syslog EPS for 1,000 devices; the harness's
  own help text implies ~200. All current points are `CHARACTERIZATION ONLY`.
  See `docs/scale/GA_WORKLOAD_CONTRACT_1K.md`. **166's remaining PASS criteria
  are throughput criteria, so the target being unratified is a real blocker.**
* **166 mechanism vs 166 capacity.** Everything 166 built is proven live
  (preparation 3 per 17 epochs, cohorts bounded, frontier and edges bounded,
  memory flat). It stays FAIL only on throughput, which is 167's territory. The
  owner may want to split the row; it has been offered and not decided.

## Tracker 169 — read this before assuming CI is clean

`ingest-contract-ci` runs all of `tests/`. `test_error_swallow_guard.py` is
**line-keyed by design**, so inserting code above a reviewed handler makes it go
red until the handler is re-read and re-pinned. That happened on 2026-08-22
(tracker 170 inserted ~210 lines) and all five sites were re-read, confirmed
behaviourally unchanged, and re-pinned with a written justification. **That is
the intended workflow, not an exemption.** Never allowlist a NEW site to get
green, and never weaken the guard.

## Lab state

Stack is up on `compose.mem125.yml` (1280 MiB/replica, 2 replicas, BUS_PARTITIONS
4). Correlation image carries 166+167+168 plus the cache fixes. Last run's
cleanup deleted 1000 devices and purged CH+OS. A standing **~2 EPS** external
UDP/514 source is refused as `identity_unattributable`; it cannot contaminate
run-scoped accounting (DLQ is counted by runid grep and refusals withhold the
hostname).

---

## Paste-ready resume prompt

```
Continue CORRELIX GA qualification from the current branch.

DO NOT start the mini-ladder or the 72-hour soak.
DO NOT point-fix the archive slice and immediately re-run.

STATE
  165 PASS/frozen · 168 PASS live · 170 PASS live · 167 PASS offline (live
  selectivity unvalidated) · 166 FAIL · 171 OPEN non-blocking · 169 OPEN
  (re-pinned, currently green) · 1280 MiB floor unchanged · soak BLOCKED.

WHY 166 FAILS NOW
  Not throughput-in-general. The engine cannot complete a SINGLE cohort inside
  the 2,160 s budget. Measured: `corr_signals_archive` is 98.6% of correlation
  persistence time (1,130 inserts, p50 152 ms, 222.4 s of 232.4 s), object
  persistence 0.47/sec, ~8,500-row window-sized archive slice PER OBJECT. This
  is tracker 156's residual `_archive_slice`, which its own row predicted.

THE PATTERN THAT MATTERS
  Four bottlenecks, all the same defect: per-object work sized by something
  GLOBAL (catalog, window) rather than by the object. Harmless pre-168 when
  there was one object; O(objects x global) now that there are ~1,000.

FIRST TASK — the architectural review, before any more code
  1. State the invariant "per-object work is sized by the object" and audit
     every per-object path against it; produce a sizing table. Is a fifth
     bottleneck already waiting?
  2. Review the bounded-cohort x object-formation interaction (singleton
     objects for not-yet-scored nodes, persisted then merged). 166 and 156 were
     designed independently.
  3. Review the persistence model for ~1,000 small objects rather than a few
     large ones: ~8 CH inserts/object, serialised, on the loop.
  No code changes in that step. Then fix, then re-run one clean 1K.

ALSO FIX (real, not dominant)
  A ClickHouse ReadTimeout raises CHInsertRejected out of _persist_snapshot
  past _mark_processed, discarding a whole cohort. P(commit) = (1-p)^objects.

HOUSE RULES
  Measure before optimising — the bottleneck has moved every single time.
  Mutation-test every guard; a check that cannot go red is not a check.
  Never weaken 165 retention, 168 identity scoping, or the 170 completion gate.
  Report FAIL as FAIL; do not bank partial evidence from an invalid run.
```
