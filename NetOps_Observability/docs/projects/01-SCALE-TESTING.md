# Project 1 — Scale Testing  🔴 HIGH PRIORITY

**Goal:** establish the **host ceiling** on the owner's hardware — the max
sustained devices at **nominal AND storm**, with all gates green — and the
**binding resource** at that ceiling. Output feeds (a) **per-resource pricing
standards** and (b) the **customer hosting-requirement spec**.

**Hardware under test:** 4 cores (Xeon E5-2683 v4 @ 2.1GHz), 15 GiB RAM, 77 GB
disk. Early signal: **CPU-bound** (ClickHouse + correlation); disk is the close
second. This box likely tops out well below the 10k GA target — that finding is
itself a deliverable.

**Model rule:** Fable specs + grades; Opus implements every code change below.

## Execution order

### A. Deploy the correlation-engine fixes that are CODED BUT NOT LIVE
(Written during the 72h soak, which owned the stack. My Aug-27 deploy was
api+gnmic only — the `correlation` containers still run the **Aug-24 soak
build**, so these are NOT running. Storm testing is meaningless until they are.)
- [ ] **#172 Storm-priority scheduling** (`eb609b45`) — the fix for the S1
  single-owner ingest wall. THE storm fix.
- [ ] **#174 Observability under saturation** (`60bd796b`) — /healthz + /metrics
  stop starving when the engine saturates (why the Aug-22 completion gate read
  the replica as "unreadable").
- [ ] **#162 `find_continuation` O(open_objects)** (`dd3f2154`).
- [ ] **#163 `OPEN_OBJECTS` count bound** (`97b2600c`).
- [ ] **#164 `_offload` executor queue** — verify after A; flagged non-bottleneck.
- Redeploy correlation, smoke-gate (T-nominal) before it counts.

### B. Unblock CI
- [ ] **#169 `ingest-contract-ci` RED** (pre-existing, blocks merge) → green.

### C. The storm ladder (nominal + S1 at each rung)
- [ ] **1k S1 storm** — re-run; prove #172 fixed the ingest wall (soak SKIPPED S1).
- [x] 2.5k nominal (run `08271432rnic`) — grading; onboard of 2,500 ✅ (boot-fix validated).
- [ ] **2.5k S1 storm** (profile `s1-2.5k`, ~10k eps storm lane) — the real tolerance test.
- [ ] Add **5k** profiles (t-nominal-5k, s1-5k) → run nominal + S1.
- [ ] Add **10k** profiles (t-nominal-10k, s1-10k) → run nominal + S1 (GA target).

### D. Grade + capture the ceiling
- [ ] Per rung: drain / correlation_completion (pending→0, oldest-pending-age
  bounded) / stability (no restarts, bounded loop-stalls) / memflat + accounting.
- [ ] **Correlation quality under storm** — did the flood collapse into the
  RIGHT incidents (not fragmented, not conflated)? Beyond the throughput gates.
- [ ] Record: max devices (nominal & storm), binding resource, and the
  per-device resource envelope → pricing + hosting spec.

### E. Larger GA-scale programme (tracker, context)
- #153 GA scale ladder L2–L6 + chaos-under-load (blocked on a real rig).
- #152 network digital twin simulator · #155 partition-ownership correctness ·
  #157 spine-leaf confidence-1.0-with-no-spine.

### F. Finish
- [ ] Owner runs **`/code-review ultra`** on the branch.

## Status snapshot (2026-08-27)
1k steady-state PROVEN (soak accepted). 1k storm UNPROVEN (last S1 failed on real
engine defects; fixes #172/#174 coded, not deployed). 2.5k nominal grading.
Everything storm-related is gated on **Group A being deployed first.**
