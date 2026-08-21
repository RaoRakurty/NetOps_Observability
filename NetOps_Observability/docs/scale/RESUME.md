# CORRELIX GA qualification — resume brief

**Read this first when picking the work back up.** One page of orientation, then
the paste-ready prompt at the bottom.

Last updated: 2026-08-21 · commit `de33b6e2` · branch `feat/observability-platform`

---

## The 30-second version

Correctness work is largely done and frozen. **Tracker 165 (RCA retention
semantics) is PASS** and the resource planner carries the qualified 1.25 GiB
correlation allocation. **Tracker 166 (bounded correlation transactions) FAILED
its live qualification** on a throughput regression whose cause is already
diagnosed to one function. Fixing that is the immediate task; nothing downstream
of it should start until it passes.

## Where the bodies are buried

| Thing | State | Notes |
|---|---|---|
| 165 retention | **PASS — frozen** | 516.527 s horizon is a correctness contract, not a tunable |
| resource planner | **PASS** | correlation floor 1280 MiB, three mirrors pinned together |
| 166 scheduler | **FAIL** | state gates passed, throughput regressed — see below |
| 167 throughput | defined, not started | blocked behind 166 |
| 162 continuation | PARTIAL | do not touch `_seam_bridged` |
| 163 OPEN_OBJECTS | deferred | measured 7–8, no action justified |
| 164 executor | open, de-prioritised | ruled out as bottleneck on complete evidence |
| 155 ownership | not run | after the soak |
| 72h soak | **BLOCKED** | see the blocker list in the prompt |

## Why 166 failed, in one paragraph

Bounding the cohort bounded pair *emission* but not the per-transaction *fixed
cost*. `build_edges` prepares `toks/refs/seam_evs/devs/memb` for **all** n nodes
and `_candidate_pairs` builds its inverted index over all of them — both
O(retained nodes), both on every transaction. Pre-166 that was paid once per
cycle; splitting a cycle into ~8 cohorts pays it ~8×. Live result: 6 cohorts in
13 minutes at 182 eps, pending growing to 37,292, oldest-pending at **82.8 % of
the retention horizon**. The same workload drained in 25 s before the change.

**Fix**: hoist the per-node preparation and the candidate index out of the
per-transaction path — build once per cycle, reuse across that cycle's cohorts.
The index is a pure function of the node set, so every proven equivalence
survives. Do **not** enlarge the cohort back toward unbounded.

## What went right and must not be undone

The scheduler design itself held. The carried-edge cache — the biggest open risk
going in — **plateaued at ~384k entries** and stayed flat while the window grew
25k→53k. The processed frontier stayed bounded. Memory sat at 56–58 % of the
1.25 GiB envelope with zero swap and zero cap hits. Those are the gates that
would have been expensive to discover during a 72-hour soak.

## The question that is blocking three decisions

**What syslog/telemetry rate should a 1,000-device GA deployment be qualified
at?** The lab p90 says 182/s; `scripts/resource_planner.py`'s own `medium`
profile says 5,000/s for the same device count. That 27× spread decides whether
167 is on the critical path, what rate the soak runs at, and whether the memory
sizing is right. It needs an answer from the owner, not another measurement.

## Small lab debt worth clearing before the soak

* The `memflat` gate reads post-ingress memory growth as a leak, but under
  stream-time retention the window legitimately keeps filling while backlog
  drains — it produces false failures.
* Harness cleanup fails intermittently with `TimeoutError`, leaving device
  residue that aborts the *next* run's preflight. It has been cleared by hand
  each time; nobody will be doing that at 3 a.m. on soak night two.

---

## Paste-ready resume prompt

```
Continue CORRELIX GA qualification from the current clean branch state.

# WHERE WE ARE

Branch `feat/observability-platform`, last commit `de33b6e2`, tree clean.
Correlation suite: 1346 passed / 9 skipped. Planner suite: 55 passed. ruff clean.

Lab is CLEAN and on the production config: 0 devices, Kafka backlog drained,
`compose.mem125.yml` (1.25 GiB, CORR_WINDOW_BUFFER=150000), profiler OFF.
Bus is Apache Kafka 4.1.1 KRaft over mTLS (`kafka:9094`) — never Redpanda,
Redis or Prometheus.

# FROZEN — DO NOT REOPEN WITHOUT REGRESSION EVIDENCE

* Tracker 165 = PASS. Retention contract is authoritative:
  max_attachable_gap = tau_s * ln((w_topo*w_r)/attach_threshold) = 396.527 s
  reach, + 120 s lateness floor (one engine interval OR permitted future clock
  skew, whichever is larger) = 516.527 s required retention. Per-tenant
  stream-time watermarks, co-partitioning safety gate, backlog-proven idle
  backstop, future-skew clamp, explicit RCA degradation. Do not shorten the
  horizon for performance.
* Resource planner = PASS. Correlation floor 1280 MiB flowing through the
  planner; three mirrors (planner floor, compose fallback, series-budget
  fallback) pinned together by a test that reads the others.
* Engine-side 166 foundation is proven and must not be redesigned:
  build_edges(cohort=...), run_window(carried_edges=...), pair-local soundness,
  new×old and B2×B1 preservation, replay content_hash equivalence.

# TRACKER 166 = FAIL — THIS IS THE IMMEDIATE TASK

Live 1K qualification ran on a verified clean baseline and FAILED.

STATE gates PASSED: carried-edge cache plateaued at ~384k entries (flat from
t+7min while the window grew 25k→53k), processed frontier bounded at
15,702/16,369, memory 750–784 MiB (56–58% of 1.25 GiB), swap 0, zero cap hits,
zero useful-evidence drops, zero RCA degradation, loop stall 5.4–5.8 s.

THROUGHPUT gate FAILED: only 6 cohorts in ~13 minutes at 182 eps, pending grew
monotonically to 37,292, and oldest_pending_event_age reached 427.6 s = 82.8%
of the 516.527 s horizon — evidence ~89 s from expiring before ever being
evaluated. The same p90 workload drained in 25 s before this change.

ROOT CAUSE (already diagnosed from source, do not re-derive): bounding the
cohort bounded pair EMISSION but not the per-transaction FIXED cost.
build_edges prepares toks/refs/seam_evs/devs/memb for ALL n nodes, and
_candidate_pairs builds its inverted index with
`for i in range(n): for t in toks[i] | refs[i]`. Both are O(retained nodes) and
both run on EVERY transaction. Pre-166 that was paid once per cycle; splitting
a cycle into ~8 cohorts pays it ~8x. engine_cycle measured ~150 s even with a
5,000-signal cohort.

FIX DIRECTION: hoist the per-node preparation and the candidate index OUT of
the per-transaction path — build once per cycle, reuse across that cycle's
cohorts. The index is a pure function of the node set, so every proven
equivalence survives. Do NOT respond by enlarging the cohort back toward
unbounded; that reinstates the runaway 166 exists to remove.

Then re-run the live 1K qualification and collect what the failed run never
reached: device accounting, signal accounting, DLQ, ClickHouse durability,
duplicates, UnknownMember, CommitFailedError, restarts/rebalances, RCA
reference equivalence.

166 PASSES when: reference equivalence intact, cohort admission bounded,
candidate generation bounded at source, transaction size bounded as backlog
grows, carried-edge and processed-frontier state plateau, no tenant starvation,
no never-evaluated evidence, clean live 1K passes, 165 stays PASS, Kafka
membership stable, memory inside the planner allocation.
Do NOT require a sustainable-EPS improvement — that is 167.

# AFTER 166 PASSES

167 throughput → formal capacity calibration → 162/163/164 disposition →
clean mini-ladder → 72h soak → 155 ownership → BUS_PARTITIONS 4→8 →
2.5K → 5K → 10K → chaos/recovery → upgrade/rollback → canary/pilot →
GA readiness review. Do not skip stages because the suite is green.

167 owns per-pair cost (~28–71 µs/candidate offline), sound prefilters (false
positives OK, false negatives NEVER — must not break _seam_bridged), hoisting
repeated computation, allocation, and only then GIL escape. Do not reach for
multiprocessing first: 0.66–0.69 cores of 2 with zero throttling does not prove
more processes are the lever.

# OPEN TRACKERS

162 PARTIAL (don't touch _seam_bridged) · 163 deferred (OPEN_OBJECTS 7–8) ·
164 open, de-prioritised (executor ruled out: queue peak 1, wait p99 20 ms
while one call ran 196 s) · 155 not run · 72h soak BLOCKED.

# KNOWN LAB DEBT (small, worth fixing before the soak)

* memflat gate reads post-ingress memory growth as a leak, but under
  stream-time retention the window legitimately keeps filling while backlog
  drains. It produces false failures.
* Harness cleanup fails intermittently with TimeoutError, leaving device
  residue that aborts the NEXT run's preflight.

# UNRESOLVED PREMISE — I still need an answer from you

What syslog/telemetry rate should a 1,000-device GA deployment be qualified at?
Lab p90 says 182/s; resource_planner.py's own `medium` profile says 5,000/s for
the same device count — a 27x spread. At 182/s we are close to done; at 5,000/s
the measured ~800–1,000/s ceiling is 5x short and 167 becomes the critical
path. This gates 167, the soak rate, and the memory sizing.

# HOUSE RULES

Mutation-test every guard you add; a check that cannot go red is not a check,
and a build failure is never a behavioural mutant kill. INVALID is a real
outcome — never fold it into PASS, never convert "not run" into PASS. Do not
mask problems by raising Kafka timeouts, memory, executor size, partitions or
thresholds unless measurement proves it is genuinely sizing. Evidence over
assertion: cite source, config or measured runtime behaviour. If a live run
fails, report it — do not move to the next tracker to bury it. Skip anything
repetitive.
```
