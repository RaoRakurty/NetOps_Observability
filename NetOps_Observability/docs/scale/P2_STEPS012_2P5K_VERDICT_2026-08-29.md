# P2 steps 0–2 — 2.5K live verdict (2026-08-29, run `p2-s012d-08290411` / `08290412u1l8`)

**Verdict: the compute bottleneck is gone and TTUR improved materially — T1 p95
4,771 → 2,980 s (−38 % vs P1, −42 % vs OLD) — but completion still FAILS the
2,700 s gate (pending 21,638), pending reached 0 partly by stream-time EXPIRY,
and the epoch budget re-lost P1's cross-cohort merges. The bottleneck is now the
per-version persist path: `run_window` = 104 s total vs ≈4,800 s of persist
wall. Next lever = step 4 (async Evidence queue) + damping, plus a merge-cadence
fix.** Four attempts were needed (§5) and two harness blind spots were fixed on
the way.

Image: `c19dcc7d` (P1 + P2 steps 0–2 + profiler-safe accounting), both replicas,
`compose.profile.yml` (profiler ON, 1.25 GiB / 150k). Harness: `c19dcc7d` copy.
Same workload as OLD/P1 (t-nominal-2.5k, 2,500 devices, 900,001 events @ ~1,000/s,
one tenant → replica-4 does all correlation work).

## 1. Harness phases
preflight PASS · onboard PASS (2,500/2,500 own, 0 absorbed, ratio 0.86) · burst
PASS · drain PASS (399 s transport) · **correlation_completion FAIL** — pending
21,638 after 2,700 s, cohorts +9, oldest 430 s, `windows_rejected +0`,
`profiler_errors +0`, `versions_persisted +38,355` (the new clauses prove the
work is real) · accounting PASS (900,001 == 900,001, 2,500/2,500) · **memflat
FAIL** (494 → 753 MiB after input stopped, ×1.53 > ×1.3; cap 1.25 GiB) ·
stability PASS (4,435 s, 0 restarts, worst loop stall 3.8 s) · cleanup FAIL
(API `TimeoutError` under load — harness client had no retry; fixed separately;
residue purged by hand, devices 0, CH 0, OS draining).

## 2. Clean-scope TTUR (same SQL as the P1 verdict; storm-aggregate cid excluded)

| leg | incidents | versions | v/inc | T1 p50 | T1 p95 | T1 p99 | T1 max | T-last p95 | merged | undetermined |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| OLD (`08281519gjez`) | 14,471 | 60,557 | 4.18 | 1,766 | 5,158 | 7,588 | 8,098 | 8,923 | 11 | 1,206 |
| P1 (`p1-on-08281911`) | 13,188 | 42,455 | 3.22 | 1,478 | 4,771 | 5,172 | 5,718 | 7,416 | 378 | 1,319 |
| **P2 s0–2 (this run)** | **16,172** | 52,911 | 3.27 | **953** | **2,980** | **3,938** | **4,114** | **5,088** | 11 | 1,515 |
| Δ vs P1 | +23 % | +25 % | +2 % | **−36 %** | **−38 %** | −24 % | −28 % | −31 % | ↓ (§4.2) | +15 % |

T1 p95 is still ~600× the proposed 5 s SLO; TTUR remains queueing latency.
Incidents +23 %: more of the evidence was evaluated before expiry (§4.1), so
more objects were minted — versions/incident stayed flat.

## 3. Engine counters (replica-4, whole run to convergence 05:48 UTC)
cohorts 33 · epochs 47 · `epoch_budget_exits` 8 · `epoch_seconds_max` 1,097 s ·
versions persisted 53,089 / damped 2,671 · rank memo hit **38,936 / 59,053 = 66 %**
(29 % early in the storm, climbing as evidence repeats) · level-2 memo hits
44,210 (tail epochs only) · components 103,263 / touched 13,047 ·
`windows_rejected` 0 · `stream_time_evictions_total` **18,857** ·
`edge_cache_dropped_total` 12,353.

**Stage profile (profiler ON, cumulative, replica-4):** `engine.run_window`
33 calls, **104 s total, p50 34 ms, max 33.8 s** · `epoch_prepare` 12 s ·
`prune` 0.3 s · `handle.syslog` 850 s over 931k calls (ingest). The profiler
does not instrument reconciliation/persist; by subtraction that path is
≈4,700 s of the ≈4,800 s engine wall since burst end. ClickHouse inserts in
the window: **149,590 inserts, 1,840 s** (38 % of wall), issued sequentially per
version (objects 34.5k, current 34.5k, archive 20.5k, edges 7.5k, evidence 7.5k
at the gate); the Python side (blob/row building, awaits) is the rest.

## 4. Findings that change the plan
### 4.1 Pending reached 0 partly by expiry, not evaluation
18,857 signals (2.1 % of 900,001) were evicted by stream-time retention before
evaluation (the same mechanism tracker 166 recorded as "backlog bounded by
expiry"). The completion gate correctly FAILed at 2,700 s; the later convergence
is NOT a pass. Any claim of "evaluated the workload" must subtract these.
### 4.2 The epoch budget made every epoch ONE cohort — merges regressed to OLD
With `CORR_ENGINE_EPOCH_BUDGET_S=300` and a cohort costing ~1,000 s, every epoch
drained exactly one cohort (`cohorts_max` 1), so the epoch-cadence merge/quiesce/
cap pass sees one cohort's `seen` set — the per-cohort lifecycle P1 replaced —
and the 378 merges P1 found (all predicate-valid) fell back to 11. Also the
level-2 memo cannot hit inside an epoch. **Fix (step 4a): decouple the lifecycle
cadence from the epoch — run merge/quiesce/cap over the union of the last K
cohorts' `seen` sets (K = the pre-budget drain bound, 20), regardless of epoch
boundaries; the budget keeps its prune/oldest-age benefit.**
### 4.3 One cohort ≈ 1,000 s and it is persist, not compute
`run_window` p50 34 ms; a 5,000-signal cohort yields ~7,500 versions × (4–5
sequential inserts + blob/row build) ≈ 1,000 s. The Decision plane already has
its verdict within the first ~100 ms of the cohort; the operator waits ~1,000 s
for the Evidence rows. This is precisely spec §4 (bounded, priority-ordered
async Evidence queue; VVR/current row synchronous). Expected effect: cohort wall
→ verdict-row cost; Evidence lag becomes a measured T7/T8 instead of T1.
### 4.4 memflat ×1.53 — attribution pending
Engine still had 21k pending when input stopped (working set), but P2 added
process-lifetime caches (rank memo 20,117 entries at convergence). Offline
attribution (`p2_memflat_attribution.md`) decides cache vs working set vs leak
before any RSS claim is made.
### 4.5 Rank memo live hit rate 66 % (offline 63–96 %)
Lower than the synthetic because live evidence keeps changing an entity's
projection across epochs (new signals attach). Still: rank time is off the
critical path; no further memo work is justified by this run.

## 5. Attempts 1–3 (why this took four runs) — all fixed and committed
1. `p2-s012-08290116`: profiler ON → `int('')` in `_record_cycle_work` → every
   window rejected, gate passed on 0 objects (`c19dcc7d`: accounting can't
   raise, rejections/hollow completion are gate clauses, parser label fix).
2. `p2-s012b-08290322`: collided with the 03:17 UTC cron 1K run (canary now
   disabled; run lock + namespace preflight in `b29d34ea`).
3. `p2-s012c-08290359`: 1,000 shadow devices from the overlap (tracker 181,
   API persists an absorbed create; harness now purges shadows/canonicals).

## 6. Decision
- P2 steps 0–2 stay ON; they are a strict TTUR improvement with identical
  semantics (0 rejections, churn/verdict equivalence to be re-run when the
  equivalence script is re-pointed at this leg).
- Build **step 4 (async Evidence queue + VVR-lite: verdict row first)** and
  **step 4a (lifecycle cadence over the last K cohorts)** next; step 3 (full VVR
  table) is deferred until step 4 shows the Evidence lag is the remaining term.
- Re-measure with this run as the new baseline (T1 p95 2,980 s).
