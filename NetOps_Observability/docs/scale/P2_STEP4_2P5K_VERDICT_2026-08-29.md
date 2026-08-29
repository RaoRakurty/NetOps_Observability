# P2 step 4 (async Evidence plane) + 4a — 2.5K live verdict (2026-08-29, run `p2-s04-08290653` / `0829065366t9`)

**Verdict: a large, real TTUR gain on top of steps 0–2 — T1 p95 2,980 → 2,401 s
(−19 %), p99 −28 %, T-last p95 −26 %, convergence 80 → 56 min — and completion
came within reach (pending 4,055 at the 2,700 s gate vs 21,638; cohorts +32 vs
+9). Verdict semantics hold (owner/tier/confidence 200/200; the −28 % incident
count is continuation adoption covering +11 % more raw signal). Three defects
found by the run's own gauges, all fixable and in build: an Evidence-consumer
hold leak (queue pinned at its bound all run), a 4a regression that emptied the
merge candidate space (merges 0), and a rank-memo byte estimator that over-charged
1.62× (hit rate 6 %). Expect the next run to pass the completion gate once those
land.** Equivalence: `P2_STEP4_EQUIVALENCE_2026-08-29.md`.

Image `87973a36` (P1 + P2 steps 0–4/4a + byte-bounded rank memo), profiler on,
both replicas; harness `63e9c229` (lock + namespace preflight + retries). Same
workload as every prior leg; replica-3 carried the tenant this time.

## 1. Harness phases
preflight PASS · onboard PASS (2,500 own, `stop=none`) · burst PASS · drain PASS
(424 s) · **correlation_completion FAIL — pending 4,055, cohorts +32, oldest 90 s,
`windows_rejected +0`, `versions_persisted +41,660`** · accounting PASS · **memflat
FAIL** (503 → 728 MiB, ×1.45; §4.4) · stability PASS (worst loop stall **9.7 s**,
was 3.8 s; §4.3) · cleanup PASS (namespace-wide verify, residue 0).

## 2. Clean-scope TTUR (aggregate cid excluded; all legs re-queried today)

| leg | incidents | versions | v/inc | T1 p50 | T1 p95 | T1 p99 | T1 max | T-last p95 | merged |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| OLD | 14,471 | 60,557 | 4.18 | 1,767 | 5,744 | 7,968 | 8,098 | 8,929 | 11 |
| P1 | 13,188 | 42,455 | 3.22 | 1,495 | 4,761 | 5,161 | 5,718 | 7,420 | 378 |
| P2 s0–2 | 16,172 | 53,002 | 3.28 | 959 | 2,980 | 3,939 | 4,114 | 5,094 | 11 |
| **P2 s4** | 11,664 | 44,286 | 3.80 | **794** | **2,401** | **2,825** | **2,999** | **3,767** | 0 (§4.2) |
| Δ vs s0–2 | −28 % (§3) | −16 % | +16 % | −17 % | **−19 %** | −28 % | −27 % | −26 % | |

Cumulative vs OLD: T1 p95 **−58 %**, p99 −65 %, max −63 %. Still ~480× the 5 s SLO.

**T7 (evidence materialized) is now measurable:** first `corr_edges` row vs the
object row, per version: p50 90 s, p95 1,055 s, p99 2,154 s, max 2,672 s
(n = 24,445). `corr_evidence_lag_seconds` peaked ≈570 s mid-drain and was 0.003 s
at convergence; items materialized 44,306 = versions persisted, failed 0, lost 0.

## 3. Incident count −28 %: adoption, not loss (equivalence report)
Σ max(signal_count) 48,627 → **54,053 (+11.2 %)** in 28 % fewer objects; 86 % of
the drop is singletons (9,831 → 5,934); 16,632 re-keyed continuations logged;
all 2,500 devices have incidents in both legs (0 A-only / 0 B-only); no scope
leakage; merges/cap/quiesce cannot destroy ids. Matched incidents (n=200):
owner / verdict_tier / top_confidence **100 %**, node_count 71.5 % (39 larger in
s4 = adoption, 18 smaller). Flag: `spine-leaf-path-degradation` is the FINAL
hypothesis of 502 s0–2 incidents and 0 s4 incidents (still appears on 1,078 s4
versions, always re-ranked away by the last version) — same shape P1 saw; to be
re-checked after the merge fix.

## 4. Defects the run exposed (all in build)
### 4.1 Evidence consumer hold leak
At idle after convergence `epoch_state().evidence.held == True` with depth 0.
The queue sat at `max_items` 5,000 (≈101 MiB) for the whole drain; backpressure
8,767; the consumer only ran when a bound lifted the hold. Fix: hold strictly
scoped to one cohort's Decision pass, released on every exit; tests pin
`held == False` between cohorts. Expected effect: Decision plane no longer
throttled to Evidence throughput → completion.
### 4.2 4a regression — merge candidate space empty
`corr_lifecycle_seen_window_ids 2312 == corr_open_objects 2312`: widening
`merge_seen` widened `survivors` AND emptied `stale = OPEN_OBJECTS \ merge_seen`,
so `find_merges` had no candidates (merges 0; counterfactual predicate pairs 272).
Fix: widen the survivor side only; `stale` from the epoch's own `seen`.
### 4.3 Loop stall 9.7 s (was 3.8 s)
`persist.decision` max 21.5 s and `persist.evidence` max 39.1 s (blocking put
under backpressure and/or a storm object inside the span); consumer yield
cadence under review; backpressure wait to be recorded as its own span.
### 4.4 memflat ×1.45 with the rank memo capped
Rank memo held ~100 MB (1,780 entries); the pinned Evidence queue held ≈101 MiB
of referenced snapshots; attribution with the Evidence plane on is running
(`p2_memflat_evidence.md`) to size `CORR_EVIDENCE_QUEUE_BYTES_MAX`.
### 4.5 Rank memo crippled by its own estimator
Byte estimator over-charged 1.62× (catalog-owned objects per entry): 1,780
entries, 6 % hits, 69,597 evictions; `run_window` back to 724 s total (from 104).
Fixed `a75b73f8` (0.98× of tracemalloc marginal; 96 MiB admits ~2,900–5,000).

## 5. Stage profile (replica-3, run total)
`persist.decision` 44,306 calls 2,901 s (p50 32 ms) · `persist.evidence` 2,552 s ·
`handle.syslog` 843 s · `engine.run_window` 46 calls 724 s (memo crippled) ·
`epoch_prepare` 71 s. Decision + Evidence ≈ 5,450 s of engine time on a 4-core box
shared with ingest; the Decision write alone (2 inserts + blob) is now the
critical path per version → **version damping** (3.8 v/inc) is the next lever
after the three fixes.

## 6. Decision
Fix 4.1/4.2/4.3 → redeploy → one 2.5K run to the gate (expect PASS or near) →
then damping (memo §9 churn guard preserved) → step 3 VVR only if T7/T8 SLOs need it.
