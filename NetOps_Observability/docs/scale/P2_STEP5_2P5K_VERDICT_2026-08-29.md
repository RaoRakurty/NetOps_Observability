# P2 steps 0–4 complete + Evidence batching + Decision offload + ClickHouse budget — 2.5K live verdict (2026-08-29, run `p2-s05-08291138`)

**Verdict: `correlation_completion` PASS in 1,986 s (budget 2,700; previous PASS
2,515 s) on the full ratified 900,001-event workload; accounting PASS (exact);
stability PASS; TTUR T1 p95 1,947 s = −66 % vs OLD, p99 −72 %, max −70 %;
T7−T1 p95 4 s (evidence now lands with the verdict). memflat reported FAIL on
two clauses that are both harness measurement defects (§4) — fix in build; the
underlying numbers PASS.** P2 is functionally complete on the 4-core box;
what remains is measurement hygiene, then version damping as the next lever.

Image `fbb4a740` (P1 + P2 steps 0–4 + batching + offload + calibrated
estimators) with ClickHouse budget `c4b11690`+`865ef7dd` (pool 6, caps,
soft limit, part_log) and api boot ALTER; harness `8e623e38` (producer
hardened, work-boxed burst, lock/namespace, retries). Replica-3 carried the
tenant.

## 1. Harness phases
preflight PASS · onboard PASS (create rate 15/s — halved vs earlier legs, see
#175) · burst PASS **900,000 of 900,000 planned @ 1,000/s** · drain PASS (425 s)
· **correlation_completion PASS 1,986 s** (pending 0 both replicas, cohorts +34,
`windows_rejected +0`, `versions_persisted +38,320`) · **accounting PASS
(900,001 == 900,001 + 0 + 0)** · memflat FAIL (§4) · stability PASS (worst loop
stall 3.7 s, 0 restarts) · cleanup: pending at write time.

## 2. Clean-scope TTUR — six legs (re-queried together)

| leg | incidents | versions | v/inc | Σ signals | T1 p50 | T1 p95 | T1 p99 | T1 max | T-last p95 | merged |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| OLD (`fa4857a5`) | 14,471 | 60,557 | 4.18 | 48,575 | 1,758 | 5,748 | 7,588 | 8,098 | 8,915 | 11 |
| P1 | 13,188 | 42,455 | 3.22 | 52,029 | 1,473 | 4,759 | 5,155 | 5,718 | 7,419 | 378 |
| P2 s0–2 | 16,172 | 53,002 | 3.28 | 48,627 | 940 | 2,960 | 3,937 | 4,114 | 5,097 | 11 |
| P2 s4 | 11,664 | 44,286 | 3.80 | 54,053 | 782 | 2,404 | 2,828 | 2,999 | 3,767 | 0 |
| P2 s4b (first PASS) | 15,335 | 47,880 | 3.12 | 50,283 | 772 | 2,208 | 2,658 | 2,684 | 3,550 | 346 |
| **P2 s5 (this)** | 10,671 | 40,507 | 3.80 | 51,161 | **611** | **1,947** | **2,131** | **2,425** | **3,040** | 140 |
| **Δ vs OLD** | | −33 % | | +5 % | **−65 %** | **−66 %** | **−72 %** | **−70 %** | **−66 %** | |

Σ signals covered is flat-to-up across legs while incident counts vary with
continuation adoption (the P2 s4 equivalence review explains the mechanism).
T7−T1 (first edge row vs object row): **p50 2 s, p95 4 s**, p99 1,496 s, max
1,971 s (n = 24,290) — from p95 1,055 s on the un-batched plane.
Still ~390× the proposed 5 s T1 SLO: TTUR remains queueing latency, now with a
2,700 s budget met.

## 3. Engine + storage (replica-3, run total)
cohorts 34 · epochs 26 · epoch max 575 s · versions 40,321 persisted / 4,891
damped · evictions 18,642 (unchanged across legs — the expiry share is a
retention-horizon property, not a P2 effect) · rank memo 17,674 / 51,696 =
**34 %** hits at 2,954 entries (31,068 evicted; 96 MiB bound binds) · merge
survivors 3,924 / candidates 2,564 · Evidence: 40,318 materialized, 0 failed,
0 lost, **backpressure 0**, flushes edges/evidence 966 each, archive 656, **399
rows/flush** · loop lag max 3.7 s · offload wait max 10 ms.
Stage profile: `persist.decision` 40,332 calls **2,426 s** (p50 34 ms, max 19 s)
· `handle.syslog` 789 s · `run_window` 336 s · `persist.batch_flush` 165 s ·
`persist.evidence` 98 s · `epoch_prepare` 29 s.
ClickHouse inserts this run: corr_objects 40,255 (415 s) · corr_current 40,255
(339 s) · corr_evidence **964** (11 s) · corr_edges **964** (17 s) ·
corr_signals_archive **656** (11 s) — Evidence tables 2,584 inserts vs ~35k on
the previous leg; peak `MemoryTracking` **1,950 MiB (48 % of the 4,096 MiB cap)**,
peak merge memory **421 MiB** (26 % of the 1.5 GiB soft limit), max parts per
partition 15 (preflight 15).

## 4. memflat FAIL — two harness measurement defects (fix in build)
1. ClickHouse clause 2 printed "merge memory 4,084 MiB = 99.7 % of cap" and
   "MemoryTracking 2,952 MiB"; `system.metric_log` for the same window says
   **1,950 / 421 MiB**. Merge memory cannot exceed total tracked memory — a
   query/unit bug in the harness's peak fold. The other two ClickHouse clauses
   PASSED (anon ×0.81, parts settled).
2. Correlation ×1.37 (470 → 647 MiB) anchors at "input stopped" while 22,736
   signals were still pending; the working set legitimately grows through the
   backlog drain. The clause is being re-anchored at first `pending == 0` with a
   settle period; RSS peaked at 647 MiB = 51 % of the 1.25 GiB cap.

## 5. Where the time is now (the next lever)
`persist.decision` = 2,426 s of ≈3,900 s engine time: the synchronous object +
current write per version (blob build + 2 inserts + estimator). With 40,321
persisted for ~10.7k incidents (3.8 v/inc) and only 4,891 damped, **version
damping** (memo §9 churn guard preserved: zero-churn share must hold) is the
remaining engine lever; second is the rank memo (34 % hits under a 96 MiB bound
— entries are ~27 KiB; a compact cached form would lift it). Decision-plane
batching exists (`CORR_DECISION_BATCH`, OFF) and is a TTUR trade the owner
decides. Storage is no longer on the critical path.

## 6. Housekeeping found by this run
- Onboard create rate 15/s (was 30–43/s): device-store tombstone growth (#175)
  after ~10 runs today — the file backend's `.d/suppressed/` sweep is due.
- Preflight's "end offset > 100k" heuristic now reads all partitions (73M) and
  is meaningless as written — retire or re-baseline it.
