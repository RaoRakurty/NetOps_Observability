# P4 — Storm-time RCA optimisation programme: consolidated measurement (draft, 2026-08-29)

Owner constraint (2026-08-28): no more hardware; success = engine efficiency +
TTUR SLOs on the existing 4-core box. P5 (scale-out proof) dropped. Authority:
owner memo `/var/tmp/Correlix-Bottleneck-Modified.md`; every number below is
from a dated verdict doc in `docs/scale/` with the SQL/method stated there.
**Draft — updated after each remaining step (lifecycle fix, P3 A/B).**

## 1. The instrument (what "measured" means here)
- Ratified workload `t-nominal-2.5k`: 2,500 devices, 900,001 events @ 1,000 eps
  (15 min), one tenant → one shard. Gates: completion in 2,700 s, accounting
  exact, memflat, stability. Its noise floor is ±10 % on TTUR (arrival-timing
  variance in continuation adoption) and it has NO storm dynamics (state pinned
  per device; tracker 183) — it is the throughput floor, not a storm test.
- `t-storm-2.5k` (built 2026-08-29): same plan with a seeded fault-injection
  scenario (flaps, recoveries, repeats, multi-vantage, contradictions, the
  enterprise-outage chain) and ground truth scored by the twin's scorer;
  `StormShape` ladder 2/10/25/50 % for the P3 A/B.
- TTUR = `scripts/scale-rca-latency.py` T0..T6 (T4 is a proxy without ground
  truth; T4 correctness = the twin scorer's `affected_includes`/owner clauses).

## 2. Results — `t-nominal-2.5k` (single shard, same workload every leg)
| leg (doc) | completion | T1 p50 | T1 p95 | T1 p99 | T1 max | T-last p95 | notes |
|---|--:|--:|--:|--:|--:|--:|---|
| OLD `fa4857a5` (`STORM_MODE_2P5K_VERDICT`) | FAIL, 24.6k pending | 1,758 | 5,748 | 7,588 | 8,098 | 8,915 | baseline |
| P1 cohort-touch gate (`P1_2P5K_VERDICT`) | FAIL (~106 min) | 1,473 | 4,759 | 5,155 | 5,718 | 7,419 | −30 % versions |
| P2 s0–2 memo/caches/budget (`P2_STEPS012`) | FAIL, 21.6k | 940 | 2,960 | 3,937 | 4,114 | 5,097 | run_window 104 s total |
| P2 s4 async Evidence (`P2_STEP4`) | FAIL, 4.1k | 782 | 2,404 | 2,828 | 2,999 | 3,767 | hold leak |
| P2 s4b generational hold (`P2_STEP4B`) | **PASS 2,515 s** | 772 | 2,208 | 2,658 | 2,684 | 3,550 | first PASS (870k events) |
| P2 s5 batching+offload+CH budget (`P2_STEP5`) | **PASS 1,986 s** | 611 | 1,947 | 2,131 | 2,425 | 3,040 | full 900k; T7 p95 4 s |
| P2 s6 compact memo/prefilter/touch (`P2_STEP6`) | **PASS 2,439 s** | 660 | 2,105 | 2,483 | 2,513 | 3,303 | within noise |
| **Δ OLD → best (s5)** | never → PASS | **−65 %** | **−66 %** | **−72 %** | **−70 %** | **−66 %** | |

Verdict semantics held at every step (equivalence reviews: owner/tier/
confidence 100 % on matched incidents; merges/continuations explained).

## 3. Results — `t-storm-2.5k` (storm dynamics, ground truth)
| run | completion | stability | memflat | T1 p95 | accuracy | note |
|---|--:|---|---|--:|--:|---|
| storm-s01 (image pre-`675966cd`) | PASS 2,171 s* | FAIL 115 s stall | FAIL (api query) | 1,376 | 93.0 % | *65k evictions, consumer ejected; counts inflated by redelivery |
| storm-s02 (after 185 fix) | **PASS 118 s** | FAIL 35.7 s stall | **PASS 9/9** | **1,054** | **93.3 %** | lifecycle pass on the loop; fix in build |
Accuracy misses are all one clause on chained outages (tracker 187); 31 % of
chain lines are not parser-promotable (tracker 184).

## 4. Where the time goes now (storm-s02, replica-4)
`persist.decision` 916 s (Decision write: blob + 2 inserts) · `run_window` 270 s
(executor) · `handle.syslog` 1,325 s (ingest, starved by the stall) ·
`persist.batch_flush` 309 s (wall, off-loop) · lifecycle pass: the remaining
loop-thread stage (tracker 185 part 2). Evictions 23,210 (nominal 17.8k) — the
identities that age out unevaluated are the P3 population.

## 5. The SLO statement (honest)
The memo's proposed T1 p95 of 5 s is not reachable on one 4-core shard for a
15-minute 1,000-eps storm: the p95 is queueing time behind the burst
(T3−T1 = 0 at max on every leg; decision latency is ~0). What P0–P2 achieved is
a 3× reduction of that queue (5,748 → ~1,950 s) with completion inside the
45-minute budget, lossless, and semantics preserved. The remaining order of
magnitude is either (a) P3 aggregation when the storm carries repeats (ladder:
−36/−56/−74 % of engine signals at 10/25/50 % storm share; ~0 % on t-nominal),
or (b) more shards — the P5 the owner ruled out. A storm-time SLO should be
stated per identity class (first occurrence vs repeat) and relative to burst
end; that is a product decision to be taken with the P3 A/B numbers.

## 6. Defects found by the programme's own gauges (all filed)
177 T4 gap → closed by ground truth · 178 replay direction · 180 profiler
rejects windows · 181 shadow device rows · 183 benchmark fidelity · 184 parser
coverage · 185 storm batch-flush stall · 186 backfill worker · 187 chain
attribution; plus ClickHouse merge budget, system-log self-merge, pool
thresholds, harness producer loss, injector shortfall, memflat clause
semantics, run lock/namespace residue.

## 7. Remaining to close P4
1. Lifecycle-pass instrumentation + bound (185 part 2) → storm 9/9 PASS.
2. P3 steps 3–4 + A/B on t-storm-10/25 (flag OFF vs ON), t-storm-2.5k neutral.
3. Final table update + owner SLO decision.
