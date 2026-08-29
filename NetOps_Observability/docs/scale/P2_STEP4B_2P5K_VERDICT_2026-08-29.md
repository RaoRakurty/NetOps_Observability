# P2 step 4 fixed (generational hold, 4a, archive offload) — 2.5K live verdict (2026-08-29, run `p2-s04b-08290858`)

**Verdict: FIRST `correlation_completion` PASS at 2.5K on this box — 2,515 s of a
2,711 s budget, pending 0 on both replicas, cohorts +34, 45,356 versions
persisted, 0 rejections (hollow/rejection clauses satisfied).** TTUR T1 p95
2,208 s (−8 % vs the step-4 leg, **−57 % vs OLD**), T7 p95 1,055 → 403 s, merges
back (346), incident count back to 15,335. Two NEW failures the run's own gates
caught, both under investigation: **accounting FAIL — 901 events short**
(ROOT-CAUSED: the HARNESS's `kafka-console-producer` dropped 901 records of
chunk 79 under broker saturation — 1.5 s ack timeout × 3 retries, exit 0, failure
only logged, stderr discarded by `Stack.produce()`; Kafka delta == OpenSearch
docs == 869,100, correlation counters clean — the platform was lossless; producer
hardened + stderr judged, fix in build), and **memflat FAIL on ClickHouse**
(docker-stats counts ~68 % reclaimable page cache/slab; the REAL finding is peak
`MemoryTracking` at 95 % of `max_server_memory_usage` from merge work: 241× write
amplification off ~170k tiny inserts; settings + Evidence batching in build,
harness clause being replaced). Correlation's own memflat PASSED. Caveat: the
injector produced 870,001 events (~963/s), 3.3 % short of the ratified 900,001.

Image `7ba42389` (+ estimator `a75b73f8`; queue bounds `e318ace2` NOT yet
deployed — this leg ran 5,000 items / 512 MiB), profiler on, both replicas;
replica-3 carried the tenant. Harness `63e9c229`.

## 1. Harness phases
preflight PASS · onboard PASS (ratio 0.66 — #175 creeping toward the 0.6 floor)
· burst PASS (870,001 @ ~963/s) · drain PASS (550 s) · **correlation_completion
PASS (2,515 s)** · **accounting FAIL (901 unexplained)** · **memflat FAIL
(clickhouse ×1.72; correlation PASS)** · stability/cleanup: pending at write time.

## 2. Clean-scope TTUR — five legs (re-queried together)

| leg | incidents | versions | v/inc | Σ signals | T1 p50 | T1 p95 | T1 p99 | T1 max | T-last p95 | merged |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| OLD | 14,471 | 60,557 | 4.18 | 48,575 | 1,764 | 5,133 | 7,585 | 8,098 | 8,921 | 11 |
| P1 | 13,188 | 42,455 | 3.22 | 52,029 | 1,494 | 4,773 | 5,174 | 5,718 | 7,419 | 378 |
| P2 s0–2 | 16,172 | 53,002 | 3.28 | 48,627 | 950 | 2,966 | 3,938 | 4,114 | 5,090 | 11 |
| P2 s4 | 11,664 | 44,286 | 3.80 | 54,053 | 776 | 2,402 | 2,827 | 2,999 | 3,766 | 0 |
| **P2 s4b** | 15,335 | 45,466 | **2.96** | 50,283 | 782 | **2,208** | **2,658** | **2,684** | **3,396** | 346 |

Cumulative vs OLD: T1 p50 −56 %, p95 −57 %, p99 −65 %, max −67 %, T-last p95 −62 %.
T7−T1 (first edge row vs object row): p50 0 s, p95 403 s, p99 1,631 s, max 2,264 s.

## 3. Engine (replica-3, run total)
cohorts 34 · epochs 22 · budget exits 6 · epoch max 939 s · versions 47,354
persisted / 6,166 damped · stream-time evictions 17,842 (same order as every leg)
· Evidence: materialized 47,364, failed 0, lost 0, **backpressure 0**, hold expiries
33 (the 5 s cap fires on storm cohorts — Decision-first ordering is bounded, not
absolute) · rank memo 17,401 / 53,433 = **33 %** hits at 3,009 entries (33,023
evicted — the 96 MiB bound is the limiter) · merge survivors 2,491 / candidates
2,539 (4a healthy) · loop lag max **3.9 s** (was 9.7).
Stage profile: `persist.decision` 47,365 calls **3,249 s** (p50 31 ms, **max 64 s**)
· `persist.evidence` 2,220 s · `handle.syslog` 730 s · `run_window` 283 s
(p50 3.6 s; memo-limited) · `backpressure_wait` 1.2 s total.

## 4. Reading
- The generational hold did what the offline A/B predicted: Evidence writes
  pipeline into the Decision path's I/O waits (backpressure 0, lag ≤ 0.1 s), and
  total wall fell enough to clear the gate. Between 09:59 (pending 15K, 18
  cohorts) and 10:05 the last 16 cohorts cleared — cohorts are bursty, so
  mid-run pending snapshots understate progress.
- The Decision write is now the critical path (3,249 s for 47K versions, ~69 ms
  each incl. blob + 2 inserts + estimator); **version damping** (2.96 v/inc,
  6,166 damped) and the rank-memo footprint (33 % hits) are the two remaining
  engine levers; ClickHouse part churn is the storage lever (§5).
- One 64 s `persist.decision` is a storm object whose blob/rows are built on the
  loop thread — the `_offload` threshold for the Decision write needs the same
  treatment the archive chunk got.

## 5. Open (in flight)
1. 901 events — harness producer (see above); fix in build. Platform-side
   row counting / dedup-token retry / DLQ already exist (tracker 160).
2. ClickHouse — `P2_CLICKHOUSE_MEMFLAT_2026-08-29.md`: settings (merge size cap,
   pool 6, soft limit 1.5 GiB, mark cache 512 MiB, part_log on), Evidence write
   batching (200 items / 8 MiB / 2 s per table, block dedup token), harness
   clause = anon-only slope + MemoryTracking < 85 % + parts recover.
3. Deploy `e318ace2` (queue 2,000 / 64 MiB, calibrated estimator) — not in this leg.
4. Injector shortfall 870k vs 900k — explain (harness).
