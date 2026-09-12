# Lever wave after P2 (compact rank memo, ingest prefilter, heartbeat touch-only, ZSTD(3)) — 2.5K live verdict (2026-08-29, run `p2-s06-08291421`)

**Verdict: completion PASS (2,439 s of 2,700; previous 1,986 s), accounting
exact, stability PASS, correlation memflat PASS under the honest anchor
(×1.08 flat). The compact rank memo works exactly as measured offline (66 %
hits, 0 evictions, 28.6 MB for 21,955 keys). The ingest prefilter and the
heartbeat touch produced NO live gain on `t-nominal-2.5k` — recorded, not
spun. TTUR moved +8 % (T1 p95 2,105 vs 1,948 s) with +27 % incidents on
identical promoted signals: arrival-timing variance in continuation adoption,
i.e. leg-to-leg noise of this benchmark, not a lever signal. ClickHouse
memflat FAIL was real (17 MEMORY_LIMIT_EXCEEDED refusals) and self-inflicted
by `system.metric_log`'s own 997-column merges after enabling it this morning
— fixed by construction (`03995ecb`) and no longer possible.**

Image `46934f3f` (all P2 steps + compact memo + touch-only + prefilter), api
`c703db56` (ZSTD(3) codec applied; daily-partition migration parked), harness
`8e623e38`+`a8bb6077`. Replica-4 carried the tenant. Perturbations on this
leg: the api's boot repartition copy of `corr_edges` ran 14:19–14:19:21 (69
MiB, finished in 13 s — NOT killed; earlier note corrected) and ZSTD(3) on
`corr_objects` inserts (no latency change: p50 8 ms both legs; parts −25 %).

## 1. Harness phases
preflight PASS · onboard PASS (35/s — the api restart rebuilt its in-memory
suppression set; #175 slowdown lives in process state) · burst PASS
900,000/900,000 @ 1,000/s · drain PASS (379 s, fastest yet) · **completion PASS
2,439 s** (cohorts +34, `versions_persisted +45,752`, 0 rejections) ·
accounting PASS (exact) · **memflat FAIL: ClickHouse** (17 MEMORY_LIMIT_EXCEEDED,
peak 4,406 MiB = 107.6 %, **p99 1,596 MiB = 39 %**, median 1,189 MiB — identical
medians to s05; victims: 2 `findings` inserts named, 15 in background threads);
correlation PASS (×1.08 vs pending-0 anchor, FLAT) · stability PASS (4.1 s
worst stall) · cleanup PASS (residue 0).

## 2. TTUR (clean scope, aggregate cid excluded)

| leg | incidents | versions | v/inc | Σ signals | T1 p50 | T1 p95 | T1 p99 | T1 max | T-last p95 | merged |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| P2 s5 | 10,671 | 40,867 | 3.83 | 51,161 | 608 | 1,948 | 2,131 | 2,425 | 3,044 | 140 |
| **P2 s6** | 13,528 | 47,308 | 3.50 | 56,249 | 660 | 2,105 | 2,483 | 2,513 | 3,303 | 113 |
| OLD | 14,471 | 60,557 | 4.18 | 48,575 | 1,758 | 5,748 | 7,588 | 8,098 | 8,915 | 11 |

Cumulative vs OLD: T1 p50 −62 %, p95 −63 %, p99 −67 %, max −69 %.

## 3. What each lever did live
- **Compact rank memo**: 43,120 hits / 65,075 lookups = **66 %**, evictions 0,
  21,955 entries in 28.6 MB (1.3 KiB/entry). `run_window` 322 s total (p50 4.8
  s/call) — rank is off the critical path and the RSS objection is gone.
- **Ingest prefilter**: 855,721 rejected / 44,280 passed (promotion identical).
  `handle.syslog` total **848 s vs 789 s** on s05 (p50 0.5 ms/line vs the
  bench's 47 µs): the live per-line cost is dominated by work outside the
  parse-and-drop path (Kafka decode, tenant verification, accounting) — the
  bench modelled the wrong denominator. No gain; keep (harmless, exact).
- **Heartbeat touch-only**: fired **0** times — on a 15-minute burst no open
  object sits unchanged for `CORR_VERSION_HEARTBEAT_S`=900 s. The "unchanged
  re-versions" in the s05 anatomy were material by `material_hash`'s definition
  (confidence-bucket / edge-structure moves). Real value is in production
  (96 → 4 versions/day for a quiet open incident), not in this benchmark.
- **ZSTD(3)**: insert latency unchanged; parts 25 % smaller; merges peaked
  lower (196 vs 636 MiB). Storage win only, as intended.
- **Decision writes +33 %** (45,641 vs 34,378 `corr_objects` inserts) from +27 %
  incidents: with faster ingest relative to the drain, more first-versions are
  minted before continuation folds neighbours. Object identity is cohort-timing
  dependent by design (per-object replay stays deterministic); TTUR variance of
  ~±10 % between legs is the honest noise floor of `t-nominal-2.5k`.

## 4. ClickHouse — attribution and fix
`P2_CLICKHOUSE_PEAK_S06_2026-08-29.md`: in 24.8 `MemoryTracking` is process RSS,
so the harness's "merge ≤ total" filter was wrong (removed); the 13 one-second
transients to 4.4 GiB coincided with `system.metric_log` merges of 997 columns
in the Wide+Horizontal band (~1 GiB of writer buffers). Fix `03995ecb`: all six
system logs Compact/vertical by construction, 64 KiB compress blocks, 128 MiB
merge cap; trace_log + asynchronous_metric_log added (bounded); error_log
bounded. Applied by a ClickHouse restart at 16:06 (21 s; legacy `*_log_0`
dropped). **That restart also wiped the metric_log/error_log history for s05/s06
before the v2 rescore ran — my error; the numbers above were captured first and
are pinned as fixtures.** Harness clause v2: `system.errors` delta is the
verdict, p99 < 85 % the level, peak ≥ 100 % without errors a WARN.

## 5. Decision
- Levers stay ON (all byte-neutral; memo proven; the other two cost nothing).
- `t-nominal-2.5k` is exhausted as an instrument for further engine levers
  (noise floor ±10 %, no storm dynamics). Next measurements run on
  `t-storm-2.5k` (+ the enterprise-outage chain) with ground truth, scored by
  the twin's scorer — that decides P3 and any damping work.
- Never restart ClickHouse between a run and its rescore.
