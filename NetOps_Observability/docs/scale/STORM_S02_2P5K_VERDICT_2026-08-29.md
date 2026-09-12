# Storm re-run after the tracker-185 fix — `t-storm-2.5k` verdict (2026-08-29, run `storm-s02-08291929`)

**Verdict: 8 of 9 phases PASS. Completion in 118 s (s01: 2,171 s), accounting
exact, memflat PASS on all 9 containers (ClickHouse 0 refusals — the backfill
fix holds), correlation flat. Stability FAIL on one 35.7 s loop stall (s01:
114.8 s) that exceeds the 30 s Kafka session timeout — a second, smaller
loop-thread stage (the epoch lifecycle pass, un-instrumented until now) that
the storm population exposes; fix in build. T1 p95 on storm incidents 1,054 s.**

Image = HEAD at launch (P2 complete + `675966cd` signal-aware offload gates +
batcher-lock/GC residuals), harness `29686b0c`. Replica-4 carried the tenant.

## 1. Phases
preflight PASS · onboard PASS (ratio 0.63 — #175 debt at the floor) · burst
PASS 900,000/900,000 @ 1,000/s · drain PASS 1,026 s (storm transport cost is
intrinsic: +2,700 promoted signals, 47,012 vs 44,280) · **completion PASS 118 s**
(cohorts +23, versions +12,746, 0 rejections) · accounting PASS · **memflat
PASS** (9/9 containers; correlation ×0.96 / ×1.13 vs pending-0 anchor;
ClickHouse anon ×0.80, MEMORY_LIMIT_EXCEEDED +0) · **stability FAIL** (worst
stall 35,690 ms > 30 s; 106 UnknownMemberId, 2 CommitFailed, 2 consumer
restarts) · cleanup: pending at write time.

## 2. s01 vs s02 — why s01's numbers were inflated
s01's consumer was ejected during its 115 s stall and Kafka re-delivered:
`handle.syslog` 1,787,273 calls vs **780,954** here, prefilter passed 75,199 vs
**47,012**, 5,889 incidents vs **2,754**, versions 67,695 vs **10,614**. s02 is
the honest storm baseline. Storm mode never engaged on s02 (deduped 0,
aggregated 0): without the stall the window never filled. Rank memo 9,719 /
19,094 = 51 % (storm repeats fold before ranking). Heartbeat touch fired 119×.
Evictions 23,210 (nominal 17.8k): storm identities age past the horizon more
often — the P3 lever.

## 3. TTUR on storm incidents (clean scope)
2,754 incidents · 13,317 versions (4.84/inc) · Σ signals 91,460 · T1 p50 453 s ·
**p95 1,054 s** · p99 1,229 s · max 1,622 s · T-last p95 2,203 s · merged 162 ·
undetermined 0 · **confirmed 0**. **Twin scorer (bounded, 21 queries, 46 s):
322/345 = 93.3 %** (s01: 321/345) — detection 100 %; every miss is the
`affected_includes` clause on the chained templates (`enterprise_outage`,
`upstream_link_failure`): the cause device is not in the site object's affected
set — tracker 187 (blocked on parser gaps 184). `STORM_S02_ACCURACY_2026-08-29.md`.

## 4. The remaining defect (tracker 185, part 2)
Stall at 20:01:09→20:01:44 begins right after a cohort's reconciliation lines;
no instrumented stage covers it (`run_window` is on the executor,
`batch_flush` is now wall-clock only). The epoch lifecycle pass —
`find_merges` over the 20-cohort survivor window × candidates, and the
continuation index — is the un-instrumented loop-thread work that scales with
the open population. Fix in build: spans for every lifecycle stage,
token-indexed candidate pairing, executor offload above a pair threshold,
yields; storm-shaped test under the watchdog.

## 5. P3 status
Steps 1–2 built (`aggregation.py`, ingest wiring behind the flag, default OFF):
engine-forwarded == plan-time K3 exactly on the 2/10/25 % bench rungs; raw
accounting byte-identical. Steps 3–4 (archive/replay representation,
equivalence suite, live A/B on `t-storm-10/25`) next, after the lifecycle fix.
