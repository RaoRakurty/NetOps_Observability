# Storm run after the lifecycle index fix — `t-storm-2.5k` verdict (2026-08-29, run `storm-s03-08292148`)

**Verdict: 7 of 9. Completion 104 s (s02: 118 s), memflat PASS 9/9 (replica-3
at 82 % of its cap — flat, but the storm working set is near the ceiling),
cleanup pending. Two FAILs, both new classes exposed by the new
instrumentation: accounting — ONE `netops.findings` row lost to a transport
`ReadError` (that table sits outside the dedup-token retry set; fix in build,
tracker 188); stability — the 35 s merge stall is gone (merge: 278 pairs for
1,142×69 in 0.47 s), but the lifecycle QUIESCE pass and the reconcile loop
tail still block the loop for ~26 s, and with the broker's own heartbeat
channel timing out that was enough to eject the consumer (52 UnknownMemberId
at 22:24, 1 restart; tracker 185 part 3, fix in build).** Image = HEAD
(`12074157`: P3 steps 1–3 flag OFF + lifecycle index fix). Replica-3 carried
the tenant.

## 1. Phases
preflight PASS · onboard PASS (0.85) · burst PASS 900,000/900,000 · drain PASS
1,155 s · **completion PASS 104 s** (cohorts +21, versions +11,208, 0 rejections)
· **accounting FAIL** (`{'netops.findings': 1}` — transport ReadError 22:17:43,
counted LOST, not retried) · **memflat PASS** 9/9 (correlation-3 544 → 959 →
1,046 MiB, ×1.09 vs pending-0, FLAT; ClickHouse anon ×0.70, refusals +0) ·
**stability FAIL** (1 CommitFailed, 53 UnknownMemberId, 1 consumer restart;
worst stall 26.8 s < the 30 s gate but ejected anyway — broker heartbeat
timeouts at 22:22:17) · cleanup pending.

## 2. Instrumentation delivered by this run (the point of the leg)
New spans (max ms): `reconcile.loop` 79,297 (wall) · `lifecycle.merge` 54,334
(wall; the merge INDEX itself is fixed — `corr_lifecycle_merge_pairs_evaluated`
278, `_seconds_max` 0.47) · `lifecycle.quiesce` **26,024** (≈ stall #1) ·
`persist.evidence` 25,827 · `persist.decision` 17,259 · `run_window` 27,978
(executor) · `reconcile.continuation_index` 586. Quiesce closing a batch of
stale objects builds each terminal version inline without yielding; the
reconcile loop's tail does the same for continuations — the next fix.

## 3. Engine (replica-3)
versions 11,208 · heartbeat touches 119 · storm mode not engaged · loop lag
max 26.8 s (s02 35.7, s01 114.8) · GC pause max 0.25 s · open objects peak
1,362 · evictions (to be read at convergence).

## 4. Decisions
- Both fixes (findings retry-safety, quiesce/reconcile yields + 60 s session
  timeout as defence in depth) land AFTER the A/B wave: the wave must run on
  ONE image for both arms, and the stall does not change WHAT is computed.
- The storm profile stays the qualification profile; nominal is the floor.
