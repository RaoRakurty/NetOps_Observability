# 2.5k full-stack verdict — post boundedness-pass (2026-08-28)

Run `082812437a77` (t-nominal-2.5k, 2500 devices, 900,001 events @ ~1000/s,
2 correlation replicas) on the engine WITH the P0 boundedness pass (`fa4857a5`)
deployed live. Compared head-to-head with the pre-fix run `08271432rnic`.

## Overall: FAIL (6 PASS / 3 FAIL) — but the FAIL moved for the right reason
The boundedness pass **delivered exactly what it targeted**: it converted the
catastrophic engine COLLAPSE into survivable, lossless operation. What remains
FAIL is throughput-completion (the scale-out problem, next step) + a confounded
memflat + a non-product cleanup artifact — NOT the stall it was built to fix.

## The headline win — stability: FAIL → PASS
| | PRE-fix `08271432rnic` | POST-fix `082812437a77` |
|---|---|---|
| stability | **FAIL** — 108,000 ms loop stall **ejected a replica** | **PASS** — worst loop stall **10,669 ms**, **0 restarts**, 0 CommitFailed, 0 UnknownMember, full 4552s lifecycle |
| accounting | PASS (lossless) | **PASS** — 900,001 == 900,001, 0 DLQ, 0 rejections, 2500/2500 covered |
| drain (transport) | PASS | **PASS** — 549s (budget 2700s) |

**The 108s stall that crashed a replica is gone — down to 10.7s with zero
restarts (10× reduction).** The engine no longer collapses under the 2.5k storm;
it survives the full lifecycle and loses nothing. That is the empirical proof the
boundedness pass works on the live stack, not just the micro-benchmark.

(Micro-bench predicted worst work UNIT ~0.30s; the live worst CYCLE stall is
10.7s because a real cycle runs many units + candidate-gen + merges. The bound
cut the aggregate 10×; sub-second cycles at 2.5k need the scale-out, not more
bounding.)

## The 3 remaining FAILs — honestly categorized
1. **correlation_completion: FAIL** — pending=15,638, oldest_pending_age=310s
   after the 2700s budget. This is a **throughput** limit, not a defect: the
   engine is CURRENT-limited at 2500 dev × 1000 eps. It survives (stability PASS)
   and loses nothing (accounting PASS) but can't fully drain the correlation
   backlog in budget on a single shard. **This is precisely the "2.5k = Conditional,
   needs scale-out" position in the capacity model** — the boundedness pass fixed
   the collapse; single-shard throughput at 2.5k is the 2-worker scale-out's job.
   Same FAIL as pre-fix, but now for a BENIGN reason (throughput) not a
   catastrophic one (collapse).
2. **memflat: FAIL** — clickhouse 2622→3503 MiB (x1.34), correlation-3 489→658
   MiB (x1.35) "after input stopped." **Confounded:** correlation was STILL
   ACTIVELY WORKING (15,638 objects pending) during the measurement window, so the
   growth is largely WORKING SET for in-flight objects, not proven leak. correlation-3's
   489→658 is nearly identical to pre-fix correlation-2's 496→691 — but pre-fix the
   replica was EJECTED (dead), here it is alive and churning the backlog. The gate
   itself notes a short window "cannot separate first-touch materialization from a
   leak." **Needs a longer-settle re-measure** (let the 15k backlog fully drain,
   then check the slope) to separate working set from leak. Not a clean FAIL.
3. **cleanup: FAIL** — OpenSearch syslog purge failed, 246,001 run docs left in
   `netops-syslog-*`. **Non-product teardown artifact** (same class as the soak-2
   cleanup FAIL). Devices WERE deleted (registry verified 0 residue); only the OS
   syslog purge step failed. Harmless to correctness; disk hygiene only.

## Verdict
**2.5k moved from "collapses" to "survives losslessly."** It is NOT yet "2.5k
Validated" (completion still misses the budget on one shard), but the boundedness
pass did its job: the engine is now resilient at 2.5k. The path to Validated is
the **2-worker ≥1.6× scale-out proof** (already the next planned step), not more
single-shard optimization. This confirms the ratified plan
(`ENGINE_DECISION_2026-08-28.md`): bound the object (done, proven) → prove
scale-out (next) → publish tiered envelope → stop.

## Follow-ups
- Longer-settle memflat re-measure to resolve leak-vs-working-set on correlation-3.
- Harness robustness: cleanup-on-failure (residue from failed runs blocked tonight's
  attempts) + a preflight that reports drain ETA instead of a bare refusal.
- OS syslog residue (246k docs) purge — stack hygiene.
See [[soak-retention-cap-lesson]], docs/scale/SHARDING_AND_CAPACITY_MODEL_2026-08-28.md.
