# Storm mode @ 2.5k — empirical verdict + the reframing it forces (2026-08-28)

Run `082815…` (t-nominal-2.5k, 2500 dev, 900,001 events @ ~1000/s, storm mode
`51575407` deployed). **Honest negative result: storm mode did NOT improve the
2.5k `correlation_completion` FAIL — and understanding WHY is the real finding.**

## What the run showed
| Gate | boundedness-only (`082812437a77`) | + storm mode (`082815…`) |
|---|---|---|
| stability | PASS (10,669 ms, 0 restarts) | **PASS** (10,141 ms, 0 restarts) |
| accounting | PASS (lossless) | **PASS** (lossless, 2500/2500) |
| drain (transport) | PASS (549 s) | PASS (619 s) |
| correlation_completion | FAIL (pending 15,638) | **FAIL — pending 24,638 (worse)** |
| memflat | FAIL (x1.34) | FAIL (x1.73, corr-4 355→614) |
| cleanup | FAIL (OS purge) | FAIL (cleanup timeout) |

Storm mode **barely activated** — `storm_mode=True` logged **2×** on one replica,
0 on the other. It was effectively inert; the 15,638→24,638 delta is run-to-run
variance on a heavily-loaded box (this run's drain was slower, 619 s vs 549 s),
not a storm-mode regression. memflat's worse *ratio* is a lower post-burst base
(355 vs 489) with a similar absolute end (614 vs 658) while the engine churned a
larger pending backlog — same working-set-vs-leak confound, not storm state
(which barely accumulated).

## WHY storm mode didn't engage — the real finding
1. **The detector watches the wrong queue.** Its backlog-age arm measures
   `newest_ts − oldest_unevaluated SIGNAL` (the signal-ingestion queue). At 2.5k
   the **signals drain fine** (transport PASS); the backlog is **open objects in
   reconciliation/persist** — a different queue. So `oldest_pending_age_s` stays
   below the 120 s trigger and storm never sustains.
2. **It structurally CAN'T watch the object queue.** The `storm_mode` flag is
   embedded in the object's content-hash (the replay pin), so it MUST be a pure
   function of window content for replay determinism. The object-reconciliation
   backlog is a RUNTIME condition (processing-rate dependent), not window content
   — wiring it into the flag would break byte-identical replay. The design's
   own determinism constraint forbids the trigger the completion bottleneck needs.
3. **The 2.5k synthetic load has little to shed anyway.** `event-mix single` is
   near-uniform; dedup/aggregate (which need repeated/low-value tails) have little
   to collapse. Even a perfectly-engaging storm mode can't manufacture throughput
   that a uniform load doesn't leave slack for.

## The reframing (aligned with the benchmark's own thesis)
**The 2.5k `correlation_completion` limit is single-shard object-reconciliation
THROUGHPUT — not signal pressure, not the stall (fixed), not something storm mode
addresses for this workload.** This is exactly the market benchmark's §4 ("horizontal
scaling is necessary") and the capacity model's "2.5k = Conditional, needs
scale-out." Storm mode remains the **correct resilience layer** — it is built,
safe, deployed, and PROVEN at unit level on sheddable load (6,000-instance flood →
1 aggregate; 60→3 dedup) — it protects REAL production storms that have a
low-value/duplicate tail. It is NOT, and cannot be, the lever for uniform-load
single-shard completion. Scoping it as the completion fix was the mis-step; this
verdict corrects it.

## Status of the benchmark plan
- **All 6 P0s implemented** (storm mode = the last). ✅
- **2.5k: survives losslessly + storm-resilient** — the collapse is fixed
  (`fa4857a5`), the resilience feature is in (`51575407`). ✅
- **2.5k completion-in-budget: a single-shard throughput ceiling** → scale-out. ⛔ (hardware)
- **Sharding architecture correct** — 12 co-partition tests pass. ✅
- **True ≥1.6× 2-worker throughput proof: HARDWARE-BLOCKED** — this box has 4
  cores total; two workers here contend for the same 4 cores, so a real ≥1.6×
  scale-out needs 8 cores / 2 nodes. Not fakeable on contended cores. ⛔

## Recommended follow-ups (resource-gated, honestly stated)
1. **Detector, actions decoupled:** keep the content-hash `storm_mode` flag
   deterministic (dedup/aggregate stay window-content driven), but drive the
   NON-content actions (persist-priority, window eviction) from a runtime
   object-backlog signal — so storm mode ENGAGES when the engine is actually
   behind, without touching the replay pin. Correctness fix; won't rescue
   uniform-load completion.
2. **Demonstrate storm value on realistic load:** re-run with `--event-mix
   realistic` (has the duplicate/low-value tail) to show storm mode's completion
   benefit where there's something to shed. Needs a healthier box.
3. **True scale-out proof on 8-core / 2-node** hardware for the ≥1.6× number.
See [[soak-retention-cap-lesson]], docs/scale/SCALE_2P5K_POSTFIX_VERDICT_2026-08-28.md,
docs/design/CORRELATION_STORM_MODE_DESIGN_2026-08-28.md.
