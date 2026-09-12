# Storm-time correlation: control/data plane separation (research synthesis, 2026-08-28)

Deep-research synthesis (Fable) answering: where does the 2.5K-device storm burn
cycles that produce no operator answer, and can we borrow the network-device
control/data-plane split to bucket work by product priority? Report artifact:
https://claude.ai/code/artifact/f720c036-b86e-417d-bf91-62d0866e8c9a

Three inputs: (1) a code-grounded analysis of the engine's per-cohort work;
(2) AIOps-vendor + systems-literature web research (cited); (3) verification of
the owner's `/var/tmp/Correlix-Bottleneck.md`.

## The finding (measured, from the code)
The wasted cycles are **breadth-scaling work re-run over incidents whose
operator-facing verdict didn't change**. One sweep freezes an epoch once, then
drains up to `CORR_ENGINE_DRAIN_COHORTS=20` cohorts against it. Tracker-166
hoisted node-build + candidate-index to once-per-epoch, but **component
formation, ranking, snapshot materialization, hashing, reconciliation still run
per-cohort — up to 20× per sweep — over every open incident, with no
"verdict unchanged → skip" gate**. Ranked waste:
1. `run_window` (engine.py:2603) re-ranks + re-materializes every open incident
   per cohort (~300K rank+snapshot builds/sweep at the storm).
2. `content_hash`+`material_hash` recomputed per object per cohort, mostly to
   DAMP (thrown away) — the damp counter proves the waste.
3. Redundant re-serialization within one persist (hash 2×, blob 3–4×) — free fix.
4. Full evidence re-emit when only the tail grew (verdict already settled).
5. O(open-objects) merge/quiesce/cap passes per cohort — belong at epoch cadence.

**The seam already exists:** `material_hash` = stable DECISION identity;
`content_hash` = volatile REPLAY PIN; `_cohort_keys` = which incidents new info
touched. A cohort-touch gate eliminates 1/2/4/7 without moving hash bytes.

## The design — three planes (RIB/FIB discipline)
- **Backplane** (storm-absorbing): cheap synchronous dedup keyed on identity +
  counter BEFORE graph build (Netcool `Tally`); raw stays durable in Kafka. This
  is storm mode's correct home — a front tier, not a per-object flag.
- **Control plane** (= FIB, fast): re-evaluate only `_cohort_keys`-touched
  components; emit cause · blast-radius · owner · **confidence**; small parent row.
- **Data plane** (= RIB, comprehensive/slow): materialize full edges/evidence/
  provenance ASYNC as a Kafka-log-derived materialized view (CQRS), version-keyed
  deltas, rebuildable by replay. Its lag no longer blocks the operator.
- **Cost governor:** the seam graph — traverse edges, typed cause set, time window
  (O(events²)→O(edges)); don't RE-do it per cohort for settled incidents.
- **Priority:** SRE criticality shedding — critical head gets the full graph first;
  low-value tail is deduped-and-counted or verdict-only.

## Determinism guardrails (the linchpin — from the systems literature)
Anything keyed on **wall-clock / elapsed-compute / arrival-order** breaks the
replay pin (anytime stop-point, utilization-triggered shed, unordered async
completion). Uniform fix: **convert every such decision into a content-addressed
quantum** — a checkpoint level derived from the input set, a semantic (content-
keyed) drop rule, an offset-canonical order re-imposed before hashing. Corollaries:
- **Kappa (Kreps):** the two planes must be ONE computation at two completeness
  levels over the same replayable log — NOT two divergent code paths that must
  agree. The decision plane is a *prefix* of the evidence plane's function.
- **Backpressure over shedding:** a durable log lets you stall the evidence plane
  and catch up (changes rate, not input → replay-safe). Only ever "shed" by
  *deferring materialization* of work recomputable from the retained log.
- `content_hash` bytes never move; no runtime backlog signal wired into the hash.

## Owner bottleneck memo — verified
Right destination (progressive / state-delta / two-tier). Corrections: "300 ms per
event" (that's the worst work UNIT post-fix, not per-event; ~100–250 eps/core);
"2.5K EPS" (it's 2,500 DEVICES at ~1,000 eps); Node.js telemetry (engine is
Python/asyncio — loop-lag watchdog exists); **don't adopt Flink/Kafka Streams**
(the engine already IS a Kafka-sharded streaming correlator; a port is a rewrite
+ dependency-rule violation — build the patterns in-engine); "exactly-once" (it's
at-least-once + idempotent dedup); "per-event" waste → sharpen to **per-cohort**.

## Staged plan
- **P0** Measure **time-to-first-useful-RCA** + causal-amplification ratio on the
  current engine (cheap, no new hardware). The metric the whole design optimizes,
  currently unmeasured — and the honest reframing of `correlation_completion`.
- **P1** Cohort-touch gate + memoize the frozen snapshot + hoist O(open) passes to
  epoch cadence. Pure in-engine, low risk, largest single saving. **Start here.**
- **P2** Control/data-plane split (verdict emitted; evidence graph = async
  replayable materialized view). Determinism care at the merge point.
- **P3** Backplane dedup tier + criticality shedding (storm mode's correct home).
- **P4** Re-measure time-to-useful-RCA; then the 8-core/2-node scale-out proof.

## Don't
Adopt Flink/Kafka Streams; chase `correlation_completion` as the gate (scale-out
bound); move `content_hash` bytes; re-serialize a settled verdict's whole graph
every version. See [[soak-retention-cap-lesson]],
docs/scale/STORM_MODE_2P5K_VERDICT_2026-08-28.md,
docs/design/CORRELATION_STORM_MODE_DESIGN_2026-08-28.md.
