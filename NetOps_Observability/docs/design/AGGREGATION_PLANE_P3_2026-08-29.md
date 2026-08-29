# P3 — Aggregation plane (design, 2026-08-29)

Authority: owner memo `/var/tmp/Correlix-Bottleneck-Modified.md` §2.A, §16–§19,
§21–§25; research synthesis (backplane = Netcool-Tally-style dedup BEFORE graph
build); storm-mode design `CORRELATION_STORM_MODE_DESIGN_2026-08-28.md` (what
exists: post-graph, storm-gated dedup + aggregate object); P2 verdicts
(`P2_STEP5_2P5K_VERDICT_2026-08-29.md`). Vocabulary: Aggregation / Decision /
Evidence planes; "priority-aware materialization"; lossless always.

## 0. Where P2 left the engine, and why P3 is next
After P2 the 2.5K storm completes in 1,986 s of 2,700 and T1 p95 is 1,947 s —
still ~390× the 5 s SLO, and TTUR is still queueing latency. The per-cohort
cost is now the synchronous Decision write (`persist.decision` 2,426 s of ≈3,900
s engine time for 40,321 versions). Version anatomy (run p2-s05): first 32 %,
terminal 32 %, evidence growth 17 %, verdict change 7 %, unchanged heartbeat
15 %. Raw→verdict amplification: 900,001 raw → 43k signals in object slices →
40.3k versions → 2.9k verdict changes (~310 : 1). Damping alone buys ≤15–25 %.
**The remaining order-of-magnitude is upstream: most raw events are repeated
observations of an identity whose causal state did not change, and every one
of them is today a Signal in the window, a node in a component, a reason to
re-rank/re-version.** P3 moves the collapse to the ingest boundary, ALWAYS ON
(not storm-gated), deterministically, with raw retained.

## 1. What exists (build on it)
- Window dedup by `signal_id` only (main.py ~1004): identical re-deliveries collapse; repeats with new ids do not.
- Storm-gated, post-graph node dedup `_storm_dedup_node/_comp` (engine.py:2622): collapses a node's signals to a representative + `occurrences` — keeps grounding identity, moves no verdict; embedded in the blob's degradation block (replay-safe).
- Storm aggregate object for below-floor singletons (`storm_agg_floor`).
- Kafka retention + `corr_signals` (every raw event persisted; accounting gate) + `corr_signals_archive` slices (replay input).
P3 generalizes the first two into an always-on, pre-correlation, content-addressed **aggregation state** and makes the engine consume **state deltas**.

## 2. Step 0 — MEASURED (`docs/scale/P3_AGGREGATION_OPPORTUNITY_2026-08-29.md`)
**Result: the ratified `t-nominal-2.5k` workload has almost no aggregation
opportunity.** Offline re-instantiation and the live Kafka window agree to ±1
event: 900,001 raw → 44,280 promoted signals (4.9 %); identities K1=K2=K5=31,955;
K3 (60 s bucket) 44,280 → **0 % reduction**, K4 (300 s) 1.6 %, whole-run 27.8 %;
per-kind repeat factor 1.00; **state transitions 0, recoveries 0** — the
generator pins each device's state for life (`seq % 2`, 2,500 devices even) and
gives every identity ONE source and ONE vantage, so memo §17/§18's causal
classes are unexercised by this benchmark. Amplification: raw→verdict 308:1
(a graph property, unchanged by aggregation); signal→verdict 15.2:1 → 11.0:1
(ideal); **version→verdict 14.0:1, version→material 3.96:1**.
Consequences: (1) P3 is NOT sized against t-nominal — re-measure on the storm
profiles `s1-2.5k` / `s4-chatter` (the only ratified profiles with sub-bucket
repetition) before choosing AggKey; (2) **version damping (14:1) and early
rejection of non-promoted raw lines (95 % of `handle.syslog`'s ~790 s) move
AHEAD of P3 in the lever order**; (3) the benchmark's lack of flap/recovery
dynamics is a harness fidelity gap filed as tracker 183 — a storm benchmark
with no recovery transitions cannot validate the product's storm behaviour.
Per memo §5/§6 on the ratified workload: unique semantic events under key
candidates K1..K5, repeat factor per kind, share of events that are first
occurrence / state transition / recovery (must be synchronous) vs repeat (aggregatable),
and the projected raw→engine ratio. **No aggregation key is chosen until this
is measured** (memo §16: "do not blindly use this example").

## 3. Architecture
```
Kafka raw (lossless) ──► ingest parse ──► corr_signals (accounting, unchanged)
                                   └──► AGGREGATION STATE (per tenant, bounded)
                                          key = AggKey(sig)          [content-derived]
                                          state = {first, last, count, sev_dist,
                                                   transitions, distinct sources/
                                                   vantages/modalities, recovery,
                                                   offset_range, sample refs}
                                          emits DELTA signals ──► engine window
                                                                   (Decision plane)
```
- **AggKey** (final form decided by step 0; candidate = `tenant | entity_id |
  kind | severity band | topology_epoch | event-time bucket`). Content-derived
  only: event time, canonical fields, topology epoch — never arrival time,
  never wall clock (memo §21).
- **Delta emission** = the memo §17 list, as a deterministic classifier on the
  aggregation state transition, not on rate: first occurrence · state
  transition (up/down, adjacency, reachability) · new independent vantage or
  modality · contradictory healthy observation · recovery · count crossing a
  content-derived threshold (e.g. 1 → 10 → 100, not "every N seconds") ·
  blast-radius/ownership changes are engine-side (Decision plane) and unchanged.
  A repeat that changes nothing updates the state (count/last/offset_range) and
  emits **nothing** to the engine.
- **The delta signal** is a `Signal` with the existing `occurrences`-style
  fields the storm path already models (`storm_occurrences`, distinct entities,
  span) generalized: `agg_count`, `agg_first_ts`, `agg_last_ts`,
  `agg_distinct_sources`, `agg_offset_range`, `agg_key`. Node/edge/rank consume
  it as today (rank is a function of kind/entity/severity/witness projection —
  counts are attrs the catalog may score but need not).
- **Lossless**: `corr_signals` keeps every raw row (accounting unchanged);
  the aggregation state and every delta carry the raw Kafka offset range and
  sample signal ids, so replay/forensics reconstruct the full sequence; the
  archive slice for an object records the delta signals it was built from
  **plus** the aggregation keys, so `replay` can re-derive either level.
- **Bounded**: per-tenant LRU by key with content-derived expiry (event-time
  horizon = retention horizon), size cap → oldest-by-event-time eviction
  (counted, never silent); backpressure to ingest when full (§9), never drop.
- **Determinism**: the state machine is a pure function of the event-time-
  ordered raw stream per key (arrival reordering within the permitted lateness
  is re-imposed by event time before the transition is evaluated — same discipline
  as the window). Two replicas with the same partition produce identical deltas.
  Runtime load may change WHEN a delta is processed, never WHICH deltas exist.

## 4. Storm mode's new home
Storm mode's dedup/aggregate/prioritize behaviors become the aggregation
plane's normal operation; the storm detector keeps only what is genuinely
load-dependent and semantics-free: the loop-yield budget and priority ORDER of
processing (severity-descending, stable). `_storm_dedup_node` stays for the
window-saturation edge case but should rarely fire.

## 5. Versioned representation + equivalence (memo §24)
This is a deliberate new representation (delta signals with aggregation fields):
- `content_hash`/blob bytes for objects built from deltas WILL differ from
  objects built from raw repeats. Pin an explicit equivalence test instead of
  byte identity: same final root cause, seam, owner, blast radius (within the
  defined semantics), same raw-event coverage (Σ agg_count == raw count per
  object), no cross-tenant contamination, no false merge/split (memo §25) on the
  166/162/168 fixtures and the storm fixture; flag `CORR_AGGREGATION_PLANE`
  (default OFF until the equivalence suite passes, then ON).
- Golden-wire fixtures gain an aggregated twin; the un-aggregated path stays
  byte-identical under the flag OFF.

## 6. Expected effect (to be replaced by step-0 numbers)
If the ratified mix's repeat share is R, signals reaching the engine fall by
~R, cohorts/versions/Decision writes fall proportionally, and T1 for the
first occurrence of an identity is no longer queued behind its own repeats.
The memo's §6 ratios (raw→verdict, evaluation waste) become the acceptance
metrics; TTUR SLOs are re-measured with `scale-rca-latency.py`.

## 6a. Controlled storm shape (owner direction, 2026-08-29 evening)
The benchmark's storm share is now a KNOB, not an accident: `StormShape`
(`scripts/enterprise_outage_chain.py`) parameterizes storm share of raw, repeat
factor and window, vantages per cause, recovery ratio, flap cycles, churn
density, contradictions, blast-radius waves — all seeded/content-derived. A
profile ladder `t-storm-2.5k` (2 %) → `t-storm-10-2.5k` → `t-storm-25-2.5k` →
`t-storm-50-2.5k` at the same 900k/1,000 eps plan lets P3 be A/B'd at
controlled repeat shares; ground truth records target vs achieved memo-§5/§6
metrics and the projected raw→engine ratio under ideal K3 aggregation. P3 is
built only if the ladder shows (a) a TTUR/T4 gain on storm incidents and (b) a
throughput gain at a realistic share (≈25 %). The twin's `_tpl_enterprise_outage`
takes the same shape so accuracy runs use identical streams.

### 6b. Ladder measured (offline step-0 at plan time, 2026-08-29 evening)
| rung | storm share | promoted signals | repeat share | engine signals → with K3 agg | reduction |
|---|--:|--:|--:|--:|--:|
| t-storm-2.5k | 1.8 % | 54,766 | 35.5 % | 54,766 → 54,766 | **0 %** |
| t-storm-10-2.5k | 10 % | 98,635 | 67.0 % | 98,635 → 63,382 | **−36 %** |
| t-storm-25-2.5k | 25 % | 172,452 | 76.9 % | 172,452 → 76,819 | **−56 %** |
| t-storm-50-2.5k | 50 % | 285,958 | 86.4 % | 285,958 → 73,523 | **−74 %** |
Transitions/recoveries are still forwarded synchronously in every row. At the
ratified rung the K3 collapse is consumed entirely by must-forward classes;
from 10 % up, aggregation is the dominant lever, and absolute engine load
with aggregation peaks at 25 % and falls at 50 % (the irreducible residual is
the background's fan-out). **Decision: build P3 (steps 1–4 below), A/B on the
10 % and 25 % rungs; the 2 % rung is the regression guard (must be neutral).**

## 7. Delivery (each flagged, A/B on one image; Opus builds, Fable grades)
0. Step-0 measurement (in flight) → choose AggKey + delta classes.
1. Aggregation state + delta classifier as a pure module (`aggregation.py`),
   property-tested (determinism under reordering, boundedness, lossless
   accounting Σ counts == raw).
2. Ingest wiring behind `CORR_AGGREGATION_PLANE` + metrics (memo §5: raw eps,
   unique semantic eps, duplicates eps, state-changing eps, recovery eps).
3. Signal/archive/replay representation (agg fields, offset ranges) + the
   equivalence suite (§5) + false-merge/split metrics (memo §25).
4. Live 2.5K A/B (flag OFF vs ON) to the completion gate; TTUR re-measure (P4).
