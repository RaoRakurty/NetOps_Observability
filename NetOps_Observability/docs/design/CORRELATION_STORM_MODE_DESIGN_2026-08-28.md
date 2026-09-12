# Correlation engine — explicit storm mode (design, 2026-08-28)

Fable design. Implements the **last open benchmark P0** (§5 of
`Correlix_Correlation_Engine_Market_Benchmark.docx`): *"Add an explicit storm
mode. Detect queue age/rate → dedup repeats, prioritize major/critical evidence,
aggregate low-value repeats into counters, preserve raw events in the durable
bus/store for replay."* Directly targets the 2.5k `correlation_completion` FAIL
(pending 15,638, oldest_pending_age 310s) — the engine now SURVIVES the storm
(stability PASS after `fa4857a5`) but can't COMPLETE in budget on one shard.
Storm mode reduces per-cycle correlation WORK under overload so the important RCA
completes in budget, without losing anything durably.

## What exists today (build on it, don't duplicate)
- **Detection:** `_storm_state(buffered, maxlen)` (main.py:852) → bool from buffer
  fill fraction; threaded as `storm_mode` into `build_object` (main.py:3636).
- **Marking:** an object built under storm carries `storm_mode=True`, embedded in
  its `hypotheses_blob` degradation block (engine.py:1906) — **replay-safe and
  already part of the content hash contract** (degradation embedded only when
  present, so healthy objects stay byte-identical).
- **Shedding today:** window `deque(maxlen)` silently FIFO-evicts overflow
  (`corr_window_overflow_dropped_total`, main.py:7199) — **severity-blind and
  lossy-looking**. Raw events remain in Kafka (bus retention).

**Missing = the four active behaviors.** We add them, GATED on detection, so
normal (non-storm) operation stays byte-identical.

## The four behaviors (all DETERMINISTIC + replay-safe + gated)

### 1. Dedup repeats (deterministic)
Within a correlation window, collapse repeated signals with the same
`(entity_id, kind, severity, band)` identity into ONE representative + an
`occurrences` count. Pure function of window content (stable: keep the
first-by-(observed_at, signal_id), sum the rest into the count). Cuts window
pressure and object size before grounding runs.

### 2. Prioritize major/critical evidence (stable order)
When the per-cycle time budget (the `_loop_yield` budget from `fa4857a5`) forces
deferral, process objects/components in **severity-descending, then stable-key**
order (`_SEV_RANK` desc, then entity key). Critical/major RCA is built and
persisted FIRST; low-severity object construction defers to the next cycle. Never
drops critical — only reorders.

### 3. Aggregate low-value repeats into counters (deterministic)
Under storm, low-severity (< `severity_open_floor`, today "high") repeated events
that would each spawn a weak singleton object instead increment a counter on a
per-tenant **aggregate "storm-noise" object** (`occurrences`, `distinct_entities`,
`peak_severity`, window span) rather than N full-grounded objects. One bounded
aggregate object replaces a flood of weak ones. Deterministic (function of the
window's low-value residue). Marked `storm_mode=True` (degraded → replayable).

### 4. Preserve raw for replay (invariant, make it explicit + observed)
Storm mode NEVER drops from Kafka — raw events stay in the durable bus at its
retention. Storm mode only bounds the IN-MEMORY correlation window / per-cycle
work. Every storm object is marked degraded, so a later replay (not under storm,
e.g. the archive-slice replay path) reconstructs FULL correlation. Replace the
**silent severity-blind FIFO drop** with: when the window saturates, evict/aggregate
**low-value first** (severity-ascending), never critical — and count it into the
aggregate object (§3), not a silent counter. Emit
`corr_storm_mode_active`, `corr_storm_aggregated_total`,
`corr_storm_deduped_total` metrics (no silent failure, §10).

## Correctness constraints (NON-NEGOTIABLE)
- **Determinism / replay:** every storm decision is a pure function of window
  content + the recorded `storm_mode` flag — no wall-clock, no `random`, no
  dict-order. Replaying a storm object reproduces it byte-for-byte.
- **Gated:** with the detector OFF, output is **byte-identical to today**
  (pin against golden-wire/replay). Storm behaviors activate ONLY when
  `_storm_state` fires. This is a DELIBERATE semantic change UNDER STORM (like
  Lever 1's hub-cap) — owner-visible, tests updated to the new reference.
- **Severity floor honored:** the existing `severity_open_floor` still governs
  what opens a real object; aggregation only touches BELOW the floor.
- **Tenant isolation (§3a):** dedup/aggregate strictly within one tenant's window;
  the storm-noise object is per-tenant, stamped from the window's tenant.
- **Hash contract:** the aggregate object + `occurrences` counts embed in the
  degradation-scoped context only (present-only), so a non-storm object's hash is
  unchanged.

## Detection tuning (deterministic trigger)
Reuse `_storm_state` (buffer fraction ≥ threshold). ADD a backlog-age arm:
storm-active also when the reconciliation backlog's oldest pending age exceeds
`CORR_STORM_BACKLOG_AGE_S` (default from the observed 310s failure — propose
120s). Both arms are recorded so the object's `storm_mode` reflects the actual
trigger. Env knobs: `CORR_STORM_BUFFER_FRAC` (existing), `CORR_STORM_BACKLOG_AGE_S`,
`CORR_STORM_AGG_FLOOR` (severity below which low-value aggregation applies).

## Test plan (REQUIRED)
1. **Gated byte-identical:** detector OFF → golden-wire/replay/damping/166/162/168
   all byte-identical to pre-change (the safety pin).
2. **Dedup:** a window with K identical repeats → 1 representative + occurrences=K,
   deterministic; grounding unchanged for the representative.
3. **Aggregate:** a flood of N low-value (< floor) repeats → 1 storm-noise
   aggregate object with occurrences=N, NOT N objects; critical events in the same
   window still get full objects.
4. **Prioritize:** under a per-cycle budget, critical objects persist before
   low-severity; no critical ever deferred behind low.
5. **Preserve/replay:** a storm object replays (archive-slice path) to a full,
   non-degraded correlation; raw event count in the bus unchanged (nothing dropped
   from Kafka). Severity-aware eviction never drops a critical when a low-value
   exists.
6. **Throughput:** at the 2.5k storm shape, per-cycle correlation work + pending
   backlog drop vs `fa4857a5`-only (the completion-in-budget target).

## Sequencing
Opus builds (determinism NON-NEGOTIABLE); Fable verifies byte-identical gated
path + reviews the semantic-change tests. Then deploy → re-run 2.5k (does
`correlation_completion` PASS?) → 2-worker scale-out proof → publish tiered
envelope → **freeze** (benchmark P1). See [[soak-retention-cap-lesson]],
docs/scale/ENGINE_DECISION_2026-08-28.md, docs/design/CORRELATION_ENGINE_THROUGHPUT_STAGE2_2026-08-27.md.
