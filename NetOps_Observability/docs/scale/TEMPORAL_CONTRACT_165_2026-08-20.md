# Tracker 165 — the RCA temporal contract, derived rather than declared

**Date:** 2026-08-20 · **Scope:** correlation engine + evidence window ·
**Status:** 165 semantics RESOLVED, retention fix NOT yet implemented · 164 measured passively

---

## 1. What `window_s` actually is

`ENGINE_CFG.window_s = 900.0` is **not an RCA contract.** Evidence:

| Question | Answer | Source |
|---|---|---|
| Does the engine core read it? | **No.** Its only appearance in `engine.py` is a comment. | `engine.py:1499` — *"the caller buffers cfg.window_s"* |
| Where is it read? | Four caller-side sites, in **two different clock domains**. | `main.py` prune horizon + overflow classifier (event ts vs wall clock); `consumer_state()` / `cold_partitions()` (monotonic) |
| Is it operator-tunable? | **No.** `ENGINE_CFG = EngineConfig()`, all defaults; no `CORR_WINDOW_S` env exists. | `main.py:905` |
| When did it enter? | First engine commit, never changed since. | `c5de198c`, 2026-06-12 |
| Any doc / spec / test / API / customer surface asserting a 15-minute horizon? | **None found.** | repo-wide grep of `docs/`, `*.py`, `*.go`, `*.yml`, `*.tsx` |
| Do the two tests mentioning it assert it? | No — both use it only to build a value "definitely outside". | `test_corr_continuation.py:176`, `test_ga_failure_accounting.py:361` |

**Verdict: category B — a stale, unproven buffering constant.** It is retained
as the wall-clock prune bound it always was, and is now *labelled* as such
(`corr_window_horizon_seconds` help text, `retention_state()["prune_bound_s"]`).

One consequence worth knowing: `window_s` participates in `config_hash()`, so it
is stamped into `engine_version` on every persisted object. Changing its value
is a version-visible event, not a silent edit.

---

## 2. The formula that does bound correlation in time

From `score_edges` (`engine.py:820–852`):

```
w_t    = exp(-gap / tau_s)
weight = min(w_t * w_topo * w_r, 1.0)
admitted  iff  weight >= attach_threshold
```

The `min(..., 1.0)` clamp **cannot decide admission** — it binds only when the
product already exceeds 1.0, far above `attach_threshold`. So the boundary is

```
exp(-gap / tau_s) * w_topo * w_r = attach_threshold
```

and therefore

```
max_attachable_gap = tau_s * ln( (w_topo * w_r) / attach_threshold )
```

with `NEVER_ATTACHABLE` when `w_topo * w_r < attach_threshold` (no gap works).

Implemented as `engine.max_attachable_gap_s()` / `engine_temporal_reach_s()` —
**derived, not a constant**, so retuning any weight moves it automatically.

### Reach by grounding and modality (`tau_s=300`, `attach_threshold=0.3`)

| Grounding | w_topo | Modality multiplier | Max attachable gap |
|---|---:|---:|---:|
| containment | 0.90 | 1.00 | 329.58 s |
| **containment** | **0.90** | **1.25** | **396.53 s** |
| path | 0.90 | 1.00 | 329.58 s |
| **path** | **0.90** | **1.25** | **396.53 s** |
| seam | 0.80 | 1.00 | 294.25 s |
| seam | 0.80 | 1.25 | 361.19 s |
| adjacency | 0.65 | 1.00 | 231.96 s |
| adjacency | 0.65 | 1.25 | 298.90 s |
| inferred | 0.50 | 1.00 | 153.25 s |
| inferred | 0.50 | 1.25 | 220.19 s |
| candidate | 0.50 | 1.00 | 153.25 s |
| candidate | 0.50 | 1.25 | 220.19 s |
| *(stale-capped)* | 0.40 | 1.25 | 153.25 s |

**Absolute maximum useful engine reach = 396.53 s.**

### Correction to the wave premise

The wave was scoped around **361 s**. That figure is the *seam* cross-modality
row, and it is what you get by clamping `w_topo * w_r` at 1.0 **before** solving.
The code clamps the full product *including* `w_t`, so the correct maximum is
**396.53 s** — 35.3 s further back. Targeting 361 s would have under-retained.

Verified against the engine, not just algebra: `test_temporal_reach_165.py`
bisects the real `build_edges` for the largest gap it still admits and asserts
agreement to 0.01 s, then straddles the boundary at ±0.5 s.

---

## 3. Event time vs wall clock — the answer is "a mixture"

| Decision | Code path | Time source | Intended semantic | Risk |
|---|---|---|---|---|
| Edge admission (`gap`, `w_t`) | `engine.py:818–821` | **Event time** (`Signal.ts` only) | Correlate what happened close together | none — this is the authority |
| Node onset / peak severity | `engine.py:286–314` | Event time | Episode interval | none |
| `window_start/end` on the object | `engine.py:1691` | Event time | Evidence span | none |
| **Evidence pruning** | `main.py` `_prune_buffer` | **Wall clock** `now()` compared against **event** `ts` | "drop evidence older than the horizon" | **the defect** |
| Capacity-drop eligibility | `buffer_signal` | was wall-clock arrival → **now event time vs `ENGINE_REACH_S`** | "was this still usable?" | fixed this wave |
| Future-ts clamp / past-stale count | `buffer_signal` (H14) | Wall clock, ±`METRIC_FUTURE_SKEW_S` / `METRIC_MAX_AGE_S` | bound a broken device clock | intended |
| `consumer_state` / `cold_partitions` | `main.py:3791/3803` | **Monotonic** vs `window_s` | liveness proxy | third clock reusing the same constant |

**Answer: Correlix SCORES in event time and RETAINS in wall-clock time.**

Because pruning ages *event* timestamps against *wall-clock* now, the retained
event-time span is

```
retained_span = window_s - processing_lag
```

Measured lag on the 1K rig was **12–19 minutes (720–1140 s)** against a 900 s
window — i.e. squarely inside, and past, the zone where the window retains
nothing at all.

### Delayed-processing result (`test_event_time_semantics_165.py`)

Story: **A at 12:00, B at 12:05** — 300 s apart, containment-grounded, well
inside the 396.5 s reach. The engine attaches them (asserted).

| Processing delay | Signals surviving prune | RCA edge |
|---|---|---|
| 10 s | 2 | **forms** |
| 15 min | 1 (the **cause** is evicted) | **gone** |
| > 900 s | 0 | gone |

Nothing about the story changed. **Processing delay alone destroys
event-time-valid evidence**, and the `window_s − lag` formula is asserted
directly at lag = 0 / 300 / 600 s.

This is a temporal-semantics defect. No source establishes it as intentional.

---

## 4. The retention contract

```
required_retention = engine_temporal_reach + permitted_lateness
                   = 396.53 s + 30.0 s
                   = 426.53 s
```

`permitted_lateness` is **not invented**. Its floor is one engine evaluation
interval (`CORR_ENGINE_INTERVAL_S = 30 s`): evidence that survives to the horizon
but not through the next cycle is never actually scored against, so retaining
less than one cycle past the reach cannot preserve the semantics. Anything
*above* that floor is a deployment fact and must come from the measured
event-time lag (`corr_event_time_lag_seconds`), not from a chosen number. It is
env-settable (`CORR_PERMITTED_LATENESS_S`) but **cannot go below the floor**.

The contract is **time-based**. The record cap remains, demoted to what it should
always have been: a resource safety ceiling, not the definition of RCA history.

---

## 5. What retaining the reach actually costs

Measured in a fresh process, 50,000 realistic 1K-rig signals, including the
dedup set and id deque:

| Component | B/signal | Share |
|---|---:|---:|
| irreducible `Signal` shape | 408 | 40 % |
| `entity_id` + `entity_tokens` (uninterned) | 184 | 18 % |
| `attrs` dict | 168 | 17 % |
| dedup set + id deque | 145 | 14 % |
| `native_id` string | 107 | 11 % |
| **total live heap** | **1,012** | |
| total RSS (incl. pymalloc arenas) | 2,467 | ×2.44 |

**`native_id` is load-bearing and cannot be dropped** — `signal_id =
uuid5(NS, source|native_id|ts_ms)`, and `signal_id` is deliberately not memoised
(tracker 156), so it feeds dedup, the archive-slice hash and the replay contract.

Applying only identity-preserving compaction — interning `entity_id` /
`entity_tokens` and sharing identical `attrs` dicts, exactly the technique
already proven here for `Observer` / `Relation` / `Grounding`:

**1,012 → 549 B/signal, 46 % recovered.**

### Projection at the measured 917.4 signals/s

| Horizon | Signals | Live @1012 B | Live @549 B | RSS @1012 B | RSS @549 B |
|---|---:|---:|---:|---:|---:|
| 54.5 s (today) | 50,000 | 51 MB | 28 MB | 123 MB | 67 MB |
| 396.5 s (reach) | 363,750 | 368 MB | 200 MB | 898 MB | 487 MB |
| **426.5 s (required)** | **391,300** | **396 MB** | **215 MB** | **966 MB** | **524 MB** |

Non-window process overhead measured at ~633 MB (756 MB settled − 123 MB window).
Total to hold the required horizon:

- uncompacted → **~1,531 MB** (needs ~1.6 GiB)
- compacted → **~1,157 MB** (needs ~1.2 GiB)

**Neither fits the current 789 MiB cap.** So raw retention at the engine's reach
is **not practical in the current container, even after compaction** —
compaction cuts the increment by 42 % but does not by itself make the reach
affordable. That is the honest answer to "is a bigger buffer the fix?": no.

---

## 6. RCA ground-truth A/B (`test_rca_retention_ab_165.py`)

One deterministic story — cause at T+0, effects at T+120 / T+240, cross-modality
corroboration at T+350 (350 s span, inside the reach) — under six retention
regimes, with unrelated same-tenant load filling the window.

| maxlen | span (s) | still-eligible drops | degraded | story kept | objects | tier | story nodes | edges |
|---:|---:|---:|:--:|---:|---:|---|---:|---:|
| 60 | 0.6 | 744 | ✅ | 0 | **0** | — | 0 | 0 |
| 200 | 2.0 | 604 | ✅ | 0 | **0** | — | 0 | 0 |
| 300 | 111.0 | 504 | ✅ | 1 | 1 | suspected | 1 | **0** |
| 500 | 231.0 | 304 | ✅ | 2 | 1 | suspected | 2 | 1 |
| 700 | 351.0 | 104 | ✅ | 3 | 1 | suspected | 3 | 3 |
| 20000 (**Run B**) | 353.0 | 0 | ❌ | 4 | 1 | suspected | **4** | **6** |

**Classification:**

1. **Verdict changes** (maxlen ≤ 200) — the RCA object does not exist. Not
   weaker, *absent*. Total loss of the finding.
3. **Verdict same, evidence changes** (300–700) — the object survives with an
   identical headline while its causal graph is hollowed out from 4 nodes /
   6 edges to 1 node / 0 edges.

**The finding that matters most:** the **verdict tier never moves.** Every
retention level that produces an object produces `suspected`. An operator
watching verdicts, confidence or "does an RCA object exist" sees *no difference*
between full evidence and a single-node, zero-edge shell.

That is why degradation has to be reported as its own signal — the RCA output
looks exactly as confident while its evidence base collapses.

---

## 7. Degradation semantics (implemented)

`rca_evidence_degraded()` is true when **the window is at its record cap AND the
retained span is below the engine's reach** — i.e. the count bound, not age, is
deciding the RCA horizon. A merely thin window (quiet tenant, cold start) is
**not** degraded; nothing is being shed. Deliberately conservative: it fires at
the boundary, when the cap becomes binding, rather than after loss.

New exposure on `/healthz` (`retention` block) and `/metrics`:

| Series | Meaning |
|---|---|
| `corr_engine_reach_seconds` | 396.527 — derived, moves with the weights |
| `corr_retention_required_seconds` | 426.527 |
| `corr_permitted_lateness_seconds` | 30.0 (floor = one engine cycle) |
| `corr_window_span_seconds` | effective retained horizon |
| `corr_window_utilization` | fraction of the record cap in use |
| `corr_rca_evidence_degraded` | **0/1 — the alertable state** |
| `corr_window_overflow_in_horizon_total` | still-eligible capacity drops |
| `corr_event_time_lag_seconds` | wall clock − newest buffered event ts |
| `corr_window_horizon_seconds` | relabelled: the wall-clock **prune bound**, not the contract |

**Eligibility is now judged in event time against `ENGINE_REACH_S`**, not against
wall-clock arrival and not against `window_s`. The previously reported **41.4 %
still-in-horizon figure was measured against the wrong yardstick (900 s) and
needs re-measurement** against 396.5 s; it will be lower.

---

## 8. Tracker 164 — passive measurement

Instrumentation added to `_offload` (timings only; admission, executor and
ordering unchanged): queue depth + peak, active/max workers and the *source* of
the worker count, oldest queued age, submitted/started/completed/failed,
wait p50/p95/p99/max, exec p50/p95/p99/max, and `rejected` pinned at 0 with
`queue_bounded: false` so the absence of rejection is an explicit fact.

### Preliminary answer: `_offload` is not the drain bottleneck

All twelve call sites are on the **object-persistence path** (`_snap_call`, gated
at `CORR_OFFLOAD_MIN_ELEMENTS = 2000` nodes+edges, once per snapshot per 30 s
cycle) or the **ClickHouse batch path** (`_ndjson_body`, `_batch_token` — per
*batch*, not per event). **None is on the per-event ingest path.**

Offload arrival rate is therefore bounded by objects and batches, not by event
rate. `OPEN_OBJECTS` was measured at **0–8** during the 1K runs, and objects
below 2,000 elements never offload at all. Tens of calls per cycle against 8
workers cannot accumulate a 12–19 minute backlog.

**This contradicts the architectural suspicion.** Live confirmation under load is
still outstanding — the instrumentation is unit-proven but has not yet run
against a loaded stack — so this is stated as preliminary, not settled.

---

## 9. Three lags, reported separately

| Lag | Definition | Where |
|---|---|---|
| Kafka backlog lag | records not yet consumed | `corr_consumer_lag` (broker-side) |
| Processing lag | how far behind the consumer is in wall-clock time | derived from commit progress |
| **Event-time lag** | wall clock − newest buffered event ts | **`corr_event_time_lag_seconds` (new)** |

Event-time lag is the one that couples to 165: because pruning ages event
timestamps against wall-clock now, `retained_span = window_s − event_time_lag`.
Reporting a single "lag" number made this invisible.

---

## 10. Mutation results

| Target | Mutants | Killed |
|---|---:|---:|
| Reach derivation (`engine.py`) | 6 | **6** |
| Retention contract + degradation state | 9 | **9** |
| Offload instrumentation | 6 | **5** |

Three of my own tests survived their first mutation pass and were strengthened,
not excused:

- *degraded compared against `window_s`* survived because the "healthy" fixture
  spanned 995 s — above **both** yardsticks. Fixed with a case landing in the gap
  between 396.5 s and 900 s, the only place the two can disagree.
- *degradation gauge deleted* survived because the test matched the metric name,
  which the surviving `# TYPE` comment still contains. Now asserts the **sample
  line and its value**.
- *reach gauge reporting `window_s`* survived because the test only checked the
  value parsed as a float. Now pins the actual number.

**One mutant survived and is not claimed as covered.** Removing `_OFFLOAD_LOCK`
passes all 14 tests. Direct probes could not produce a lost update or a torn dict
snapshot on CPython at any switch interval (1e-6, 1e-9) , thread count (8/16/32)
or dict size (200k): `+=` on a module int and `list(dict.values())` both complete
inside one GIL slice. The lock is kept because the language guarantees none of
that and a free-threaded build guarantees the opposite — **not** because a red
test demands it. Recorded in the test's own docstring.

Fixture note: the H14 future-clamp restamps future-dated signals to arrival,
which silently collapses event-time spread. Two fixtures had to be anchored so
the *newest* signal lands at now and the rest run into the past.

---

## 11. Status

| Item | Status |
|---|---|
| **165** | 🟡 **PARTIAL** — semantics resolved, contract derived, degradation observable, A/B complete. **The retention fix is not implemented**: the window still holds 54.5 s against a 426.5 s requirement. |
| **164** | ⏳ open — passively instrumented; preliminary evidence says **not** the bottleneck. Do not implement bounded admission on this evidence. |
| **163** | ⏳ deferred, unchanged — `OPEN_OBJECTS` 0–8 measured; signal retention remains the dominant state problem. |
| **162** | 🟡 PARTIAL, unchanged — revisit only once 165/163 establish a real bound on N. |

Tests added: `test_temporal_reach_165.py` (15), `test_event_time_semantics_165.py`
(7), `test_retention_contract_165.py` (11), `test_rca_retention_ab_165.py` (8),
`test_offload_instrumentation_164.py` (14). `test_prune_buffer_156.py` re-based
onto event-time eligibility (+1). Full suite **1222 passed, 9 skipped**, ruff clean.
