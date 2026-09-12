# Tracker 165 — stream-time retention, and the live 1K evidence

**Date:** 2026-08-20 · **Base:** `ac3385b9` · **Run:** `08202225178u` (1000 devices, 600,001 events)
**Bus:** Apache Kafka 4.1.1 KRaft, mTLS (`kafka:9094`) — *not* Redpanda, removed under #97

---

## 1. The contract, derived

```
max_attachable_gap = tau_s · ln( (w_topo · w_r) / attach_threshold )      # engine.py
required_retention = engine_temporal_reach + permitted_lateness
```

| Quantity | Value | Where it comes from |
|---|---:|---|
| engine temporal reach | **396.527 s** | max over all grounding × modality combinations |
| permitted lateness | **30 s** | floor = one `CORR_ENGINE_INTERVAL_S`; evidence that survives to the horizon but not through the next cycle is never scored against |
| **required retention** | **426.527 s** | reach + lateness |

Single source of truth: `engine.engine_temporal_reach_s()` / `required_retention_s()`.
`main.py` derives `ENGINE_REACH_S` / `RETENTION_REQUIRED_S` from them and nothing
recomputes either. Verified live on the running container:

```
corr_engine_reach_seconds        396.527
corr_retention_required_seconds  426.527
corr_permitted_lateness_seconds   30.000
```

## 2. `window_s = 900` — removed

Not redefined, not deprecated: **deleted from `EngineConfig`**. It was never an
engine parameter (the core never read it), had no env override, no doc, no test
asserting it, and keeping a second temporal constant beside `tau_s` is what let
the two drift apart. Retention is the caller's concern and now derives from the
scoring rule, so they cannot disagree.

**Migration:** removing the field changes `config_hash()` and therefore
`engine_version` (`3.1.0+cfg.d92aacb66561`). That is intended and visible —
objects scored under the old retention semantics genuinely are not equivalent —
and `replay.py` *reports* the pin mismatch (`engine_pin_match`) rather than
failing, so historical replay still runs and says what changed. The
`corr_window_horizon_seconds` metric keeps its name so dashboards resolve, but
now carries the derived requirement (426.5) instead of the retired constant.

## 3. Event time vs wall clock — fixed

Retention expires against each tenant's **stream clock** (newest event timestamp
seen for that tenant), never the wall clock. The old formula
`retained_span = window_s − processing_lag` has no lag term any more.

| Processing delay | Signals surviving | RCA edge | Before this wave |
|---|---:|---|---|
| 10 s | 2 | forms | forms |
| 15 min | 2 | **forms** | cause evicted, edge gone |
| 30 min | 2 | **forms** | gone |
| 2 h | 2 | **forms** | gone |
| 24 h | 2 | **forms** | gone |

### Watermark scope, and why a global one would be wrong

Per **tenant**. The co-partitioning contract (`test_scale_copartition.py`) is the
argument: every producer keys by tenant with Java-compatible murmur2, so a tenant
hashes to the same partition **number** on all 12 topics, and the RANGE assignor
keeps partition *k* of every topic on one member. A tenant therefore lives
entirely on one instance across every lane; the engine partitions by tenant and
`run_window` refuses a mixed-tenant window, so **no edge can span tenants**.

Consequences, all now tested:
* a fast tenant must never expire a slow tenant's evidence — a global watermark
  would do exactly that, silently;
* a slow partition can never hold evidence a fast partition needs, because they
  carry different tenants and cross-tenant edges do not exist;
* per-tenant is both the safe scope and the tightest one.

Compatible with tracker 155: watermarks are per-process state with no rehydration
path, exactly like `OPEN_OBJECTS` and the window, so a partition acquired at a
rebalance starts cold and refills.

**Backstop.** A silent tenant freezes its watermark and would retain forever, so
a wall-clock idle backstop (`CORR_TENANT_IDLE_EVICT_S`, 3600 s) bounds it. It is
a **resource** control, counted separately (`corr_idle_tenant_evictions_total`)
so it can never be mistaken for semantic expiry. Live: **0**.

**Watermarks are monotonic** — an out-of-order arrival is counted
(`corr_watermark_regressions_total`), never obeyed. Live: 154,540 / 153,086 out
of ~600k, i.e. ~25% of arrivals land behind the tenant's high-water mark. That is
expected with 1000 devices interleaved round-robin, and it is exactly why the
watermark must take the max rather than the last value.

## 4. Compact representation — measured, then NOT adopted

The prompt asked for a `RetainedSignal` projection. The field trace says the win
is not there, so it was not built:

| Component | B/signal | Droppable? |
|---|---:|---|
| irreducible `Signal` shape | 408 | no |
| `entity_id` + `entity_tokens` uninterned | 184 | **shareable, no field loss** |
| `attrs` dict | 168 | **shareable, no field loss** |
| dedup set + id deque | 145 | structural |
| `native_id` | 107 | **no** — feeds `signal_id = uuid5(source\|native_id\|ts)` |
| **total** | **1,012** | |

Two findings killed the projection idea:

1. **`native_id` is load-bearing.** `signal_id` derives from it and is
   deliberately not memoised (tracker 156), so dedup, the archive-slice hash and
   the replay contract all depend on it.
2. **`_archive_row` calls `sig.to_ch_row()`** — the archive slice is built from
   the live window and must be byte-identical to its twin. A projection that
   dropped fields would break replay exactness.

What *is* free is **sharing, not dropping**: interning `entity_id` /
`entity_tokens` and sharing identical `attrs` dicts gives **1,012 → 549 B/signal
(46%)** with identical `to_ch_row()` output. That is the same technique already
proven here for `Observer` / `Relation` / `Grounding`. It is measured and
documented but **not implemented in this wave** — it is a pure memory
optimisation with no semantic content, and it belongs in the sizing work, not in
a correctness change.

**Model A vs Model B (one-tier vs two-tier) is therefore moot** and was not
built: there is no compact tier to promote into.

## 5. Live 1K qualification — run `08202225178u`

600,001 events, 1000 devices, ~1651/s injected, 2 correlation replicas, mTLS.

| Phase | Verdict | Detail |
|---|---|---|
| preflight | **PASS** | 29 services, consumers live |
| onboard | **PASS** | 1000/1000, 45.2/s → 38.7/s (ratio 0.86) |
| burst | **PASS** | 600,001 injected in 363 s |
| drain | **FAIL** | lag never returned to baseline in 1090 s (final 286,439) |
| **accounting** | **PASS** | **600,001 injected == 600,001 persisted + 0 DLQ + 0 rejections; 1000/1000 devices covered** |
| memflat | **FAIL** | correlation-1 at 725 MiB = 91.9% of its 789 MiB cap |
| stability | **PASS** | full 2,414 s lifecycle: 0 CommitFailed, 0 UnknownMember, 0 restarts; worst loop stall **9,316 ms** |
| cleanup | **FAIL** | `TimeoutError` while deleting devices (harness robustness; same failure as the 2026-08-18 cron run). 703/1000 removed before it gave up; the remaining 297 were cleared by hand and the registry drained to 0. |

### Retention behaviour under load

| Metric | replica 1 | replica 2 |
|---|---:|---:|
| `corr_window_signals` peak | 50,000 | 50,000 |
| `corr_window_span_seconds` peak | 75.2 | 75.2 |
| `corr_oldest_retained_stream_age_seconds` | 75.2 | 75.2 |
| **`corr_stream_time_evictions_total`** | **0** | **0** |
| `corr_idle_tenant_evictions_total` | 0 | 0 |
| `corr_window_overflow_dropped_total` | 106,032 | 104,577 |
| `corr_window_overflow_in_horizon_total` | 106,032 | 104,577 |
| `corr_rca_evidence_degraded` | 1 | 1 |
| `corr_event_time_lag_seconds` peak | 1,259.6 | 1,251.8 |

**Read that carefully — it is the whole result.** Stream-time expiry evicted
**nothing**. Every signal lost was lost to the **record cap**, and every one of
them was still inside the engine's reach, and the system **said so** — degraded
= 1, reason `resource_capacity`.

That is the designed outcome: the resource ceiling still protects the process,
but it no longer silently redefines the RCA horizon.

### Phase 12 — the recalculated overflow split, and a correction

| | old measure | new measure |
|---|---:|---:|
| yardstick | wall-clock age vs `window_s` (900 s) | event-time distance vs `ENGINE_REACH_S` (396.5 s) |
| still useful | 41.4% | **100.0%** (210,609 / 210,609) |
| already stale | 58.6% | **0.0%** |

**I predicted this number would go down. It went to 100%, and the earlier 41.4%
understated the damage.** The old measure compared a victim's *wall-clock* age
against 900 s, so under 12–21 minutes of processing lag most victims looked
"already stale" — but that staleness was an artefact of the backlog, not of the
evidence being obsolete. Measured the way the engine actually reasons (event-time
distance to the newest evidence, span 75.2 s ≪ reach 396.5 s), **every** shed
signal could still have formed an edge.

## 6. Tracker 164 — answered live, and it is NOT the bottleneck

| Metric | replica 1 | replica 2 |
|---|---:|---:|
| `corr_offload_queue_depth` peak | **0** | **0** |
| `corr_offload_queue_depth_peak` | **1** | **1** |
| `corr_offload_oldest_queued_age_seconds` | 0.000 | 0.000 |
| `corr_offload_wait_max_seconds` | **0.021** | **0.020** |
| wait p50 / p95 / p99 | 0.26 ms / 8.1 ms / 13.4 ms | — |
| `corr_offload_exec_max_seconds` | 8.29 | 4.87 |
| exec p50 / p95 / p99 | 0.50 s / 3.19 s / 4.73 s | — |
| submitted / completed / failed | 466 / 466 / 0 | 568 / 568 / 0 |

**Queue depth never exceeded 1. Worst wait was 21 milliseconds — while
event-time lag reached 21 minutes.** Submissions equal completions exactly.

The static argument held: all 12 call sites are on the object-persistence path
(`_snap_call`, gated at 2,000 elements, once per snapshot per 30 s cycle) or the
ClickHouse batch path — none per-event. Execution is genuinely expensive
(p95 3.2 s), which is precisely why it is offloaded; the queue behind it is
empty.

**Verdict: Tracker 164 is not the current drain bottleneck.** It remains open as
pre-GA saturation hardening — an unbounded queue is still a §9 defect — but it
must not be prioritised as a throughput fix.

## 7. Where the drain time actually goes

Measured drain rate ~236–425 events/s against ~1651/s injected.

Excluded by measurement:
* **offload queueing** — depth ≤ 1, wait ≤ 21 ms (§6)
* **pruning** — `corr_prune_seconds_max` **0.070 s / 0.016 s**, down from
  1,618 ms in run WA. The chunked stream-time prune did not regress cost; it
  improved it ~23×.
* **open objects** — `corr_open_objects` = **8**, so 162's O(N) scan and 163's
  unbounded dict are both operating on a trivial N.

Remaining candidates, in order of evidence:
* **event-loop stalls** — 41 / 39 stalls. My external sampler saw a worst of
  2,692 ms / 2,535 ms, but the harness, which watches the whole lifecycle,
  recorded **9,316 ms** — the worst stall happened during the post-burst drain,
  after I had stopped sampling. Take 9,316 ms as the figure. Still below the
  30 s session timeout (membership stayed clean), but 9.3 s of frozen loop is
  substantial throughput loss and is now the leading drain suspect.
* **per-event handling and the engine cycle over a 50,000-signal window.**

Pinpointing needs the opt-in profiler, and profiling contaminated a previous run,
so this is stated as narrowed, not solved.

## 8. Memory

| | replica 1 | replica 2 |
|---|---:|---:|
| peak cgroup memory | **774.5 MiB** | 776.5 MiB |
| settled | 680.1 MiB | 614.6 MiB |
| cap | 789 MiB | 789 MiB |
| peak / cap | **98.2%** | 98.4% |

The window at its 50,000 cap is what fits in 789 MiB, and 50,000 signals is
**75.2 s** of span at burst rate — far short of the 426.5 s requirement.

Sizing arithmetic, at the two rates that matter:

| Regime | rate | signals for 426.5 s | window @1,012 B | @549 B (interned) |
|---|---:|---:|---:|---:|
| burst (this run) | 1,651/s | 704,000 | 712 MB | 387 MB |
| p90 active (measured, 4-day) | 182/s | 77,600 | 79 MB | 43 MB |
| median (4-day) | 2.2/s | 938 | 1 MB | 0.5 MB |

**The requirement is satisfiable at steady state and not at 10× burst.** No
production memory limit is proposed here — the prompt forbids picking one before
the implementation is stable, and the interning work above should land first
because it changes the answer by 46%.

## 9. Negative controls

| Mutant | Killed |
|---|---|
| wall-clock pruning restored (the original defect) | ✅ 9 tests |
| one global watermark instead of per-tenant | ✅ 13 tests |
| watermark moves backwards on out-of-order arrival | ✅ |
| retention horizon halved | ✅ 3 tests |
| lateness floor removed | ✅ |
| idle backstop counted as stream-time expiry | ✅ |
| idle backstop fires when not idle | ✅ 10 tests |
| H14 future clamp removed (watermark poisoning) | ✅ |
| engine reach clamped before `w_t` (the 361 s error) | ✅ 6 tests |
| degradation suppressed / reported against the wrong yardstick | ✅ |
| retention block removed from `/healthz` | ✅ |
| effective-horizon metric sample deleted | ✅ |

### Two bugs the tests did not catch — the container did

1. **uvloop.** `_offload_max_workers()` read `loop._default_executor` guarded
   only for `RuntimeError`. uvloop's `Loop` has no such attribute, so `/metrics`
   and `/healthz` raised `AttributeError` and the container never went healthy.
   pytest drives the stdlib loop, which *does* have it. Fixed, and pinned by a
   test that removes the attribute the way uvloop does.
2. **Wrong health surface.** The retention block went into the diagnostic
   snapshot, not the public `/healthz`. Only querying the running stack revealed
   it. Fixed and pinned against the public endpoint.

Both are the same lesson: an instrumentation change is not verified until it has
run in the real container.

### One documented equivalent mutant

`_OFFLOAD_LOCK` removal still passes all tests. No probe produced a lost update
or torn dict snapshot on CPython at any switch interval, thread count or dict
size — `+=` on a module int and `list(dict.values())` both complete inside one
GIL slice. The lock stands on language-guarantee grounds (and free-threaded
builds), **not** claimed as test-covered.

## 10. Status

| Item | Status |
|---|---|
| **165** | 🟡 **PARTIAL** — semantics, clock, contract, degradation and A/B all done and live-verified. Held open by **acceptance criterion 6**: retained state does not cover the engine's reach under burst (75.2 s vs 426.5 s), because 50,000 signals is what 789 MiB holds. Not a semantic defect any more — a sizing one, and it is now *declared* rather than silent. |
| **164** | ⏳ open, **de-prioritised on live evidence** — queue depth ≤ 1, wait ≤ 21 ms. Pre-GA saturation hardening, not a throughput fix. |
| **163** | ⏳ deferred — `OPEN_OBJECTS` = 8 live. |
| **162** | 🟡 PARTIAL — unchanged; N is 8, so worst-case scan is trivial today. |

**1K qualification: does not pass yet** — accounting, onboarding and stability
pass; drain and memflat fail, both pre-existing and both now explained.
**Capacity calibration: not yet.** **72 h soak: still blocked.**
