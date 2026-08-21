# Tracker 165 — watermark safety, sharing, and the full-horizon 1K run

**Date:** 2026-08-21 · **Base:** `89666600` · **Bus:** Apache Kafka 4.1.1 KRaft, mTLS
**Runs:** `082023500q77` (before sharing, 5-min burst) · `08210038lvor` (after sharing, 10-min burst)

---

## 1. The required horizon changed: 426.527 s → **516.527 s**

Not a moved target — an incomplete analysis, corrected in phase 5.

```
required_retention = engine_reach + permitted_lateness
                   = 396.527 + max(CORR_ENGINE_INTERVAL_S, METRIC_FUTURE_SKEW_S)
                   = 396.527 + 120.0
                   = 516.527 s
```

The lateness floor had one term. It needed two. H14 accepts a device timestamp up
to `METRIC_FUTURE_SKEW_S` (120 s) ahead of arrival **without clamping**, and that
timestamp advances the tenant watermark — so a device running two minutes fast
drags the whole tenant's expiry cutoff 120 s into the future. Evidence then
expires at `(true_stream_time + skew) − retention`, i.e. the effective horizon is
`retention − skew`. At a 30 s lateness the margin was **90 s short of the skew the
intake layer already permits**, so a legitimately fast device could silently
expire still-attachable evidence.

Pinned by `test_the_lateness_allowance_covers_the_permitted_skew`, and by the
+30 s / +5 min / +1 h / +1 day skew battery.

---

## 2. Co-partitioning (phases 1–2)

### Topic table — every correlation lane

| Topic | Key | Partitions | Partitioner | Consumer ownership | Co-location guaranteed? |
|---|---|---:|---|---|---|
| netops.syslog | tenant_id → `__key` | 4 | murmur2_random (Java-compatible) | range assignor, group `netops-correlation` | ✅ |
| netops.flows | tenant_id → `__key` | 4 | murmur2_random | same | ✅ |
| netops.metrics | tenant_id → `__key` | 4 | murmur2_random | same | ✅ |
| netops.probes | tenant_id → `__key` | 4 | murmur2_random | same | ✅ |
| netops.snmptrap | tenant_id → `__key` | 4 | murmur2_random | same | ✅ |
| netops.cloud | tenant_id → `__key` | 4 | murmur2_random | same | ✅ |
| netops.app.identities.v1 | bus-bridge `tenant_id`, else envelope key (Go sets `Key: TenantID`) | 4 | murmur2_random | same | ✅ |
| netops.controller_events | as above | 4 | murmur2_random | same | ✅ |
| netops.app.edge | as above | 4 | murmur2_random | same | ✅ |
| netops.verification | as above (`verify_service.go` sets `Key: rec.TenantID`) | 4 | murmur2_random | same | ✅ |
| netops.wireless_sessions | as above | 4 | murmur2_random | same | ✅ |
| netops.wireless_events | as above | 4 | murmur2_random | same | ✅ |

Every lane folds an empty tenant to `"global"` before keying — never an absent
key, which would land on a random partition. `main.tenant_partition()` is the
in-process mirror, pinned against an independent murmur2 reimplementation.
**All 12 topics measured live at 4 partitions**, uniform.

### It is now enforced, not documented

The invariant was already checked at rebalance — and did nothing but log an
ERROR. Under stream-time retention that is no longer adequate, because the
failure got *worse*:

* **before 165:** a split tenant meant each member correlated over its own half.
  Degraded RCA, nothing destroyed.
* **after 165:** each member also runs a watermark over its own half and
  **expires evidence on a clock it cannot fully see**. Silent destruction.

So on violation, stream-time expiry is **suspended** — evidence is retained
instead, bounded by the record cap and the idle backstop — and the condition is
reported as `partition_topology`, ranked *above* `resource_capacity` because a
wrong clock is worse than a full buffer. Retaining too much is recoverable;
deleting on a wrong clock is not.

Negative controls: divergent partition sets are detected via the real rebalance
callback; topics the member does not hold are correctly ignored; the flag
recovers when topology is repaired.

---

## 3. The idle backstop was recreating the original defect (phase 3)

**This was a live bug in what shipped last wave.**

The backstop reclaimed a tenant whose watermark had not advanced for an hour of
wall time. During a backlog, "the watermark has not advanced" does **not** mean
"no more events are coming" — it means "we have not reached them yet". Evidence
A at T was shed while B at T+300 sat unprocessed in the log; B then arrived with
nothing to correlate against. That is wall-clock delay destroying
event-time-valid evidence — the exact defect tracker 165 exists to remove.

**Fix: idleness must be proven, not assumed.** A tenant is idle only when its
watermark has stalled **and this process is demonstrably level with the broker**,
measured by an in-process backlog probe (`highwater()` against consumed offsets,
rate-limited, never on the wire).

| Scenario | Result |
|---|---|
| A — genuinely idle, no backlog | reclaimed ✅ (the backstop still works) |
| B — backlog present, 6 h of wall clock | **evidence retained** ✅, and the delayed partner still forms its edge |
| C — backlog on a *different* topic | retained ✅ (the probe is deliberately global) |
| D — lag unknown / stale reading | retained ✅ (fail-safe: unknown ≠ caught up) |
| E — tenant resumes after inactivity | clock advances cleanly, no stale-state corruption ✅ |

**Exact criterion for "truly idle":** watermark stalled ≥ `CORR_TENANT_IDLE_EVICT_S`
**AND** `CONSUMER_LAG_TOTAL == 0` **AND** that reading is fresher than
`CORR_LAG_FRESH_S`. Kafka offset state *is* consulted. Unknown or stale reads as
backlog. Global rather than per-partition on purpose: strictly more conservative,
provable from one number, and being slow to reclaim is the safe direction for a
last-resort memory control.

---

## 4. Watermark invariants (phase 4)

| # | Invariant | Status |
|---|---|---|
| 1 | never moves backward | ✅ regressions counted, not obeyed |
| 2 | advances only from processed event-time progress | ✅ advanced at the single window-entry chokepoint |
| 3 | one tenant cannot advance another's retention | ✅ |
| 4 | future-skew cannot prematurely expire evidence | ✅ (§1 floor + H14 clamp) |
| 5 | one pathological event cannot jump the watermark | ✅ clamped beyond skew |
| 6 | replay is deterministic | ✅ identical survivors at wall clocks 100,000 s apart |
| 7 | restart safely reconstructs | ✅ cold watermark expires **nothing** |
| 8 | safe across assignment movement | ✅ "no clock" means "expire nothing", never "expire everything" |

---

## 5. Sharing: measured, partially adopted (phases 6–8)

| Field | Type | Shared? | Why |
|---|---|---|---|
| `entity_id` | `str` | ✅ | immutable — a shared reference cannot be written through |
| `entity_tokens` | `tuple[str]` | ✅ | immutable, members shared too |
| `attrs` | **`dict`** | ❌ **rejected** | **mutated after construction** — `main.py` stamps `probe_intent` / `vantage_type` / `probe_authority` / `probe_scope` / `execution_id` / `seam_id` on the probe path. Sharing would let one signal's enrichment rewrite another's evidence. |

**Measured: 1,011 → 832 B/signal, 17.7 % heap.** The earlier 46 % figure assumed
`attrs` sharing and is not available without first making `attrs` immutable — a
separate change with its own risk. The honest number is 17.7 %.

**Cache bound (phase 7):** keyed by the string itself, LRU-capped at
`CORR_ENTITY_CACHE_MAX` (50,000), counted evictions, exposed on `/healthz` and
`/metrics`. Eviction is value-safe by construction — a miss yields an *equal*
string, never a different one. Live population settled at **7,049 entity_ids /
6,001 token tuples with 0 evictions**: bounded by the estate (devices × ports),
not by "every unique value forever", exactly as predicted.

**Equivalence (phase 8):** proven against an unshared control — `signal_id`,
`native_id`, `to_ch_row()`, `_archive_row()`, nodes, edges, grounding, gap hints,
verdict, evidence, and the replay **`content_hash`**.

---

## 6. Full-horizon 1K run — the acceptance evidence (phases 9–13)

Diagnostic configuration (**not a recommendation**): `CORR_WINDOW_BUFFER=900000`,
`mem_limit=3g`. Burst lengthened to 10 minutes at ~979/s so the stream's own
event-time extent (**613 s**) exceeds the 516.527 s horizon — the previous 5-minute
burst spans only ~315 s and *structurally cannot* fill it.

### Retention

| Metric (peak) | replica 1 | replica 2 |
|---|---:|---:|
| retained signals | 263,013 | 270,052 |
| **effective horizon** | **544.4 s** | **544.3 s** |
| required horizon | 516.527 s | 516.527 s |
| oldest retained age vs stream | 544.4 s | 544.4 s |
| **capacity drops** | **0** | **0** |
| stream-time evictions | 15,099 | 1 |
| idle-tenant evictions | 0 | 0 |
| **`rca_evidence_degraded`** | **0** | **0** |
| `copartition_ok` | true | true |
| entity cache (ids / tuples / evicted) | 7,049 / 6,001 / **0** | — |

**`effective_horizon_s = 523.6 → 544.4` against `required_horizon_s = 516.527`,
with `horizon_satisfied: true` and `capacity_dropped_total: 0`.** Evidence leaves
the window only by *semantic* expiry at the horizon — `stream_time_evictions`
began incrementing exactly when the span crossed 516.5 s — and never by capacity.
Degradation never fired, because nothing usable was ever discarded.

### Phase 13 — capacity-dropped evidence, recalculated

| | previous run (50k cap) | this run (full horizon) |
|---|---:|---:|
| total capacity drops | 210,609 | **0** |
| still within max attachable gap (396.5 s) | 210,609 (100 %) | **0** |
| still within required retention (516.5 s) | 210,609 (100 %) | **0** |
| already semantically expired | 0 (0 %) | n/a |

The stale 41.4 % is retired twice over: it was measured against a wall-clock
yardstick, and the condition it measured no longer occurs when retention is
sized to the horizon.

### Harness verdicts

| Phase | Verdict |
|---|---|
| preflight | PASS |
| onboard | PASS — 1000/1000, ratio 0.86 |
| burst | PASS — 600,001 in 613 s |
| drain | **FAIL** — lag never returned to baseline (pre-existing class) |
| **accounting** | **PASS — 600,001 == 600,001 + 0 DLQ + 0 rejections; 1000/1000 devices covered** |
| memflat | **FAIL** — see below |
| stability (before-sharing run) | PASS — 2,185 s lifecycle, 0 CommitFailed/UnknownMember/restarts |

**The memflat failure is the gate's assumption, not a leak.** It reads
`484 → 711 MiB after input stopped` as a leak slope, but with stream-time
retention the window keeps *filling* after ingress stops, because the backlog is
still being consumed. Memory rising post-ingress is retention working. The gate
needs to account for that; filed as a harness item, not a product defect.

---

## 7. Memory (phases 10–11)

| | before sharing | after sharing |
|---|---:|---:|
| retained signals | 161,891 | 270,052 |
| bytes/signal (heap, tracemalloc) | 1,011 | **832** |
| peak cgroup memory | 749.0 MiB | **1,042.5 MiB** |
| settled | 719.7 MiB | 800.3 / 848.2 MiB |

**Heap savings ≠ RSS savings.** Measured marginal cost between the two runs:
**2,845 B/signal of RSS against 832 B of heap — an allocator/native residency gap
of 3.42×.** Any sizing done from the heap figure alone would under-provision by
more than 3×.

Host swap: 390 MiB in use of 4,095 (host-wide, unchanged across the run); no
cgroup `memory.max` hits; no PSI stall pathology observed.

### Is 789 MiB viable? **No — and not by a small margin.**

| Regime | rate | signals @516.5 s | window RSS @2,845 B |
|---|---:|---:|---:|
| p90 active (4-day measured) | 182/s | 94,008 | **0.25 GiB** |
| this run's burst | 979/s | 505,680 | **1.34 GiB** |
| prior run's burst | 1,651/s | 852,786 | **2.26 GiB** |

Base process (excluding window) measures ~550–600 MiB. So:

* **p90 workload:** ~0.85 GiB — 789 MiB is *marginal*, with no burst headroom.
* **burst workload:** ~1.9–2.9 GiB.

**Recommendation, from measurement rather than preference: 1.25 GiB for a p90
workload with real headroom.** Sizing for the 10× synthetic burst would mean
~3 GiB, and I do not recommend it — that burst is deliberately set above the
drain ceiling to make the drain proof non-vacuous, and it is not a GA workload.
Under a genuine storm the correct behaviour is the declared degradation that now
exists.

---

## 8. Tracker 164 — live, again, and again not the bottleneck (phase 14)

| Metric (peak) | replica 1 | replica 2 |
|---|---:|---:|
| queue depth | 0 | 0 |
| all-time queue depth peak | **1** | **1** |
| oldest queued age | 0.000 s | 0.000 s |
| wait max | **~0.00 s** | **~0.00 s** |
| exec max | 4.5 s | 6.6 s |

Queue depth peaked at **1** while event-time lag reached **34 minutes**. Execution
is expensive (max 6.6 s), which is exactly why it is offloaded; the queue behind
it is empty.

**`Tracker 164 = NOT CURRENT DRAIN BOTTLENECK`** — measured twice, at two window
sizes. This does **not** close its resilience concern: an unbounded executor
queue is still a §9 defect, and "not today's bottleneck" is not "safe under
arbitrary downstream slowdown". It stays open as pre-GA saturation hardening.

**Coverage caveat:** `run_window` at `main.py:2580` uses `run_in_executor(None, …)`
**directly**, not via `_offload`, so it is not counted in these figures — and it
is the largest CPU consumer. Three `asyncio.to_thread` sites are likewise
uncovered. All share the same 8-thread pool. The conclusion still holds
empirically (had the pool been saturated, `_offload` submissions would have
queued behind it, and their wait was ~0), but the instrumentation does not cover
every caller and should.

---

## 9. Where the drain time actually goes (phase 15)

Excluded by measurement:

* **offload queueing** — depth ≤ 1, wait ~0 (§8)
* **pruning** — `corr_prune_seconds_max` ≈ **0.00 s** even at 270k signals
* **open objects** — `corr_open_objects` = 7–8, so 162's scan and 163's dict are
  operating on a trivial N

**A prediction of mine that was wrong, stated plainly:** I expected a larger
window to make event-loop stalls *worse*, because the engine cycle has a
synchronous O(N) pass over the whole buffer. Measured the opposite —

| window cap | worst loop stall |
|---:|---:|
| 50,000 | **9,316 ms** |
| 900,000 (162k held) | **3,504 ms** |
| 900,000 (270k held) | 3,414 / 4,144 ms |

The 50k configuration was *worse* despite holding 5× less. The likely reason is
constant capacity-eviction churn at a full deque; that is a hypothesis, not a
measurement, and I have not isolated it.

Remaining candidate: per-event handling plus the engine cycle. Isolating it needs
the opt-in profiler run off-loop, which contaminated an earlier run — so this
phase remains diagnosis, not conclusion.

---

## 10. Mutation summary

| Target | Mutants | Killed |
|---|---:|---:|
| watermark safety / idle backstop / co-partitioning | 14 | **14** |
| entity sharing + cache | 6 | **6** |

Three of my own tests survived their first pass and were strengthened:

* **co-partitioning detection** — every test set the flag directly, proving only
  the *response*. It has its own tests now driving the real rebalance callback.
* **"once broken, broken until restart"** — survived because my helper reset the
  flag between assignments, masking the recovery test.
* **"sharing silently disabled"** — survived because the fixture passed the same
  string *literal* to every signal, so they shared identity through CPython's
  constant pool whether or not the cache ran. ruff's FLY002 wants those joins
  turned back into literals; the advice is suppressed with the reason.

One bug this work introduced, caught by an existing test: the backlog probe ran
**inside** the per-event try-block, so when it raised on a consumer without
`assignment()`, the **event was quarantined as if its payload were poison**.
Instrumentation must never be able to blame the data. It now runs outside the
payload path and never raises.

---

## 11. Tracker 165 decision

**PARTIAL — one criterion short, and it is a deployment decision, not a defect.**

| Criterion | Status |
|---|---|
| reach derived from engine config | ✅ |
| lateness justified (now incl. skew) | ✅ |
| retention single-sourced | ✅ |
| event-time watermark safe | ✅ |
| co-partitioning proven **and enforced** | ✅ |
| no fast tenant expires a slow one | ✅ |
| future skew cannot jump state | ✅ |
| idle backstop cannot remove needed state | ✅ |
| full semantic horizon retained | ✅ **544.4 s ≥ 516.527 s, 0 capacity drops** |
| sharing semantically exact | ✅ (content_hash) |
| intern structures bounded | ✅ (7,049 / 0 evicted) |
| RCA reference equivalence | ✅ |
| degradation correctly signalled | ✅ |
| accounting / durability / isolation | ✅ |
| **stable memory plateau at a supportable limit** | ❌ **the qualifying run used 3 GiB; 789 MiB is not viable and the production limit is not yet set** |
| **clean 1K qualification** | ❌ drain FAIL (pre-existing), memflat gate needs rebasing |

**165 cannot close until a production memory limit is chosen and qualified at
it.** Everything semantic is done and proven; what remains is sizing plus the
drain deficit, which is a different problem.

| Tracker | Status |
|---|---|
| 162 | PARTIAL — N measured at 7–8; worst-case scan is trivial today |
| 163 | deferred — `OPEN_OBJECTS` 7–8 |
| 164 | open, **not the bottleneck**; pre-GA saturation hardening |
| 165 | **PARTIAL** |

**Capacity calibration: not yet.** **72 h soak: still blocked.**
