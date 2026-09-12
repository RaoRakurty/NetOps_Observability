# CORRELIX PRE-GA ARCHITECTURE REVIEW

**Date:** 2026-08-22 · **Charter:** `/var/tmp/Re-architect.md` · **Reviewer:** independent, source-derived
**Tree:** `feat/observability-platform` @ `f74a0e0c` + uncommitted 2026-08-22 session work
**Standing:** review only — no code was modified by this review.

> The charter's §9 "most important unknown" — *can the post-168/post-167
> architecture complete the truthful 1K qualification?* — was answered after the
> charter was written. Run `082201589waa` (2026-08-22) answered **NO**, with a
> measured cause. This review therefore runs with strictly more evidence than
> the charter anticipated, and that answer is incorporated throughout.

---

## 1. Executive Decision

### KEEP CURRENT ARCHITECTURE WITH ONE TARGETED STRUCTURAL CHANGE

**The one change: the object-persistence model — specifically the archive
slice — must be re-shaped for the many-small-objects regime that tracker 168
made the permanent reality.** Everything else in the correlation architecture
survives falsification on current evidence.

**Confidence: HIGH** for the 1K GA path. **MEDIUM** beyond 2.5K, dropping to
LOW only for the single-tenant-10K scenario, which is a real structural ceiling
but a category-D/E concern (§8, §19), not a GA blocker.

Two subordinate rulings that are part of the decision, not separate ones:

1. **No qualification result can be graded until the GA workload contract is
   ratified.** Every remaining 166 criterion is a throughput criterion against
   an unratified target that spans a 27× range (182 vs 5,000 EPS) and an
   unmeasured promotion ratio (§6, §23 of `GA_WORKLOAD_CONTRACT_1K.md`). The
   architecture cannot be falsified by failing a workload nobody has committed
   to supporting.
2. **A qualification-validity defect was found by this review** (§below, and
   §5): the harness injects null-keyed events, splitting one tenant 50/50
   across both replicas — a topology production's tenant-keyed pipeline cannot
   produce. Measured per-replica figures describe *half* a tenant. This
   overstates production single-tenant capacity by ~2× and must be fixed in the
   harness before the next qualification is graded.

## 2. One-paragraph rationale

Four successive bottlenecks (candidate explosion, template scoring, catalog
hashing, archive persistence) share one generator — per-object work sized by a
global (catalog or window) — and three of the four have been removed with
measured, order-of-magnitude results and zero semantic change, while every
*architectural* property the engine claims (determinism, replay exactness,
retention semantics, identity scoping, durability boundaries, bounded memory,
Kafka stability: 0 rebalances, 0 commit failures, RSS flat at 29–58 % of the
floor across all recent runs) has held under every test thrown at it. That is
the signature of a sound architecture with residual implementation defects, not
of a structural ceiling: the burden of proof for redesign — *name the invariant
that prevents the current system from meeting its supported workload* — cannot
currently be met, because the one measured blocker (archive writes at 98.6 % of
persistence time) is a stage-local design defect with a correctness-preserving
fix inside the existing architecture, and the "supported workload" itself is
not yet a ratified number.

## 3. Evidence table

| Observation | Status | Architectural significance |
|---|---|---|
| Engine core is pure/deterministic; replay-exact; `engine_version` pins semantics | Measured (source + replay tests) | Parallelization and sharding options stay open; nothing forces ordering beyond persist/continuation |
| 168 identity fix: candidates/signal 970.9 → 23.5; Σpairs 25.1 M → 1.128 M (−95.5 %); RCA objects 1 → 150 on ground truth | Measured | The original "scaling failure" was substantially a correctness defect; pre-168 capacity numbers are void |
| 167 + cache fixes: `run_window` 495.86 → 186.63 s offline (2.66×), 0 semantic mismatches; live epoch max 3,956 → 221/230 s | Measured | Per-object scoring cost ≈ **4.3 ms/object** (186.63 s / 43,065 objects); remaining cost is legitimate work (`verdicts.assess` 43.7 %) |
| Archive persistence: 1,130 inserts, p50 152 ms, **222.4 of 232.4 s (98.6 %)** of correlation insert time; 0.47 objects/s; pending flat at 129,220 for the full 2,160 s | Measured (`system.query_log`) | THE current blocker. ~4 chunk-inserts per object-version at chunk=10,000 with observed tail chunks of 8,461/8,904 rows ⇒ slice ≈ **30–40 k rows ≈ the whole retained tenant window per object version** |
| All other corr tables: p50 7–8 ms, ~2.5 s total each in the same window | Measured | Non-archive persistence is NOT a bottleneck; the defect is one table's write model |
| GIL: 0.66–0.69 cores used of 2, zero throttling; one `run_window` call = 196 s; offload queue depth 0, peak 1 | Measured | One replica ≈ one Python execution thread. `_offload` is a thread pool — it protects the event loop, it does not add CPU |
| Null-key harness injection: pending split 64,740 / 64,480; window_signals 65,719 / 65,322 (this review, from `082201589waa` final state + `Stack.produce` source + Vector `__key` config) | **Measured mechanism; consequence inferred** | Qualification ran "one tenant sharded 50/50 by round-robin" — a topology tenant-keyed production cannot produce. Per-replica loads are per-HALF-tenant |
| 165 retention: 516.527 s contract held; evictions 100 % stream-time semantic; 0 capacity drops; 0 evidence-degraded | Measured, frozen | Retention semantics are correct and must not be touched for performance |
| 35,422 signals expired before evaluation (`08212335gjeg`) | Measured | The de-facto overload behaviour: backlog is bounded by expiry, not catch-up. Honest, counted — but an implicit contract (§32 finding) |
| 3 ClickHouse writes LOST to ReadTimeout under 17 s loop stalls; `ch_insert` had no retry; client timeout 10 s vs measured 14,395 ms commit | Measured; **fixed in tree 2026-08-22, NOT yet deployed** | P(cohort commits) = (1−p)^objects coupling of one slow insert to a whole cohort's frontier — closed by the bounded-retry fix (dedup-gated), pending deployment |
| `OPEN_OBJECTS`: 0–8 pre-168 → **1,626/1,509** post-168; unbounded by count; input to O(S×O) continuation | Measured | Tracker 163's deferral rationale ("0–8 observed") is **stale**; re-prioritized in §16/§22 |
| Memory: live Python heap ~170 MB at a full 50 k window; RSS plateaus (666 MB at a 1.5 GiB cap — does not chase the ceiling); Signal ≈ 832 B | Measured (A/B) | In-process state is nowhere near justifying an external store |
| Nightly `08220317gmp4`: correlation-1 RSS 474 → 639 MiB (×1.35) after input stopped; both replicas restarted mid-run | Measured but **confounded** | Unexplained; must be reproduced under the completion gate before soak (§20 test C) |
| Planner says 5,000 raw EPS @ 1K devices; harness's own help text implies ~200 nominal; measured qualification ran 182 | Documented conflict | The GA target is unratified across a 27× span; promotion ratio (raw→admitted) has never been measured (~100 % in every run to date) |

## 4. Root cause history

```
apparent scaling collapse (pre-168)
  ↓  was actually
device-local interface name acting as a GLOBAL identity (168)
  → 25.1M candidate pairs, one 1,800-node welded object, 144k carried edges
  ↓  fix multiplied objects 1 → ~1,500/replica, exposing every per-object cost in turn
objects × 100 templates scoring (167: kind index, −78% calls)
  ↓
catalog re-serialized per object (version_hash memoisation, 48.6% of a cycle → ~0)
  ↓
window-sized archive slice per object version (98.6% of persistence time — CURRENT)
```

**This history argues FOR the current architecture, not against it.** Each
bottleneck was found by measurement, removed with an order-of-magnitude result
and zero semantic drift, and the next one became visible — the healthy
performance-engineering loop the charter's FINAL STANDARD describes. What it
also shows is that the *cost model changed permanently* at 168: the engine now
lives in a many-small-objects regime, and exactly one subsystem — archive
persistence — was never redesigned for it. Tracker 156's own row predicted
this ("sized by the whole WINDOW rather than by the object"). That is a known,
named, bounded defect, not an unknown structural ceiling.

## 5. Current architecture map (source-derived)

```
Kafka (KRaft, 12 topics × 4 partitions, tenant-keyed by producers: Vector __key = tenant_id)
  │  RangePartitionAssignor, group netops-correlation, manual commit,
  │  no deserializer (poison-safe), F-38 handled-offsets ledger, revoke hook
  ▼
consume() [asyncio task]  ── per-event handlers (handle_syslog … 0.34 ms p50)
  │   producers.py classify → Signal;  CHBatcher → corr_signals (batched,
  │   retry w/ backoff+jitter, content-hash dedup token, DLQ on permanent)
  ▼
buffer_signal()  [single chokepoint]
  │   tenant canon → clock clamp → dedup → maxlen evict (counted) →
  │   WINDOW_BUFFER (deque, 150k cap lab) → per-tenant stream-time watermark
  ▼
engine_loop [asyncio task, 30 s interval]
  └─ EPOCH (_begin_epoch):  prune (stream-time, chunked, ≤0.02 s) →
     flow flush → FREEZE snapshot (immutable tuple) → partition by tenant →
     per tenant: seams/adjacency/oracle/path-index/discovery + prepare_run_window
     [_offload → default ThreadPoolExecutor, GIL-bound]           [ONCE, ~1.3 s/48k nodes]
       └─ up to 20 COHORTS (5,000 signals, tenant-fair round-robin):
            run_window(prep, cohort_keys, carried_edges)  [_offload, pure]
              build_edges (cohort pairs only) ∪ carried → components →
              fold → rank (22 candidate templates/object, 4.3 ms/object) →
              ObjectSnapshots
            continuation index → find_continuation → OPEN_OBJECTS (unbounded dict)
            _persist_snapshot per changed object version [ON EVENT LOOP, awaits serial]:
              corr_objects → corr_current → corr_edges → corr_evidence →
              ★ corr_signals_archive: _archive_slice = every node whose activity
                interval overlaps the object's span ⇒ under estate-wide activity
                ≈ THE WHOLE TENANT WINDOW (~30–40k rows), chunked ×10k   ★ 98.6 %
            merges → quiesce closes → _mark_processed(cohort)  [160 boundary]
     └─ epoch discarded (prepared state never outlives its snapshot)
```

Execution contexts: **one process, one event loop, one GIL** per replica.
`_offload` = default thread pool (8 workers, unbounded queue — tracker 164):
it protects loop latency (heartbeats survive), it adds **zero** CPU throughput.
Failure boundary: cohort (frontier advances only after all its persists — 160).
Retry boundary: per-insert in the batcher; per-insert in `ch_insert` as of the
2026-08-22 in-tree fix (dedup-gated; **not yet deployed**).

## 6. Complexity model (measured constants)

| Stage | Cost model | Measured constant | At 182 sig/s, post-168 |
|---|---|---|---:|
| per-event handle | O(1)/event | 0.34 ms p50 | 0.06 core |
| epoch preparation | O(nodes) | ~1.3 s / 48 k nodes, once/epoch | ~0.3 % of epoch |
| candidate emission | O(cohort × density) | 30 µs/candidate × 23.5 cand/signal | 0.13 core |
| object scoring | O(objects × relevant templates) | **4.3 ms/object** (22 of 100 templates; `verdicts.assess` 43.7 % of it) | dominant CPU |
| continuation | O(new × open) | constant improved 1.3–2×, class unchanged (162) | benign now; watch at O≈10⁴ |
| persistence (non-archive) | O(objects) × ~28 ms CH | 7–8 ms p50 × 4 tables | small |
| **archive** | **O(objects × window) rows** | 152 ms/10k-row chunk × ~4 chunks/version | **98.6 % — the blocker** |
| prune | O(retained), chunked | ≤ 0.02 s | negligible |

Extrapolation (stated assumptions: post-archive-fix; per-object costs as
measured; single owner per tenant as production keying enforces):

* **1K, realistic promotion (5–15 %)** — 250–750 admitted sig/s platform-wide,
  incident-bound O (10s–100s of objects): every stage ≪ budget. **Fits with
  headroom.**
* **1K, CORRELATION_STRESS (100 % promotion, estate-wide flap)** — O ≈ 10⁴
  objects/cycle: scoring alone ≈ 43,065 × 4.3 ms ≈ 185 s/epoch on one core.
  Marginal-to-failing on a single tenant owner regardless of the archive fix.
  This is the workload's pathology, not the product's — unratified.
* **2.5K–5K multi-tenant** — scales by partition spread (needs P ≥ W; see §9).
* **10K single-tenant** — exceeds one core at any plausible promotion ratio;
  needs intra-tenant parallelism (§8, §19). Category D/E.

## 7. Scaling wall

**The first unavoidable wall is not today's profiler leader.** In order of
arrival:

1. **Archive write amplification** (now) — implementation, removable.
2. **Single-owner CPU ceiling** (first *architectural* wall) — one tenant maps
   to one partition to one replica to ~0.7 usable cores of GIL-bound Python.
   Arrives when `ratified admitted EPS × per-object cost + per-signal cost`
   for the largest tenant exceeds one core sustained. At measured constants
   this is roughly **400–500 admitted sig/s or ~10⁴ simultaneously active
   objects for a single tenant** — whichever comes first.
3. **Continuation/merge O(S×O)** with unbounded `OPEN_OBJECTS` under a broad
   storm (162/163 compound) — arrives with O ≈ 10⁴, same regime as (2).

## 8. Single-tenant ceiling (mandatory)

**YES — a structural single-tenant ceiling exists.** The chain is exact:
`tenant_partition(tenant) = murmur2(tenant) mod 4` → all of a tenant's records
on ONE partition → one consumer → one replica → one GIL-bound execution path
(`_offload` is threads, not processes). A 10,000-device enterprise tenant
cannot use a second core for correlation, no matter how many replicas or
partitions exist. Replicas add capacity **only across tenants**.

Compounding finding (this review): the qualification never measured this
ceiling, because null-keyed injection split the single lab tenant 50/50 across
both replicas (final state: 64,740 / 64,480 pending; 65,719 / 65,322 window
signals). Production keying cannot produce that split. **Every per-replica
capacity figure in the record is a per-half-tenant figure**, and the correct
production single-tenant reading is ~half of what the runs imply per replica
count. Additionally, since each replica correlated an interleaved half of every
device's stream, the two replicas necessarily formed independent (differing
`correlation_id`) objects for the same underlying flaps — the 2,586-object live
audit therefore counts cross-replica duplicates (mechanism certain from
keying; magnitude unverifiable post-cleanup). None of this invalidates 168's
0-welds result, which is about multi-device fusion, not duplication.

When the ceiling matters: not at 1K under any realistic promotion ratio; it is
the gating constraint for large-single-tenant 5K/10K (§19). What it needs is
already architecturally available: the dominant per-object scoring is a pure
function over independent components — process-pool parallelism over objects
(charter Option B) preserves determinism by construction (sort results by
`correlation_id` before the sequential persist/continuation phase). That is an
evolution, to be built when a ratified workload demands it — not now.

## 9. Horizontal scaling verdict

**PARTITION-LIMITED and HOT-TENANT-LIMITED — and unqualified for elastic
change.** 2→4 replicas: helps only if ≥4 active tenants hash onto distinct
partitions; P=4 caps useful replicas at 4; a hot tenant saturates its one owner
regardless. Worse, tracker 155 is unresolved: `OPEN_OBJECTS`/`WINDOW_BUFFER`
are process-global with no rehydration, so ANY rebalance (deploy, crash, scale
event) silently cold-starts the new owner's window and orphans the old one's.
**Horizontal scale may be claimed only for static membership until 155 lands.**
Do not raise BUS_PARTITIONS before 155 (existing freeze is correct).

## 10. Python execution verdict

**ADEQUATE WITH KNOWN CEILING.** Adequate: for ratified-workload 1K (and
plausibly 2.5K multi-tenant) after the archive fix — per-event path is 0.34 ms,
scoring 4.3 ms/object, memory flat, loop protected by offload. The ceiling:
one core per tenant (§8), reached under storm-shaped O ≈ 10⁴ or single-tenant
admitted EPS ≈ 400–500. Escape is Option-B worker processes for the pure
scoring stage — deterministic, state stays put — held until Falsification
Test B (§20) demands it. **Native code / Rust / more asyncio: rejected — the
measured hotspots were cache defects and one write-amplification defect, not
interpreter-bound inner loops; and asyncio concurrency cannot add CPU.**

## 11. Epoch architecture verdict

**KEEP — SOUND WITH ONE TARGETED DECOUPLING** (which is the same change as the
archive fix, viewed from the other side). The epoch answers are all semantic,
not accidental: the frozen snapshot gives cohort-invariant preparation
(object-identity guarded), determinism, and mid-drain expiry safety; cohorts
already commit independently (frontier advances per cohort past the 160
boundary); prepared state provably dies with the epoch. Maintenance starvation
(171) is real but collapsed from 3,956 s to the cohort duration; with archive
fixed, epochs shrink to ~run_window time and the intended ~180 s cadence is
reachable. Two boundedness gaps remain in-scope for the epoch design, both
pre-identified in `SNAPSHOT_EPOCH_166.md`: **a wall-time bound on the epoch**
(so retention deferral is bounded by policy, not by cohort cost), and noting
that mid-epoch pruning is pointless as memory relief while the snapshot tuple
pins the signals — the wall-time bound is the correct instrument, not
background pruning against read-copy state.

## 12. Incremental RCA verdict

**NOT NEEDED (full incremental); one targeted incrementalization already
exists and suffices.** The incrementality audit finds: preparation — once per
epoch (168/166, done); pair scoring — cohort-new only + carried edges (done);
per-cycle re-*ranking* of unchanged components — deliberate (lifecycle
correctness; a skipped victim tenant was a real prior bug) and cheap at
4.3 ms/object; persistence — damped by content/material hash (done); archive —
damped only on identical membership, which a sliding window defeats (the
defect). The largest remaining recomputation is the archive slice itself.
A fully incremental engine would need an invalidation graph spanning late
evidence, topology mutation, seam changes, catalog changes, merges — high
correctness risk purchasing headroom the evidence does not yet require.

## 13. State ownership verdict

Tenant→partition→replica ownership with in-process state is **sound for GA at
current scale** and consistent with the zero-trust tenancy model (§3a scoping
is structural in the engine). Two conditions attach: (a) 155 must land before
elastic membership is claimed (§9); (b) the state itself is small (live heap
~170 MB at a full window; RSS plateaus rather than chasing the cap), so
external state stores are **not justified** — reconstruction-from-durable
(`corr_signals` replay on assign) is the natural 155 design, not Redis/RocksDB.

## 14. Template architecture verdict

167's applicability index holds as far as the evidence reaches: cost is tied
to relevant-templates/object (22 of 100 here), semantics pinned byte-identical,
selectivity conservative by construction (impossible templates get analytic
scores, never dropped — the `evidence_missing` lesson). Two honest limits:
live selectivity is **unvalidated** (single-kind workload; the
`--event-mix realistic` harness arm added 2026-08-22 unblocks this), and
catalog growth to 250–1000 templates scales candidates roughly linearly with
per-kind template density — the index defers, it does not remove, O×T. At
~100–250 templates: fine. Compiled matchers/DAGs: **not justified now**;
revisit at ≥500 templates with measured selectivity < ~10 %.

## 15. Tracker 171 verdict

**NOT YET (future, evidence-triggered) — with one before-soak checkpoint.**
Post-167 the worst prune gap was 610/1,363 s vs ~180 s intended, with zero
operational consequence (catch-up complete, memory flat, 165 intact). The
archive fix should shrink epochs below the cadence naturally. Before the soak:
re-measure the gap on the post-fix build; if it still exceeds ~2× intended
cadence, apply the wall-time epoch bound (§11) — the smallest correct fix.
Background/concurrent pruning is NOT approved: it would break the immutable
snapshot contract for no memory benefit (§11).

## 16. Pre-soak tracker matrix

| Tracker | Before soak? | Before GA? | Why |
|---|---|---|---|
| 165 retention | already PASS — stays frozen | yes (holds) | Semantic contract; its gates keep running during soak |
| 166 scheduler/throughput | **MUST PASS** (at the ratified workload) | yes | A soak of an engine that cannot complete its workload measures nothing but expiry |
| 167 template index | live-validate selectivity with `--event-mix realistic` (now unblocked) | yes | The soak should run the mixed profile anyway; single-kind soak re-proves the friendly case |
| 168 identity scope | already PASS | yes (defences frozen) | Do not weaken either layer |
| 169 CI guard | green to merge (not soak-specific) | yes | Line-keyed re-pin workflow is working as designed |
| 170 completion gate | already PASS — it is the soak's own instrument | yes | |
| 171 maintenance cadence | CAN REMAIN OPEN — re-measure post-archive-fix; wall-time bound if gap > 2× cadence | yes | §15 |
| 155 state ownership | CAN REMAIN OPEN — soak on static membership; any uncontrolled rebalance invalidates the soak segment and must be flagged | **MUST PASS** | Routine rebalances silently lose window state today |
| 162 continuation | CAN REMAIN OPEN | before 2.5K | Constant improved; premise re-check needed at O≈1,500 (not 0–8) |
| 163 OPEN_OBJECTS bound | CAN REMAIN OPEN — but its deferral premise ("0–8 observed") is stale at 1,626/1,509; watch `corr_open_objects` during soak with an alert threshold | before 2.5K | Unbounded count + storm = the §7 wall |
| 164 offload queue bound | CAN REMAIN OPEN | yes (resilience) | Proven not the bottleneck; still a §9 defect |
| — memflat nightly slope (474→639 MiB) | **reproduce before soak** (test C, §20) | — | Confounded evidence; a real leak would void a 72 h soak |

## 17. Re-architecture option comparison

| Option | Benefit | Correctness risk | Complexity | GA delay | Scale benefit | Verdict |
|---|---|---|---|---|---|---|
| **A: keep + targeted optimization** | proven loop: 3 order-of-magnitude wins, 0 semantic drift | none new | low | none | reaches ratified 1K, likely 2.5K | **CHOSEN — with the archive change** |
| B: CPU worker processes (scoring stage only) | breaks the one-core-per-tenant ceiling; determinism preserved (pure stage, canonical re-sort) | low (state untouched) | medium | weeks | single-tenant 5K/10K | **PREPARED, not built** — trigger: Falsification B |
| C: finer Kafka sharding (sub-tenant keys) | intra-tenant spread | HIGH — breaks single-owner watermark, continuation, merge; cross-shard edges real (seam-bridge, shared tokens); no correctness-preserving merge exists today | high | months | 10K | rejected now |
| D: per-tenant actors | fairness isolation | medium | high | months | marginal over B | rejected — B subsumes |
| E: fully incremental engine | recomputation removal | HIGH (invalidation graph: late evidence, topology, seams, catalog, merges) | very high | quarters | unproven need | rejected — §12 |
| F: native code hotspots | faster inner loops | medium (dual-implementation drift) | medium | months | ~2–5× on scoring | rejected — measured hotspots were cache/write defects, not interpreter-bound |
| G: externalize state | ownership movement | medium | high | months | none at 170 MB live heap | rejected — 155 solved by durable-replay instead |

## 18. Minimum architecture for GA

1. **Archive persistence re-shape (the one structural change).** Requirements,
   not implementation: slice cost sized by the OBJECT, not the window; archive
   writes off the cohort's frontier-critical path; per-version replay exactness
   preserved (it is a product contract — replay.py, Inspector timeline, Go
   readers). The design space includes membership-reference archiving (store
   (signal_id, corr_id, version) tuples joined against retained `corr_signals`
   at replay, with copy-on-expiry for rows leaving hot retention) and
   span-scoped slices with explicit context bounds — choosing is design work
   with its own equivalence oracle (`test_replay_archive_slice.py` extended),
   done as ONE bounded change under §7 modification rules.
2. **Deploy the already-landed `ch_insert` retry + timeout fix** (in tree,
   2026-08-22, 17 tests, mutation-proven; the running image predates it).
3. **Harness keying fix**: inject with tenant keys (or via the twin through the
   production pipeline) so qualification topology matches production; keep the
   null-key mode only as an explicitly-labelled chaos case if kept at all.
4. **Ratify the GA workload contract** (owner decision; §23 of the contract
   doc) — without it, "166 PASS" is unfalsifiable in both directions.
5. **155** before GA (not before soak): reconstruct-on-assign from
   `corr_signals`, cold-window state visible in the consumer state enum.

Explicitly NOT required for GA: worker processes, partition raise, incremental
engine, external state, native code, template compilation.

## 19. Architecture evolution to 10K

Evidence-triggered path, in order: (i) ratified workload model × measured
constants says the largest supported tenant exceeds ~0.5 core sustained →
build Option B (process-parallel scoring; coordinator keeps persist +
continuation sequential per tenant); (ii) O sustained ≥ ~5,000 per owner →
land 163 cap + 162 index (bounded, defined degradation before RAM exhaustion);
(iii) tenants × EPS spread beyond 4 owners → 155 then BUS_PARTITIONS 4→8
(migration already designed, deliberately deferred); (iv) only if B is
insufficient: revisit C with a real cross-shard merge design. Each step has a
measurable trigger; none is speculative work today.

## 20. Falsification experiments (smallest set)

| # | Experiment | Threshold / behaviour | Conclusion if failed |
|---|---|---|---|
| A | Post-archive-fix truthful 1K (deployed retry fix, harness keyed correctly), CORRELATION_STRESS baseline + `--event-mix realistic` | 170 gate: pending→0 within budget at the **ratified** workload; archive ≤ 5 % of persistence time | If scoring CPU is then the binding constraint at a *ratified* workload on adequate vCPU → the CPU execution model is falsified → build Option B |
| B | Single-tenant ceiling measurement: full tenant keyed to ONE replica, ladder the admitted rate | sustained admitted sig/s at pending→0; compare to ratified largest-tenant requirement | Requirement > ceiling → Option B becomes category C (before 2.5K), not D |
| C | Leak-slope reproduction: completion-gated run + 30 min post-drain observation (+ tracemalloc snapshot) | RSS slope ~0 after pending→0 | Persistent slope → find leak before any soak; soak void otherwise |
| D | Storm object-population test: broad multi-device storm at ratified burst multiplier | `corr_open_objects` bounded; cycle time slope vs O sub-quadratic | Superlinear → promote 162+163 to before-soak |
| E | Replica-scaling check (multi-tenant): 2→4 replicas, ≥4 tenants | ~2× completion throughput | Not ~2× → partition/affinity assumptions wrong; halt scale claims |

## 21. "DO NOT CHANGE" list

Evidence-supported keeps: Kafka/KRaft bus and tenant-keyed co-partitioning ·
165 retention/watermark semantics (516.527 s, stream-time, divergence-suspends-
expiry) · 168 identity model and both defence layers · the pure/deterministic
engine core and its replay contract · the epoch/cohort/frontier scheduler and
the 160 durability boundary · 170's five-condition completion gate · the 167
index approach · in-process state (pending 155's durable-replay design) ·
ClickHouse as the store (7–8 ms p50 on every well-shaped table) · the 1280 MiB
qualified floor · the line-keyed error-swallow guard and the CI gate.

## 22. Top 5 GA architecture risks

| # | Risk | Prob. | Impact | Evidence | Detection | Mitigation |
|---|---|---|---|---|---|---|
| 1 | GA workload contract never ratified → capacity claims unfalsifiable, soak measures the wrong thing | high (it is currently unratified) | high | 27× EPS spread, promotion ratio unmeasured | — (decision, not experiment) | Owner ratifies §23 of the contract doc; harness gains the mixed profile (partly done 2026-08-22) |
| 2 | Archive write amplification (156 residual) | certain (measured) | high — blocks 166/soak | 98.6 % of persistence; 0.47 obj/s | already detected | §18.1; falsification A |
| 3 | Single-tenant ceiling + harness keying artifact overstating capacity ~2× | high | high at enterprise-tenant scale | §8; 50/50 split measured | test B | Option B prepared; fix harness keying now |
| 4 | 155: routine rebalance silently loses window state | certain (source) | high (correctness) | tracker row; no rehydration path | controlled-rebalance test vs twin ground truth | reconstruct-on-assign before GA |
| 5 | Unbounded `OPEN_OBJECTS` × O(S×O) continuation under storm (162+163, stale premise) | medium | medium-high | 1,626/1,509 observed vs "0–8" deferral basis | test D | count cap with defined force-close + tenant-bucketed index |

(Watch item, not ranked: the confounded nightly leak slope — test C.)

## 23. 72-hour soak recommendation

**REQUIRES ONE SPECIFIC FIX FIRST** — the archive persistence re-shape
(§18.1, with §18.2/18.3 deployed alongside), then a truthful 1K PASS at the
ratified workload. Soak at the ratified normal model (not 182/s-because-
convenient, not the 10× stress), static membership, `corr_open_objects` and
prune-gap alerts armed, leak-slope test C passed beforehand. Do NOT gate the
soak on 155, Option B, partition raise, or any 10K work.

## 24. ONE NEXT ACTION

**Re-shape the archive persistence model (tracker 156's residual) as the
single targeted structural change, then run the truthful 1K twice — once at
CORRELATION_STRESS for continuity with the evidence trail, once at
`--event-mix realistic` — on a correctly-keyed harness with the in-tree
durability fix deployed.** (The workload-contract ratification is the owner's
parallel decision and gates how that run is *graded*, not whether it runs.)

---

### Appendix: charter-mandated classifications not covered above

**§2 decision categories for every recommendation made here:**
A (before next 1K): archive re-shape · deploy `ch_insert` fix · harness tenant
keying. B (before soak): ratified workload model for grading · leak-slope
reproduction · 171 re-measure (wall-time bound only if still starved).
C (before 2.5K): 163 cap · 162 index · 155 (also GA-gating) · 167 live
selectivity at scale. D (before 5K): Option B worker processes for the largest
supported tenant · BUS_PARTITIONS 4→8 (after 155). E (before 10K): Option B
mandatory; revisit C-sharding only if B insufficient. F (post-GA): template
compilation · bounded offload executor (164) unless a downstream stall proves
it earlier · explicit backpressure contract formalization. G (not justified by
evidence): external state store · fully incremental engine · native code ·
actors · new bus/framework · GPU.

**§36 bottleneck classification (mandatory):** archive amplification =
**ARCHITECTURE-local design defect (persistence model)**; catalog hashing /
inapplicable-score recomputation = IMPLEMENTATION (fixed); candidate explosion
= correctness defect (fixed, 168); GIL single-owner ceiling = ARCHITECTURE
(deferred, D/E); 10 s CH timeout vs 14.4 s commit = IMPLEMENTATION (fixed in
tree); null-key injection = **QUALIFICATION HARNESS**; lab 2-core box vs
production sizing = RESOURCE SIZING (untested at production vCPU — but note
the GIL makes correlation largely core-count-insensitive per tenant, so
production sizing rescues ingest/storage tiers, not the correlation owner).

**§32 backpressure contract (current, made explicit):** overload ⇒ Kafka lag
grows (durable) → pending grows (bounded by window) → stream-time expiry sheds
oldest evidence UNEVALUATED (counted: 35,422) → window maxlen head-drop
(counted) → storm_mode declared on snapshots at 90 % buffer. Nothing rejects
at ingest; nothing pages on sustained expiry-before-evaluation. Recommendation
(category F, observability not architecture): alert on
`never-evaluated expiry rate > 0` sustained, since it is the system's actual
"cannot keep up" signal.

**§30 determinism inventory:** ordering-dependent algorithms = window sort
(ts, signal_id), node/edge canonical sorts, component fold, tie-breaks
(154a/b), continuation at-most-once per cycle in sorted-tenant order, cid =
uuid5(tenant|first-node-key|onset). All are stable under Option B's
parallel-score/sequential-persist split; C-style sharding breaks the
continuation and merge orders — a further reason C is rejected without a merge
design.
