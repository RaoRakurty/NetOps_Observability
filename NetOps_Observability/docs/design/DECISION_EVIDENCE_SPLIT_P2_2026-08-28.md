# P2 — Decision / Evidence plane split (design, 2026-08-28)

Authority: owner memo `/var/tmp/Correlix-Bottleneck-Modified.md` §14–§15, §19–§25;
research synthesis `STORM_PLANE_SEPARATION_RESEARCH_2026-08-28.md`; P1 verdict
`docs/scale/P1_2P5K_VERDICT_2026-08-28.md` §4 (the measured brief for this step).
Owner decision 2026-08-28: **no more hardware** — success is engine efficiency +
TTUR SLOs on the 4-core box. Vocabulary: Aggregation / Decision / Evidence planes;
"priority-aware materialization", never "shedding"; lossless always.

## 0. The problem this step solves, from the P1 measurement
After P1 the 2.5K storm still needs ~106 min after burst end to reach pending 0
(budget 45 min) and TTUR is ~100 % queueing latency (T1 p95 4,767 s vs 5 s SLO).
Where the load epoch's time goes (P1 verdict §4):
1. **61 % of component evaluations in the load epoch were untouched components
   ranked anyway** (8,941 of 14,605), because the P1 memo is intra-epoch: every
   component's first sighting in an epoch pays full `rank`+materialize. Per
   cohort ≈190 s, GIL-bound compute; ClickHouse inserts are 17.5 % of wall.
2. **One epoch = 20 cohorts ≈ 65 min.** Retention prune, merge/quiesce/cap and
   the operator-visible "settled" state wait for the epoch; `oldest_pending_age`
   sits at 710 s (> 516 s horizon) the whole time.
3. Every persisted version pays the full graph write (objects+current+edges+
   evidence+archive slice ≈ 4–5 inserts, blob serialization) **before** the next
   object's verdict can be computed. 42,455 versions for ~1,900 material verdict
   changes ≈ **22 : 1** (memo §6 "raw-to-verdict amplification"; P1 improved
   it from 30.6 : 1).

Offline per-stage profile of the real sweep at 2,500-device shape
(`docs/scale/P2_COHORT_PROFILE_2026-08-28.md`, `bench_profile_p2.py`; shares
transfer, seconds are a floor — 17 s/cohort mocked vs ~190 s live): **rank 31.8 %**
(lower bound — live memo hit rate was far worse than the synthetic's) ·
**digests 28.4 %** (hypotheses_blob 16.4, content_hash 10.3, material_hash 1.7) ·
executor/asyncio glue 15.9 % · persist row building 11.8 % · materialize 7.5 % ·
build_edges+prepare+components+lifecycle < 5 %. Two findings change the design:
`hypotheses_blob` is built TWICE per version (content_hash embeds it and it is not
instance-cached per the tracker-156 RSS rule) — a cycle-scoped cache is ≈7 % of
cohort wall for free; and a memo keyed on node signal ids would hit **0 %** across
epochs (signal ids move with arrivals and the 50K window cap) whereas a rank-level
key (node | kind | severity | entity | deviation + catalog version) matched 100 %
of the reusable components with 0 collisions over 13,562 keys.

P2 attacks exactly these, in order of payoff, without a second RCA algorithm
(memo §15) and without moving `content_hash` bytes.

## 1. Architecture: ONE computation, two completeness levels
`F(component inputs) → ObjectSnapshot` is the deterministic causal computation
(`run_window`'s per-component body: `build_edges`→`_components`→`rank`→snapshot).
Nothing in P2 adds a second F. The planes are **projections of F's output at two
completeness levels**, scheduled differently:

| plane | what it emits | when | cost class |
|---|---|---|---|
| **Decision** | `RCA Verdict Record` (§2) — a projection of the snapshot's `ranking`, seams, affected set, confidence, state | synchronously, per cohort, **before** any Evidence write of the same cohort | O(touched components) after §3 |
| **Evidence** | edges, evidence rows, typed edges, archive slice, hypotheses blob — the full graph a replay/forensics needs | asynchronously from a durable, bounded, **priority-ordered** queue (§4); may lag in a storm | O(graph size) |

Determinism (memo §21, non-negotiable): runtime conditions decide **when** an
Evidence item is written, never **what** it contains — each item is a pure
function of a frozen snapshot that already exists. Backpressure over loss: when
the queue is full the Decision plane blocks (memo §22), it never drops.

## 2. RCA Verdict Record (VVR) — the Decision plane's row
New ClickHouse table `netops.corr_verdicts` (append-only MergeTree, RLS/tenant
scoped like `corr_objects`; `corr_current` stays the ReplacingMergeTree
projection Command Center reads — it is rebuilt from the VVR, not from the blob):

```text
tenant_id, correlation_id, version              -- same identity as corr_objects
topology_version, catalog_version, engine_version, policy_version (new; today = engine_version)
verdict_state: DETECTED | PRELIMINARY | CORROBORATED | STABLE | FINALIZED | RECOVERED
probable_cause (= top_hypothesis), causal_seam (seam id/type), owner
confidence, confidence_label, verdict_tier
blast_radius: node_count, device_count, site_count, service_count
affected_services, affected_sites            (arrays, from `affected`)
supporting_modalities, supporting_vantages   (arrays — distinct source kinds / observers over the nodes)
contradictory_summary                        (count + top contradicting signal kinds)
evidence_segment_refs                        (which corr_edges/corr_evidence/archive versions carry the graph; empty until the Evidence plane lands them)
raw_offset_ranges                            (min/max Kafka offset per partition of the slice — replay pointer)
decision_material_hash (= material_hash), content_version (= content_hash)
evidence_state: PENDING | MATERIALIZED       (flipped by the Evidence plane; never gates the verdict)
created_at
```
State derivation is content-derived only (no wall clock): DETECTED = v1
undetermined; PRELIMINARY = tier suspected, 1 modality; CORROBORATED = ≥2
independent modalities or vantages (T5); STABLE = `material_hash` unchanged over
K further evaluations **that carried new evidence** (K content-derived, default
3 — not seconds); FINALIZED = closed + `evidence_state=MATERIALIZED`; RECOVERED =
recovery transition seen on the causal entity. The existing `state` enum and
`corr_objects` contract are unchanged — VVR is a **new versioned representation**
with its own equivalence test (memo §24), not a byte-identity claim.

T5/T7/T8 (tracker 177 gaps) become measurable: T5 = first CORROBORATED, T7 =
`evidence_state=MATERIALIZED`, T8 = Evidence queue depth returns to 0.

## 3. Two-level content-addressed decision memo (the compute lever)
P1's `ComponentMemo` (node-key set, one epoch) stays as **level 2** — the whole
snapshot, valid while nodes are frozen. **Level 1 is new and cross-epoch: a
`rank` memo**, because `rank(catalog, evidence)` (scoring.py:489) is a pure
function of the evidence's *kinds/entities/severities* and the catalog — not of
signal instances — and the profile shows the rank-level identity is what survives
epochs (100 % match of the reusable set, 0 collisions).

```text
RankKey = sha256(catalog_version,
                 sorted((node.key, sig.kind, sig.severity, sig.entity_id, sig.deviation-bucket)
                        for node in comp for sig in node.signals),
                 storm_mode, topology_stale)          # the only epoch-context inputs rank/_cap_verdict read
RankMemo: bounded LRU RankKey -> RankingResult (+ the tie-break/cap inputs it feeds)
```
**Soundness is proven, not assumed**: the builder first derives the key from the
fields `rank`/`score_template`/`verdicts.assess`/`_cap_verdict` actually READ
(grep shows `s.kind`, `s.signal_id` directly plus whatever the Clause matchers
touch — enumerate them), then ships a property test: for random evidence tuples,
perturb every NON-key field (ts, signal_id, observer, raw text, tokens) and
assert `rank` output is identical; perturb any key field and assert the key
changes. If a non-key field turns out to influence `rank`, it joins the key —
the memo never widens equality beyond the function's true inputs. On a level-1
hit the component still materializes its snapshot (edges/nodes are per epoch),
but skips `rank` (31.8 % of cohort wall, lower bound); level-2 hits skip
everything. Bounded: `CORR_RANK_MEMO_MAX` entries (default 50,000; a
`RankingResult` is small — no snapshot reference, no RSS exposure).
- `hypotheses_blob` cycle cache: build once per (snapshot instance, cycle) and
  reuse in `content_hash` and `to_object_row`; dropped at cycle end (never held
  on the snapshot — tracker 156). ≈7 % free.
- Micro-hotspots from the cProfile: `Clause.kinds()` recomputes a split/frozenset
  ~248 k times per cohort (~15 % of `run_window`) — memoize on the Clause
  instance; `Signal.signal_id` re-derives a uuid5 ~67 k times (~18 %) — cache
  per instance. Byte-neutral, test-pinned.
- Counters: `corr_rank_memo{result=hit|miss|evicted}`, `corr_decision_memo_level{1|2}`,
  `corr_cohort_components_reranked_with_new_evidence_total` (memo §5 waste ratio).
- `CORR_COHORT_TOUCH_GATE=0` still disables both levels.

## 4. Evidence plane: deferred, prioritized, durable materialization
`_persist_snapshot` today = object row → current row → edges → typed edges →
evidence → archive slice, inline, per version. P2 splits it:

**Synchronous (Decision):** VVR row + `corr_objects` row (the versioned truth,
small) + `corr_current`. Cost ≈ 2–3 small inserts and NO blob serialization
(`hypotheses_blob` moves to the Evidence item; `corr_objects.hypotheses` is
written by the Evidence item as a second row-version? NO — that would move the
table's semantics. Decision: `corr_objects` keeps the blob, so the blob build
stays synchronous **but only on material change**; a heartbeat/unchanged version
writes VVR only. Blob cost is already bounded by P1 §3 single build.)

**Asynchronous (Evidence):** one `EvidenceItem(snapshot_ref, version, tok,
priority_key)` per persisted version, holding: edge pages, typed-edge pages,
evidence pages, archive slice (same functions as today, same dedup tokens, same
bytes — the writer code moves, it does not change). Queue: in-process
`asyncio.PriorityQueue`, **bounded** (`CORR_EVIDENCE_QUEUE_MAX`, default 5,000
items / 1 GiB of referenced snapshots); `put` blocks the Decision plane when full
(backpressure, memo §22). Ordering key is content-derived (memo §19, §21):
`(priority_class, window_start, correlation_id, version)` where priority_class =
P0 new incident / cause change / recovery · P1 corroboration or contradiction ·
P2 blast-radius or owner change · P3 repeated support (heartbeat) · P4 closed /
settled forensic expansion. Runtime load changes the drain **rate** only.
Durability: an item is recomputable from `OPEN_OBJECTS[cid]["snapshot"]` while
the process lives; on restart, pending items are lost **but detectable**: VVR
rows with `evidence_state=PENDING` and no matching edge/evidence/archive rows are
re-materialized by a startup reconciler that replays the archive slice's inputs
from the retained window (or, if pruned, marks the version
`evidence_state=UNRECOVERABLE` — loud, counted, never silent). Raw Kafka events
are retained regardless (lossless).

**Epoch budget:** `CORR_ENGINE_EPOCH_BUDGET_S` (default 300) ends the drain sweep
when exceeded even below 20 cohorts, so prune/lifecycle/`oldest_pending_age`
recover on a bounded cadence. Cohort formation is already arrival-ordered and
per-object replay is pinned by the version's archive slice, so this changes
scheduling, not any object's content.

## 5. Priority-aware materialization inside the Decision plane
Within a cohort, evaluate touched components in a content-derived order (severity
rank, then earliest onset, then cid — the storm sort generalized to all modes) so
that under backpressure the highest-value verdicts land first. Memo hits cost O(1)
and are ordered after misses only in **persist** (they are unchanged; their VVR
is not re-written unless a heartbeat is due).

## 6. What does NOT change (pin with tests)
- `content_hash`, `material_hash`, `hypotheses_blob` bytes; `corr_objects` /
  `corr_edges` / `corr_evidence` / `corr_signals_archive` row bytes and dedup
  tokens; golden-wire full-window output (`cohort_keys=None` ⇒ no memo).
- Replay: `replay.py` reads the same archive slice; the VVR is additive.
- Storm-aggregate branch (P1 §2.1) untouched.
- Tenant isolation: VVR table gets the `tenant_iso` FORCE-RLS migration and is
  queried via the same tenant scope as `corr_objects` (CLAUDE.md §3a).

## 7. Tests (mutant-style, Opus builds, Fable grades)
T1 level-1 property test (non-key perturbation ⇒ identical `rank`; key perturbation
⇒ key change) and level-2 hit returns the identical snapshot object and digests;
T2 any single key input change (kind/severity/entity/catalog version/storm flag) ⇒
level-1 miss; T3 memo eviction on close/merge/cap; T4 golden-wire
byte identity unchanged; T5 VVR state machine table-driven (each transition from
content, none from clock); T6 Evidence queue: bounded, blocking put, priority
order is stable under shuffled arrival; T7 restart with PENDING items ⇒
reconciler re-materializes or marks UNRECOVERABLE (counted); T8 determinism:
same input log with epoch budget 30 s vs 3,000 s and with injected loop stalls
⇒ identical final VVRs and identical Evidence rows (versions may differ in
count; content per version identical); T9 equivalence test OLD-representation vs
VVR (memo §24 list) on the 166/162/168 fixtures; T10 tenant isolation of the VVR
surface (cross-tenant get → 404 / own-only list); T11 false-merge/false-split
metrics on the storm fixture (memo §25) — asserted unchanged from P1.

## 8. Measurement plan (P0 script is the judge)
Re-run the exact 2.5K workload to the **completion gate** (harness interrupt fix
first). Report with `scripts/scale-rca-latency.py` clean-scope method: T1/T4/T6
p95, T5/T7/T8 now measurable, versions per material change, memo hit share of
first-sight components, epoch length max, Evidence queue depth/age max, CH insert
share. Targets (stretch, owner rule "exceed baselines"): T1 p95 ≤ 600 s at 2.5K
on this box (from 4,767), versions/material change ≤ 5 : 1, epoch max ≤ 300 s,
pending 0 within the 2,700 s budget.

## 9. Delivery order (each a separate commit, each A/B-flagged)
0. §3 byte-neutral wins: hypotheses_blob cycle cache, `Clause.kinds()` and
   `Signal.signal_id` caches (~25–30 % of cohort wall combined, per the profile).
1. §4 epoch budget (tiny; fixes the 65-min epoch) — `CORR_ENGINE_EPOCH_BUDGET_S`.
2. §3 level-1 rank memo with its soundness property test — `CORR_RANK_MEMO`.
3. §2 VVR table + writer + `corr_current` rebuilt from it — `CORR_VERDICT_RECORD`.
4. §4 Evidence queue + startup reconciler — `CORR_EVIDENCE_ASYNC`.
5. §5 priority ordering. Then §8 re-measure (P4). P3 Aggregation plane follows.
