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

---

## 10. Implementation notes — steps 0 and 1 (builder, 2026-08-28)

Delivered: §9 item 0 (the three byte-neutral caches) and item 1 (the epoch
budget). Items 2–5 are untouched. Every knob is read once at import, like the P1
flags, so an A/B runs on ONE image. What differs from the letter of §3/§4, and
why:

1. **`Signal.signal_id` — the tracker-156 ruling was REVERSED on a fresh
   measurement, and that is the one surprising thing in this step.** The
   docstring in `signals.py` did not merely omit an instance cache, it forbade
   one, on a recorded measurement: "+944 bytes per signal … ~47 MB of RSS bought
   for nothing". That figure **does not reproduce**. Re-measured on today's
   `Signal` (20 dataclass fields, CPython 3.10) with tracemalloc and with RSS
   over 200,000 signals, the cache costs **~128 bytes per signal** — the `UUID`
   object plus one dict slot; the instance dict does **not** resize, because 20
   fields + 1 cache key still fit its table. Across the 50k-signal window cap
   that is ~6.4 MB, not 47 MB. The old note is superseded in place, with the new
   numbers and the caveat that **adding fields to `Signal` could put the resize
   back**. `CORR_SIGNAL_ID_CACHE=0` reverts it on one image. The same ruling
   still stands unchanged for `Signal.to_ch_row`, which is the large object the
   tracker actually fought over.
2. **`Clause.kinds()` uses the identity-keyed bounded dict, NOT a pydantic
   private/instance attribute.** `Clause` is `frozen=True` with
   `extra="forbid"`; anything written onto the model risks reaching
   `model_dump`, and `model_dump` is what `Catalog.version_hash` — the replay
   pin in every `corr_objects` row — is computed from. The repo's existing
   pattern (`catalog._VERSION_HASH_CACHE`, `scoring._CATALOG_PLAN_CACHE`) keeps
   the value entirely off the model, so the pin cannot move. Pinned by
   `test_B4_the_catalog_version_hash_is_unaffected`.
3. **The blob cycle cache is HARD BOUNDED (`CORR_BLOB_CYCLE_CACHE_MAX`, default
   64), not merely cycle-scoped.** §9.0 asks for "a cycle-scoped dict keyed by
   `id(snapshot)` with a strong ref … cleared in a finally", which is what it
   is — but an *unbounded* cycle dict over a storm cohort would retain one blob
   per open object (15–25K × 5.7 KB–MBs), i.e. it would reintroduce the exact
   tracker-156 RSS shape inside the cycle. The access pattern is
   build-then-immediately-reuse (reconciliation computes `content_hash`,
   `_persist_snapshot` writes the row a few statements later), so a small bound
   loses no hits: measured on leg A, blob builds fell from 12,924 to 7,415 =
   exactly one per persisted version (5,509 saved), which is the theoretical
   maximum.
4. **`_drain_epoch_sweep()` was extracted from `engine_loop`** (body verbatim
   plus the budget check). The drain loop lived inside an infinite `while True`
   and had no test surface at all; the budget is a scheduling rule and needed
   one. `engine_loop` now calls it inside the same `try/except`.
5. **The budget check reuses the pending list** the loop condition already
   computed, so it costs no extra walk of the frozen snapshot.
6. **Counters.** `corr_snapshot_digest` gains `kind="blob"` (the blob is not a
   digest, but it is built by `content_hash` and by the row builder, so it
   belongs on the same surface); `corr_engine_epoch_budget_exits_total` and
   `epoch_state()["epoch_budget_s"] / ["epoch_budget_exits_total"]` are new.
   `catalog.clause_kinds_cache_stats()` is exposed for the tests/bench but is
   deliberately NOT on `/metrics` — it is a micro-cache, not an operator signal.

### Measured (offline, `bench_profile_p2.py` leg A, same fixture, one image)
`--devices 500 --signals 7000 --arrivals 3500 --cohorts 20 --epochs 2 --burst 1`,
BEFORE = all three caches off via env, AFTER = defaults:

| | before | after | Δ |
|---|--:|--:|--:|
| total wall | 145.92 s | 93.84 s | **−35.7 %** |
| `P.cohort(total)` | 136.90 s | 89.87 s | −34.4 % |
| `P.run_window(total)` | 63.23 s | 40.50 s | −35.9 % |
| `P.persist(total)` | 37.54 s | 22.83 s | −39.2 % |
| `4.rank(scoring)` | 45.54 s | 28.91 s | −36.5 % |
| `6.hypotheses_blob` | 19.88 s / 12,924 calls | 10.34 s / **7,415 calls** | −48.0 % |
| `6.content_hash` (excl) | 12.25 s | 9.73 s | −20.6 % |
| `7.archive_slice` | 7.10 s | 3.35 s | −52.8 % |
| `1.prepare_run_window` | 1.33 s | 0.48 s | −63.8 % |

**Byte neutrality at scale:** versions persisted (5,509), versions damped (39),
per-table row counts, per-table BYTE counts and insert-call counts are
**identical** between the two legs, as is the whole `cross_epoch_reuse` block
(including `rank_key` hit shares) — the caches changed how often work happens
and nothing else. The epoch budget is not exercised by this offline bench (it
drives its own cohort loop); it is measured by the live P0 script in §8.

---

## 11. Implementation notes — step 2, the level-1 rank memo (builder, 2026-08-28)

Delivered: §9 item 2 (`CORR_RANK_MEMO`). Items 3–5 are untouched. New module
`src/correlation/rank_memo.py` (key derivation + bounded LRU), wired into
`engine.run_window` and `main._engine_cycle_inner`; tests in
`src/correlation/test_p2_rank_memo.py`. Knobs read once at import like the P1
flags, so the A/B runs on ONE image.

### 11.1 The key is NOT the one §3 sketched — it is `rank`'s true input set
§3 proposed `(node.key, kind, severity, entity_id, deviation-bucket)`. Following
what `rank` → `score_template` → `_satisfying`/`clause_matches`/
`_verification_corroborates` → `verdicts.assess` → `coverage` → `witness_of`
actually READ (enumerated with file:line refs in the module docstring) gives a
different set, and the differences matter in both directions:

* **DROPPED** — `node.key` (`rank` never sees a Node; it takes the flat evidence
  tuple) and `severity` (nothing in `scoring.py` or `verdicts.py` reads it — the
  severity floor is `engine.py`'s, applied BEFORE `rank`). Both were sound to
  include but strictly narrowed equality for no reason; dropping them is what
  lets two structurally different components with the same evidence share a
  result.
* **ADDED, and this is the correctness-critical half** — `entity_tokens` (the
  verification co-identity test), and the ENTIRE verdict-gate projection:
  `modality_class`, `observer.observer_id`, `observer.collection_path`, and the
  `attrs` keys `probe_authority`, `probe_scope`, `verify_method`, `agent_host`/
  `agent_id`/`host_id`, `source_egress`/`egress_ip`, `seam_id`, `schedule_id`,
  `target`. A key without these would serve a CONFIRMED verdict to evidence that
  cannot confirm — the bench's "0 collisions over 13,562 keys" would not have
  caught it, because that fixture varies observers barely at all.
  The projection **calls `verdicts.witness_of` itself** rather than re-listing
  its fields, so it cannot drift from the function it describes.
* **EXACT, not bucketed** — `abs(sig.deviation)`. A "deviation bucket" is only
  sound if every bucket edge coincides with every catalog `min_deviation`;
  `abs()` is the exact comparand (`scoring.py:78`), and taking the absolute
  value legitimately WIDENS equality (±d are one class).
* **NOT in the key** — `storm_mode` / `topology_stale`. §3 listed them as "the
  only epoch-context inputs rank/_cap_verdict read"; in fact `rank` takes
  neither, and `_cap_verdict`'s gates read `worst_data_class` and edge grounding.
  Only `rank` is memoized, so the tie-break, both caps, the unknown-hop
  amendment and the whole snapshot build still run on every hit — per §3's own
  rule, they stay out of the key.
* **`tenant` IS in the key**, though `rank` does not read it. CLAUDE.md §3a: a
  cached verdict must be structurally unable to cross a tenant boundary, even
  when the result would be equal by value.

### 11.2 `signal_id` really is a rank input — twice — and both fail CLOSED
`rank` is otherwise order- and instance-independent, but two places read
`str(signal_id)`, and pretending otherwise would have been the unsound shortcut:

1. `scoring.py:232` iterates the `active_verification_healthy` witnesses in
   `signal_id` order and appends to an ORDER-SENSITIVE `contradictions` tuple.
2. `verdicts.py:242` de-duplicates by `signal_id`, FIRST-wins — observable when
   two signals share an id but project differently (`signal_id` =
   `uuid5(NS, source|native_id|ts_ms)` is NOT a superset of the projected
   fields, so a mis-stamping producer can do it).

The first design put an ordered sub-key in the hash; the property test caught it
immediately as the WRONG fix — it made the key move on a pure `signal_id`
perturbation that `rank` ignores, i.e. it reintroduced exactly the id-sensitivity
that measures 0 % cross-epoch. The shipped answer refuses a key in both cases
(≥2 DISTINCT refuting healthy witnesses; any colliding-id pair), counts it as
`unkeyable`, and ranks in full. The key is then a pure SET, so shuffling the
evidence or rebuilding it from `dataclasses.replace` copies cannot move it. On
the bench leg `unkeyable` is 0.

### 11.3 Gating and immutability
* Consulted only when `rank_memo is not None AND cohort_keys is not None` —
  **exactly the level-2 gate**. Golden-wire / replay / direct-test full-window
  runs (`cohort_keys=None`) never reach it, so §6's byte-identity claim holds
  structurally rather than by argument. The property test proves equality would
  hold there too; the gate is kept anyway because the full-window paths are the
  replay contract and are not on the hot path — there is nothing to win and a
  contract to lose. `test_T5b` pins it (and goes red if the gate is widened).
* The stored value is shared BY REFERENCE across components. That is safe for
  the same reason `scoring._build_inapplicable_score` has been sharing one
  `HypothesisScore` catalog-wide since 2026-08-22: `RankingResult`,
  `HypothesisScore`, `Verdict` and `EvidenceCoverage` are frozen dataclasses, and
  every downstream amendment (`_cap_verdict`, `_break_ties_by_seam_affinity`, the
  unknown-hop `replace`) builds a NEW object. The one mutable interior is
  `HypothesisScore.causal_chain`'s dicts; no production path writes to them
  (`to_dict` copies), and `test_T7b` re-checks each held entry against a freshly
  computed ranking after three cohorts of downstream work.
* Bound: `CORR_RANK_MEMO_MAX` (default 50,000), LRU. The value graph is walked by
  `test_T7` and asserted to contain no `Signal`, `Node` or `ObjectSnapshot` —
  the tracker-156 rule.

### 11.4 Measured (offline, `bench_profile_p2.py` leg A, one image)
`--devices 500 --signals 7000 --arrivals 3500 --cohorts 20 --epochs 2 --burst 1`;
BEFORE = `CORR_RANK_MEMO=0`, AFTER = defaults (steps 0/1 caches ON in both).

| | before | after | Δ |
|---|--:|--:|--:|
| total wall | 97.64 s | 72.11 s | **−26.1 %** |
| `P.cohort(total)` | 93.39 s | 68.36 s | −26.8 % |
| `P.run_window(total)` (incl) | 41.61 s | 18.01 s | −56.7 % |
| `4.rank(scoring)` | 29.76 s / 7,375 calls | **4.39 s / 1,686 calls** | −85.2 % / −77.1 % |
| `P.persist(total)` | 24.07 s | 23.74 s | −1.4 % |
| `P.run_window` residual (excl) | 6.77 s | 8.68 s | **+28.2 %** — the key derivation |

The residual line is the honest cost: deriving 7,375 keys costs ≈1.9 s to avoid
≈25.4 s of scoring, i.e. the memo pays for itself ~13:1 on this fixture. Every
other stage moves ≤ a few percent (run-to-run noise; `1.prepare_run_window` and
`9.find_merges` have 2-call absolutes).

Level-1 hit rate per epoch (new bench output):

| epoch | lookups | hits | hit share | entries | evicted | unkeyable |
|---|--:|--:|--:|--:|--:|--:|
| 1 | 4,193 | 2,647 | 63.1 % | 1,546 | 0 | 0 |
| 2 | 3,182 | 3,042 | **95.6 %** | 1,686 | 0 | 0 |

Epoch 2 is the design's whole claim: 95.6 % of the components that reach `rank`
in a LATER epoch have already been scored, where the DecisionKey (signal ids)
would have hit 17.6 % and the P1 intra-epoch memo cannot help at all on a
component's first sighting in the epoch.

**Byte neutrality at scale:** versions persisted (5,509), versions damped (39),
per-table row counts, per-table BYTE counts, insert-call counts and the whole
`cross_epoch_reuse` block are **identical** between the legs. The memo changed
how often `rank` runs and nothing else.

### 11.5 Observability
`/metrics`: `corr_rank_memo{result="hit"|"miss"|"evicted"|"unkeyable"}` (the
fourth series is additive — a fail-closed refusal must never be silent),
`corr_rank_memo_entries`, and `corr_decision_memo_level{level="1"|"2"}` (level 2
= the P1 `COHORT_MEMO_HITS_TOTAL`). `epoch_state()` carries the same figures plus
`rank_memo_enabled`. THE invariant to read them by: level-2 hits reset with every
epoch, level-1 hits keep accruing across them; `unkeyable` climbing means
producers are stamping colliding `signal_id`s.

### 11.6 Set vs multiset — the multiplicity audit (reviewer question, 2026-08-28)
The key reduces the evidence to a **SET** of projections, so N signals sharing a
projection collapse to one. Sound only if nothing up to the `RankingResult`
counts, sums or thresholds over evidence multiplicity. Audited line by line:

| place | reads | multiplicity-blind? |
|---|---|---|
| `_satisfying` hit tuple | truthiness `scoring.py:196, 208, 244, 258, 260`; `.extend` `:197, :210`; `{s.kind for s in hits}` `:259`; `any(...)` `:244` | **yes** — `len(hits)` appears nowhere |
| clause coverage | `(len(required) - len(missing)) / len(required)` `:214` | yes — counts CLAUSES |
| optional bonus | `min(CAP, bonus + PER_CLAUSE)` `:212` | yes — per clause, capped |
| rank sort specificity | `-len(s.satisfied)` `:506` | yes — clause kinds |
| discriminators / forced | per `template.discriminators` `:219-222` | yes — per template |
| healthy-verification tags | `if tag not in contradictions` `:247-248` | yes — de-duplicated |
| causal chain | `bool(hits)`, `sorted({s.kind …})` `:258-259` | yes |
| `verdicts.coverage` | `set(seen.values())` `verdicts.py:243-246` | **yes — the crux**: a set of frozen `Witness` VALUES, i.e. exactly this projection |
| gate thresholds | `modality_count`/`observer_count` `verdicts.py:210-215` vs `MIN_MODALITIES`/`MIN_OBSERVERS` `:371-376`; `independent_pair` `:268-275`; `fate_groups` `:279-308` | yes — all over the de-duplicated witness list / frozensets |

**Answer: no.** Adding a duplicate-projection signal (same kind/entity/observer/
collection_path/attrs, fresh `signal_id` and `ts`) cannot change the
`RankingResult` or the hypotheses blob. `coverage` is the only step where
multiplicity could enter, and it de-duplicates by `Witness` value — which is
precisely what the projection is. `test_T1d` pins that equivalence field-for-field
against `Witness` and `ProbeFate`, so a NEW field on either goes red instead of
silently widening equality.

Pinned by **`test_T1c`** (40 seeds: duplicate 1–3 random signals under fresh ids
⇒ identical ranking, identical blob bytes, identical key) and **`test_T1d`**.

**Mutant, run both ways.** Switching the key to a multiset
(`sorted(Counter(projections).items())`) fails **46 tests — and only the two
key-STABILITY tests**: `T1c` (29) and `T1b` (17), every one of them on the
`rank_key(a) == rank_key(b)` line, *after* that same test's
`rank(a) == rank(b)` and `blob(a) == blob(b)` assertions passed. **Zero**
byte-identity tests (T4/T4b/T4c/T5) move. That is the expected result and it
proves both directions: the multiset is also sound (strictly narrower), and the
set's extra equality is exactly the duplicate-instance case.

**Measured cost of the multiset** on the same leg A: epoch-2 hit share
95.35 % vs **95.60 %** (148 misses vs 140), entries 1,694 vs 1,686, total wall
72.48 s vs 72.11 s. Small here — this synthetic fixture re-touches devices with
*new* evidence rather than re-reporting the *same* evidence, so it
under-represents the population the set protects. The set is kept because it is
proven sound, costs nothing, and the case it covers (a sustained incident
re-reporting evidence it already carries — the #100 damping population, which
the live 2.5K storm has in abundance) is the one the whole memo exists for.

---

## 12. Implementation notes — step 4 (async Evidence plane) + step 4a (lifecycle cohort window), builder 2026-08-29

Delivered: §9 item 4, plus the step-4a merge-cadence fix the live verdict asked
for (`docs/scale/P2_STEPS012_2P5K_VERDICT_2026-08-29.md` §4.2/§4.3). Item 3 (the
full VVR table) and item 5 remain untouched — per that verdict's §6, step 3 is
deferred until step 4 shows Evidence lag is the remaining term. New module
`src/correlation/evidence_plane.py` (the pure `EvidenceItem` + `EvidenceQueue`);
writer, consumer and lifecycle changes in `main.py`; tests in
`test_p2_evidence_async.py` (32) and `test_p2_lifecycle_window.py` (12). Every
knob is read once at import like the P1/P2 flags, so an A/B runs on ONE image:
`CORR_EVIDENCE_ASYNC` (default 1), `CORR_EVIDENCE_QUEUE_MAX` (5,000),
`CORR_EVIDENCE_QUEUE_BYTES_MAX` (512 MiB), `CORR_EVIDENCE_DRAIN_ON_STOP_S` (60),
`CORR_LIFECYCLE_COHORT_WINDOW` (20 = `CORR_ENGINE_DRAIN_COHORTS`).

### 12.1 The split, and where the line actually falls
`_persist_snapshot` is now Decision then Evidence:

* **Decision (synchronous, unchanged bytes/tokens/order):** hypotheses blob →
  `to_object_row` → `corr_objects` insert → `corr_current` projection. Timed as
  the `persist.decision` stage.
* **Evidence (`_write_evidence`, inline or queued):** edges → typed edges →
  evidence → archive slice, the same functions, page sizes and dedup tokens,
  moved verbatim. Timed as `persist.evidence`. Both paths call the SAME body,
  which is what makes the byte-identity test meaningful rather than a
  comparison of two implementations.

**The archive slice is the one thing that could NOT move wholesale**, and this
is the design decision worth reading:

1. `_archive_slice(snap, window)` needs the epoch's window and this cycle's
   `_WINDOW_INDEX_CACHE`, and both are dropped (`_close_epoch`, `engine_cycle`'s
   `finally`) long before a queued item can drain. So slice **membership** and
   its id-hash are computed synchronously; only row building and the inserts are
   deferred.
2. More importantly, the **damping decision is a determinism question, not a
   performance one**. `_ARCHIVE_SLICE_HASH` says "same membership as the LAST
   ARCHIVED version of this object ⇒ skip". Evaluated in the consumer it would
   be decided by the drain ORDER — a runtime condition deciding WHAT is
   written, which §1 forbids outright. It is therefore decided on the Decision
   path, in version order, exactly as today, and the item carries the verdict.
   `test_E1c` pins it: the damped COUNT and the set of `(object, version)`
   archived slices are identical flag-on vs flag-off.
3. Consequence: the hash is recorded OPTIMISTICALLY, before the rows land. A
   failed archive write therefore REVERTS it (guarded on identity so a later
   version's successful record is never clobbered by an earlier version's
   failure draining out of order) — the same rule as today's "record only when
   all chunks landed", expressed the other way round. `test_E5b`.

**RSS trade, verified rather than assumed.** An item holds (a) the
`ObjectSnapshot` — already retained by `OPEN_OBJECTS[cid]["snapshot"]` while the
object is open, so it is a second pointer, not a second graph; for a terminal
version the item holds the LAST reference, which is precisely what lets a closed
object's slice still be written after its registry entry is gone — and (b) the
slice's `Signal` list. Most of that list is `node.signals`, which the snapshot
already holds; the genuinely new retention is the "loose" signals (`*_clear`,
`source=app_identity`) and matched identity signals, which live only in the
window and would otherwise be freed at the next prune. That is why the queue has
a **second, byte bound** (`CORR_EVIDENCE_QUEUE_BYTES_MAX`, 512 MiB) alongside the
item bound: `estimate_bytes(nodes, edges, slice)` with documented per-element
weights, an ESTIMATE for bounding only, never an accounting figure. `test_E4b`
proves the byte bound blocks independently of the item bound.

**One real cost, stated plainly.** `_archive_row`'s per-cycle base-row cache is
keyed by `id(sig)`, and its safety argument is that every archived signal
belongs to the ONE window the cycle is holding open. The consumer runs between
cycles over items from several of them, where a freed `Signal`'s id can be
recycled by a later item's — so the deferred path passes `cache=False` and
builds each row fresh. Bytes are unchanged (`to_ch_row` is deterministic); what
is lost is cross-object row reuse inside a cohort. Measured in the bench below
(it does not show up as a wall regression at this fixture's slice sizes); if it
ever does, the fix is a consumer-side cache keyed on something that cannot be
recycled, not a re-enabled `id()` cache.

### 12.2 The cohort HOLD — §1's "before any Evidence write of the same cohort"
A queue drained by a task on the same loop interleaves with the Decision path by
default, so the cohort's verdict rows would land no sooner than today. `hold()`
parks the consumer for the duration of a cohort's decision pass
(`engine_cycle` wraps `_engine_cycle_inner` in `_evidence_cohort_hold()`), and
the hold is **lifted automatically while the queue is at a bound** — pressure
always beats ordering preference, so a cohort larger than the queue can never
deadlock against its own backpressure (`test_E4d`, `test_E4e`).

`test_E3` asserts the resulting property from both sides: flag ON, every
`corr_objects`/`corr_current` row of a cohort precedes its first Evidence row;
flag OFF, Evidence necessarily interleaves. Without that second half the test
would pass on an implementation that had quietly reverted to inline writes.

### 12.3 Where the consumer is started, and why not in `_persist_snapshot`
`_evidence_ensure_consumer()` is called by `engine_cycle` and by `lifespan` —
never by `_persist_snapshot`. A direct persist outside the engine (tests, replay
tooling, `_epoch_lifecycle` driven by hand) has no surrounding loop to drain a
queue, so it must keep writing inline. `_active_evidence_queue()` enforces three
conditions before ANY enqueue: the flag is on, the consumer task is alive, and
the caller is on the same event loop the consumer runs on. The loop check is not
paranoia — the first full-suite run enqueued onto a queue whose consumer belonged
to a closed `asyncio.run` loop and silently swallowed every later test's Evidence
rows. A queue that can never drain is now counted (`outcome="lost"`), named per
item in the log, and replaced (`test_E6c`).

For the same reason `engine_cycle` drains the queue in its `finally` **only when
it owns its epoch** — a one-shot manual cycle. The engine's own drain sweep
passes an epoch in and is deliberately NOT drained per cohort: keeping the queue
across cohorts is the entire point.

### 12.4 Durability — the honest delta
* An Evidence write that fails after `ch_insert`'s bounded retries is counted
  (`corr_evidence_items_total{outcome="failed"}`) and logged with a traceback.
  **Inline, a rejected RCA-critical child write raised out of the cohort and the
  whole cohort was retried; from the consumer there is no cohort to retry.** The
  Decision row for that version stands (it landed first), so the incident is
  never invisible — only its graph is, until the next version of the object
  re-emits it. `test_E5` pins that the Decision rows all survive a systematic
  `corr_edges` rejection.
* Shutdown drains for at most `CORR_EVIDENCE_DRAIN_ON_STOP_S` (60 s), then logs
  ONE LINE PER ITEM and counts `outcome="lost"` (`test_E6`, `test_E6b`). **No
  schema changed in this step**, so the shutdown log and the counter are the
  whole cross-restart detection surface; §2's VVR `evidence_state` is where this
  becomes queryable after a restart, and the module docstring says so.

### 12.5 Observability
`/metrics`: `corr_evidence_queue_depth`, `_bytes`, `_oldest_age_seconds`,
`corr_evidence_lag_seconds` (T7 — verdict → materialized graph),
`corr_evidence_queue_backpressure_total` (how often the Decision plane was
slowed to keep the queue bounded — the LOSSLESS half of "never drop"), and
`corr_evidence_items_total{outcome=materialized|failed|lost}`. `epoch_state()`
carries the same dict under `"evidence"`. Stage spans `persist.decision` /
`persist.evidence` split the profiler's single persist figure in two
(`test_E8b`). THE invariant to read them by: `depth` returns to 0 between storms
(spec §2's T8), `lag_seconds` is T7, and `failed_total`/`lost_total` must both
stay 0.

Also folded in (coordinator, 2026-08-29) — the level-1 rank memo's new BYTE
bound needed its two hand-written surfaces in main.py updated:
`rank_memo_stats()`'s memo-OFF branch now returns `bytes`/`bytes_max`/
`evicted_bytes` as zeros (a key that appears and disappears with a flag reads as
a zero on the day it matters), and `_metrics_text()` gained
`corr_rank_memo_bytes`, `corr_rank_memo_bytes_max` and
`corr_rank_memo_evicted_bytes_total`. Pinned by `test_E9`/`test_E9b`, which
compare the OFF branch's key SET against the live memo's field for field.

### 12.6 Step 4a — and the ONE place these notes narrow the brief
The brief (and §4.2) asked for merge/quiesce/cap over the union of the last K
cohorts' `seen` sets. **Only the MERGE candidate space was widened.** Quiesce and
the 163 count cap keep the epoch's own set, and `test_L4`/`test_L4b` pin that.

The reason: `seen` does two different jobs. For `find_merges` it means "this
object is LIVE, so it may receive a merge" — and that is what the budget broke,
because a one-cohort epoch has almost no live targets. For quiesce it means
"don't age this object", and that job is already done correctly, and in a
TIME-BOUNDED way, by `last_seen` + `CORR_QUIESCE_S`. A cohort can be ~1,000 s
wide at 2.5K, so K = 20 cohorts of history would suppress quiesce for hours and
push the population onto the 163 cap instead of closing it. P1's own protection
was not unbounded either — it was one epoch of a FROZEN `now`. Widening the
merge partition restores exactly the candidate space P1 measured; widening
quiesce would go further than P1 ever did, in the wrong direction.

Mechanically: `_LIFECYCLE_SEEN_WINDOW` is a module-level `deque(maxlen=K)` of
per-cohort `seen` sets, appended in `_engine_cycle_inner` AFTER the cohort has
committed its versions (so a cohort that raised leaves nothing behind —
`test_L5`), and never touched by `_close_epoch`. `_lifecycle_merge_seen(epoch)`
returns the union plus the epoch's own set; `CORR_LIFECYCLE_COHORT_WINDOW=0`
returns `epoch.seen` (the shipped P1 shape) and
`CORR_LIFECYCLE_EPOCH_CADENCE=0` still passes an explicit per-cohort set, which
bypasses the window entirely (`test_L6b`, `test_L6c`).

`test_L1`/`test_L1b` are the regression shape end to end: five epochs of ONE
cohort each; the merge target materializes in cohort 1, its evidence then leaves
the window, and a quiet duplicate arrives later. With the window the twin folds
into the target; with `CORR_LIFECYCLE_COHORT_WINDOW=0` it does not — which is
run `p2-s012d`'s 378 → 11. `test_L2` proves the deque's `maxlen` is doing the
bounding (the SAME fixture finds the merge under K=20 and loses it under K=2),
and `test_L0` proves the twin is mergeable at all, so L1/L1b cannot both pass for
the wrong reason.

New counters: `corr_lifecycle_seen_window_cohorts`, `_ids`, plus
`lifecycle_cohort_window` in `epoch_state()`. The invariant an operator reads:
`cohorts_last` = 1 (a budget-bounded epoch) while `lifecycle_seen_window_cohorts`
= K.

### 12.7 Measured (offline, `bench_profile_p2.py`, one image, same seed)
`bench_profile_p2.py` gained `--insert-sleep-ms` (the mocked sink now models the
LIVE per-insert latency; the 2.5K run measured 149,590 inserts / 1,840 s ≈ 7 ms
p50 sequential) and reports **decision-complete vs evidence-complete** per
cohort. Without a modelled insert latency the bench measures Python CPU only and
the entire question — who WAITS behind whom on an awaited insert — is invisible.

`--devices 250 --signals 2500 --arrivals 1200 --cohorts 6 --epochs 2 --burst 6
--insert-sleep-ms 7`, BEFORE = `--no-evidence-async`, AFTER = defaults:

| | before | after | Δ |
|---|--:|--:|--:|
| cohort **decision-complete**, mean | 2.87 s | **1.94 s** | **−32 %** |
| cohort **decision-complete**, max (the storm cohort) | 18.76 s | **13.81 s** | **−26 %** |
| decision share of cohort wall | 100 % | **67 %** | — |
| cohort wall (decision + evidence), mean | 2.87 s | 2.89 s | +0.7 % |
| total sweep wall | 36.46 s | 36.50 s | +0.1 % |
| `P.persist(total)` (inclusive) | 26.91 s | 16.57 s | −38 % |
| `P.ch_insert(total)` | 24.87 s | 25.77 s | +3.6 % |

Read it as: the same work, the same inserts, the same wall — **reordered so the
verdict lands first.** The decision share (67 %) tracks this fixture's insert mix
(3.3 inserts per version, of which 2 are Decision = 61 % — the extra points are
the Evidence rows that drain while the next cohort is computing). The LIVE mix is
4–5 inserts per version, so the same reordering should put the decision share
near 40–50 % there, i.e. a larger TTUR win than this fixture can show. The
storm-cohort max is the number that matters for T1: the first cohort of an epoch
is where the operator's wait is minted.

**Byte neutrality at scale:** versions persisted (1,004), versions damped (80),
per-table row counts, per-table BYTE counts, insert-call counts and the whole
`cross_epoch_reuse` block are **identical** between the legs. The queue changed
when rows were written and nothing else.

### 12.8 Gate
`cd src/correlation && ruff check . && mypy main.py && python3 -m pytest . -q`
→ **1,896 passed / 9 skipped** for this change's scope (1,852 baseline + 44 new),
`ruff`/`mypy` clean on `main.py`, `evidence_plane.py`, `bench_profile_p2.py` and
both new test files. The one pre-existing edit outside this change is
`test_storm_mode_2026_08_28.py`, whose `_persist_snapshot` double needed the new
`priority_class` keyword.

### 12.9 What step 4 does NOT fix, and what to measure next
The queue removes the Evidence rows from the operator's critical path; it does
not remove them from the box. Total wall is unchanged by construction, so the
completion gate (pending 0 within 2,700 s) is NOT expected to pass on this step
alone — §4.3's other half, damping the 3.27 versions per incident, is still
open. The live re-measure should read: T1 p95 (expected to fall with the
decision share), the new T7 (`corr_evidence_lag_seconds`) and T8
(`corr_evidence_queue_depth` returning to 0), `corr_evidence_queue_backpressure_total`
(non-zero means the box cannot absorb the Evidence rate and the queue is doing
its job), `failed`/`lost` (must be 0), and merges (11 → the P1 population, per
step 4a).
