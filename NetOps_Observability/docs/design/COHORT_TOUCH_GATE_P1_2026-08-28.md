# P1 — Cohort-touch gate, digest memoization, epoch-cadence lifecycle (design, 2026-08-28)

Implementation-ready spec (Fable). Builder: Opus subagent. Verifier: Fable, then
owner. Parent: `docs/design/STORM_PLANE_SEPARATION_RESEARCH_2026-08-28.md` and the
owner's `/var/tmp/Correlix-Bottleneck-Modified.md` (§11–§13 = this P1; §3 renames the
planes **Aggregation / Decision / Evidence** — use those names from now on, never
"data plane" for the evidence side).

## 0. Problem, in one paragraph
One sweep freezes an epoch once (tracker 166) and drains up to
`CORR_ENGINE_DRAIN_COHORTS=20` cohorts against it. Per cohort, `run_window` still
re-forms every component, re-ranks it, re-materializes an `ObjectSnapshot`, and
main.py re-hashes it (content + material) and re-walks merge/quiesce/cap over all
open objects — for **every** open incident, though only the components a cohort's
`_cohort_keys` touch can have changed. At 2.5K that is ~15.6K–24.6K objects × up
to 20 cohorts of pure re-derivation per sweep; the damp counter (`VERSIONS_DAMPED`)
is the proof it is thrown away. Fix: don't do it.

## 1. Soundness argument (why an untouched component's snapshot is reusable)
Verified against `engine.py` / `main.py` @ `2abbf74d`:
- Nodes are frozen for the epoch (`epoch.preps[tenant].nodes`; `prep.matches_window`
  is object-identity, `test_the_epoch_hands_run_window_the_SAME_window_object_every_cohort`).
- `build_edges(cohort=…)` scores only pairs with ≥1 endpoint in the cohort
  (engine.py ~1399–1425). Carried edges (`_carried_edges_for`) are filtered by
  `epoch.live_keys`, constant within the epoch. Fresh wins over carried only for a
  pair that has a cohort endpoint. ⇒ within an epoch the edge set is **monotone**
  and every new/replaced edge has a cohort endpoint.
- `_components` is union-find over nodes+edges; `_fold_seam_bridged_components`
  is pure. ⇒ components only **merge** within an epoch, and a merge always
  contains a touched node.
- Everything else a snapshot is built from — catalog, seams, cfg, adjacency,
  `disc`, `view`, `storm_mode`, `topology_stale`, `topo_ver`, `eng_ver` — is
  per-epoch constant (`epoch.ctx[tenant]`, `epoch.storm`, `epoch.topo_stale`).
- `rank`, `_break_ties_by_seam_affinity`, `_cap_verdict`, cid (uuid5 of first
  node+onset), `adjacency_pairs`, `object_attribution`, `_storm_dedup_comp`,
  `_identities_for` are pure functions of the above.

Therefore: **a component with no node key in `cohort_keys` produces, on cohort n,
a snapshot equal to the one it produced on the last cohort that touched it (or on
cohort 1), on every field except two per-TRANSACTION fields:**
1. `gap_hints` — `run_window`'s transaction-global diagnostic, embedded in the
   blob as `topology_gap_hints`. The archive-slice/replay contract already records
   the gap-hint count as "the one thing that legitimately differs on replay"
   (engine.py ~1526–1535). Reusing the touching cohort's value is inside contract.
2. `orientations` — `RecordingOracle` is constructed per `run_window` call
   (engine.py ~2548); an untouched component's pairs are never re-oriented (its
   edges are carried), so today its re-materialized snapshot has
   `orientations=()` and its blob DROPS the embedded orientations that make a
   directed edge replay deterministically (C7). The memoized snapshot keeps them.
   **This is a latent replay-fidelity defect the gate fixes as a side effect —
   pin it with a test (§6 T7), do not "preserve" the bug.**

Hence the gate does not move `content_hash` **bytes** (the function is untouched;
its inputs for a memo hit are the inputs of the cohort that built the snapshot).

## 2. Change G — cohort-touch gate (engine.py `run_window` + main.py epoch)
### Interface
```python
class ComponentMemo:              # engine.py, caller-owned, EPOCH-scoped
    """Per-tenant intra-epoch cache: frozenset(node keys) -> ObjectSnapshot.
    Pure-data. Lives on _EngineEpoch; discarded in _close_epoch."""
    hits: int; misses: int; touched: int; components: int
    def get(self, comp_key: frozenset[str]) -> ObjectSnapshot | None
    def put(self, comp_key: frozenset[str], snap: ObjectSnapshot) -> None

def run_window(..., cohort_keys=None, carried_edges=(), prep=None,
               memo: ComponentMemo | None = None) -> list[ObjectSnapshot]
```
### Semantics (inside the `for comp in comps:` loop, engine.py ~2603)
1. Keep the below-open-floor / storm-aggregate branch exactly where it is (it must
   run every cohort — the aggregate object is rebuilt from ALL below-floor nodes;
   it is O(nodes), no `rank`, deterministic; leave it alone).
2. After that `continue`, before `comp_sigs`:
   ```python
   comp_key = frozenset(n.key for n in comp)
   touched = cohort_keys is None or not cohort_keys.isdisjoint(comp_key)
   if memo is not None and not touched:
       hit = memo.get(comp_key)
       if hit is not None:
           snapshots.append(hit); memo.hits += 1; continue
   ... existing build ...
   if memo is not None: memo.put(comp_key, snapshot)
   ```
   `cohort_keys is None` (full-window run: golden wire, replay, tests) ⇒ every
   component is touched ⇒ memo never consulted ⇒ those paths are byte-for-byte
   untouched. Emission ORDER is unchanged (same `comps` iteration, memo hits
   appended in place), so the storm severity sort and non-storm order are the same.
3. Memo key is the **node-key set**, never the cid: a merged component has a
   different key and is rebuilt (its nodes include a touched one anyway).
### Caller (main.py)
- `_EngineEpoch` gains `memos: dict[str, ComponentMemo]` (add to `__slots__`);
  `_engine_cycle_inner` passes `memo=epoch.memos.setdefault(tenant, ComponentMemo())`
  into `run_window`. `_close_epoch` drops them (the memo is NOT process-lifetime —
  cross-epoch reuse is P2 material: nodes are rebuilt after prune, so the key would
  need to be content-addressed over signal ids; do not do it here).
- `run_window` runs on the executor; the memo is mutated there. Access is
  sequential (one awaited `run_window` per tenant per cohort) — no lock needed;
  document that invariant on the class.
- Config: `CORR_COHORT_TOUCH_GATE` (env, default `1`, read once at startup like the
  other `CORR_*` knobs). `0` ⇒ `memo=None` everywhere ⇒ exact pre-P1 behaviour.
  Exists so the owner's A/B (§18 of the memo: same 900,001-event storm, OLD vs
  NEW) runs on ONE image. Same for `CORR_LIFECYCLE_EPOCH_CADENCE` (§4).

## 3. Change M — memoize the immutable snapshot's digests; build the blob once
- `ObjectSnapshot.content_hash()` / `material_hash()`: compute once per object,
  cache the 16-char digest on the instance. `ObjectSnapshot` is
  `@dataclass(frozen=True)` without slots ⇒ store via
  `object.__setattr__(self, "_content_hash_c", v)` (or `functools.cached_property`
  behind the method). NOT a dataclass field: never in `__eq__`/`__hash__`/`replace`;
  `dc_replace` (continuation re-key) therefore yields a fresh, uncached copy — that
  is correct (the cid is in the object row, not in `content_hash`, but never assume;
  fresh copy = recompute). Thread-safety: pure idempotent compute; a race only
  recomputes. Bytes: identical to today by construction (same function body).
- Do **NOT** cache `hypotheses_blob` on the instance: 15–25K open snapshots ×
  5.7 KB–MBs is the RSS tracker 156 fought for. Instead thread it through one
  persist: `to_object_row(version, state, merged_into, *, hypotheses: str | None = None)`;
  `_persist_snapshot` builds it once via `_snap_call` and passes it in. Result per
  persisted version: blob built ≤2× (hash + row) instead of 3–4×; per
  damped/unchanged object: 0× (was 1–2×).
- Reconciliation (main.py ~3834–3866) becomes O(1) for a memo hit: `chash`
  is the cached digest; `reg["hash"] == chash` ⇒ `else` branch. Optional fast
  path `if reg is not None and reg["snapshot"] is snap:` — allowed, but it is
  not required for the saving and must not change which snapshot `reg` holds.
- `_persist_snapshot`'s token `content_hash` call → cache hit (was a second
  full serialize+sha256 of the storm object).

## 4. Change H — hoist merge / quiesce / cap to epoch cadence
Today (main.py ~3889–3930) `find_merges` (O(survivors×stale)), quiesce (O(open))
and the 163 cap (O(open log open)) run after EVERY cohort. Their inputs at cohort
cadence: `OPEN_OBJECTS`, `seen_this_cycle`, and `now = epoch.now` — the timestamp
is already the epoch's, so nothing they decide depends on WHICH cohort runs them.
- Extract to `async def _epoch_lifecycle(epoch: _EngineEpoch, loop_yield) -> None`
  containing the three passes verbatim. `seen` = `epoch.seen: set[str]`, the UNION
  of every cohort's `seen_this_cycle` (keep the per-cohort set: it is still the
  `exclude=` for `find_continuation`, and `materialized` stays per cohort).
- Call it ONCE per epoch on the SUCCESS path only: (a) drain loop (main.py
  ~4031–4044) after the `while` exits normally, before `finally: _close_epoch`;
  (b) `engine_cycle()` own-epoch path after `_engine_cycle_inner` returns. A cohort
  that raises ⇒ no lifecycle pass this epoch (today a failing cohort also skipped
  its own pass; earlier cohorts' passes are re-derivable next epoch). Tests
  `test_a_failing_cohort_still_releases_the_epoch` and
  `test_cohorts_before_a_failure_stay_committed…` must stay green.
- Documented behaviour deltas (both in the correct direction, both flag-revertible):
  1. `CORR_OPEN_OBJECTS_MAX` is enforced once per epoch: the count may transiently
     exceed the cap within an epoch by the objects opened in that epoch. Expose the
     transient peak (`corr_open_objects_epoch_peak`). The cap-163 tests drive
     `engine_cycle()` (own epoch) ⇒ enforced at its end ⇒ unchanged results.
  2. An object that cohort k would have quiesce-closed and cohort k+1 would have
     continued now survives to be continued (one incident instead of close+new).
- `CORR_LIFECYCLE_EPOCH_CADENCE=0` ⇒ call `_epoch_lifecycle` after every cohort
  with `seen=seen_this_cycle` ⇒ exact pre-P1 behaviour (A/B knob).

## 5. Counters (owner memo §3 — the P1 proof is these numbers, not a feeling)
Monotonic per replica, exposed in the engine state dict + `/metrics`
(`corr_*` naming as `versions{outcome=…}`):
`corr_cohort_components_total`, `corr_cohort_components_touched_total`,
`corr_cohort_components_memo_hits_total`, `corr_cohort_components_ranked_total`
(= built), `corr_snapshot_digest{kind=content|material,result=computed|cached}`,
`corr_lifecycle_passes_total`, `corr_open_objects_epoch_peak`, plus last-cohort
gauges `corr_cohort_open_objects`, `corr_cohort_touched`. Derived ratios (touch
ratio, verdict-change ratio, eval-waste ratio) are computed by the report/harness
from these — never in the engine.

## 6. Tests (new file `src/correlation/test_cohort_touch_gate_p1.py`; mutant-style
like 163/168) — all REQUIRED
T1 memo-on vs memo-off over K∈{2,3,5,8} cohorts of a mixed fixture: identical
   snapshot lists on every field except `gap_hints`; `content_hash` identical on
   undirected fixtures (orientations empty both ways).
T2 MUTANT: any component containing a cohort key is NEVER served from memo
   (assert `memo.hits` unchanged, snapshot rebuilt, and that a fixture whose new
   signal changes the ranking sees the new ranking).
T3 a cohort whose new edge bridges two previously-separate components rebuilds
   the merged component (new key) and never returns either half from memo.
T4 memo dies with the epoch: cohort 1 of the next epoch has `hits == 0`.
T5 `cohort_keys=None` (golden/replay path) never consults the memo.
T6 digest cache: cached value == fresh recompute, byte-identical; `dc_replace`
   copies recompute; `to_object_row(hypotheses=blob)` row == `to_object_row()` row.
T7 directed fixture (existing `test_directed_object_replays_clean_via_embedded_orientation`
   as a base): an untouched directed component on cohort 2 keeps its embedded
   orientations and replays clean via `frozen_oracle`; assert the pre-P1 form
   (memo off) drops them — that pins the fixed defect and documents it.
T8 lifecycle hoist: 3-cohort epoch — merge/quiesce/cap outcomes identical to the
   per-cohort form (flag off) for a fixture with no mid-epoch continuation;
   `corr_lifecycle_passes_total` == 1 per epoch; failing cohort ⇒ 0 passes and
   `OPEN_OBJECTS` untouched.
T9 §3a isolation: memos are per tenant; a component key never crosses tenants;
   a two-tenant fixture with identical node keys produces two distinct snapshots.
T10 flags: gate off + cadence off ⇒ hit counters stay 0 and outputs equal today's.
Plus the whole existing suite green: `cd src/correlation && python3 -m pytest -q`
(golden_wire, golden_wire_all_lanes, replay, archive_corpus_replay_156, *166*,
*162*, *168*, *163*, *170*, *172*, storm_mode_2026_08_28, storm_priority,
bounded_object_paging, ch_epoch_inserts, persist_retry). CI parity: `ruff check .`,
`bandit -r main.py -ll`, `mypy main.py` (see `.github/workflows/correlation-ci.yml`).

## 7. Bench (evidence, not a gate)
`src/correlation/bench_cohort_touch_gate.py` (pattern:
`bench_bounded_object_paging.py`): synthetic 1-tenant window, ~5K components,
K=10 cohorts each touching 2 %; report per-cohort `run_window` + reconciliation
time gate on/off, digest computed/cached, and the touch ratio. Print JSON.

## 8. Out of scope (do NOT do here)
Cross-epoch memo (P2), evidence-tail append instead of full re-emit (P1 item 5
in the memo — separate change, it touches the paged emitter's dedup tokens),
Decision/Evidence split (P2), aggregation plane (P3), any `content_hash` /
blob-format change, any wall-clock/load-driven decision (memo §14/§21).

## 9. Acceptance (Fable verifies before commit; owner approves before deploy)
1. Full suite + CI parity green; new tests present and mutant-tested.
2. `git diff` shows `content_hash`/`material_hash`/`hypotheses_blob` BODIES
   unchanged (only caching wrappers / blob threading).
3. Bench shows memo hits ≈ (1 − touch ratio) × components on cohorts ≥2.
4. Then the owner's A/B on the identical 2.5K run (flags on vs off, one image):
   accounting still lossless, `corr_versions{outcome=persisted}` and final
   `corr_objects` verdicts/owners equal; cohorts/sec, pending curve, TTUR (P0
   script) compared. No magnitude is assumed — it is measured.

---

## 10. Implementation notes (builder, 2026-08-28) — deviations & findings
Implemented as specified. What differs from the letter of §2–§7, and why:

1. **`_epoch_lifecycle(epoch, loop_yield, seen=None)`** carries a third,
   optional `seen` parameter. §4 itself requires the `CORR_LIFECYCLE_EPOCH_CADENCE=0`
   form to pass `seen=seen_this_cycle`, so this is the signature that text implies;
   default `None` ⇒ `epoch.seen` (the union).
2. **`_make_loop_yield()`** — the cooperative loop-yield gate was a closure inside
   `_engine_cycle_inner`. It is now a module-level factory returning
   `(loop_yield, reset)`, unchanged in behaviour, so the epoch-cadence pass (which
   now runs OUTSIDE any cohort) keeps the identical bounded-grind protection.
   `_engine_cycle_inner` uses the factory too, so there is one implementation.
3. **Counters with the gate OFF.** The component counters are derived from the
   memo, so `CORR_COHORT_TOUCH_GATE=0` leaves `corr_cohort_components_total` /
   `_touched_total` / `_ranked_total` at 0 as well as the hit counter. The A/B's
   OFF arm reads work from `corr_versions` + timings, not from these.
4. **`corr_open_objects_epoch_peak` is a process-lifetime high-water gauge**
   (sampled at the end of every cohort, before any lifecycle pass), not a
   per-epoch value — that is the alertable form of "the cap overshot".
5. **The §3 optional fast path** (`reg["snapshot"] is snap`) was NOT added: the
   digest cache already makes the memo-hit reconciliation O(1), and the spec
   marks it not required.
6. **T7's premise held, but only partly observable — pinned as measured, not as
   assumed.** An untouched directed component re-materialized on cohort 2 with the
   memo OFF does lose its `orientations` (proven: blob loses the key, content_hash
   moves, `StoredObject.directed()` becomes None). But `replay()` reports **clean**
   for that object either way: `_diff` compares edge keys
   `(from,to,grounding_kind,grounding_ref)` and the from/to order is decided by
   onset order, never by the oracle — the oracle only moves `direction_basis` /
   `direction_conf`, which the drift report does not diff. The test therefore pins
   the real damage instead: the stored object asserts a directed edge
   (`onset_order+topo_updown`, conf 0.8) that a replay **of that same stored
   object** recomputes as `('none', 0.0)`. With the gate ON the orientations
   survive, the frozen oracle rehydrates, and the direction reproduces exactly.
   (Widening `_diff` to compare direction landed the same day as tracker 178: `replay.EDGE_COMPARISON_SCHEMA=2`, `test_replay_direction_178.py`; T7 now asserts the stale object reports `direction_drift`.)
7. **Tests**: T1–T10 as specified, plus three additions — `T2b` (a touched
   component with genuinely new evidence yields the new ranking), `T8b`/`T8c`
   (the failing-cohort case and the real drain-sweep call site, split out of T8),
   and a counters-exposure test for §5. All were mutant-verified: forcing
   `touched=False`, never serving a hit, keying the memo on one node key,
   restoring per-cohort lifecycle, a class-level digest cache and a corrupted
   `hypotheses=` pass-through each fail at least one test.
8. **Pre-existing mypy failure, fixed on request (follow-up)**: `mypy main.py`
   reported 2 errors in `engine.py`'s storm-aggregate branch
   (`window_start`/`window_end`: `datetime | None`) at HEAD `2abbf74d` too —
   verified against the unmodified tree, so NOT introduced here. Narrowed
   explicitly (`agg_lo`/`agg_hi` with a fallback to the folded nodes' own event
   times, never a cast that hides a None); the fallback is unreachable while the
   fold loop sets both bounds, so no emitted aggregate's bytes move. `mypy
   main.py` is now clean.
9. **`test_loop_blocking.py` hardened (follow-up)**: its offloaded-vs-inline
   ratio test measured a CACHED `content_hash` on whichever leg ran second
   (module-scoped fixture + P1 §3 per-instance cache), which shrank the inline
   leg's work from ~338 ms to ~147 ms and thinned the `worst_in > dur_in*0.5`
   margin into an intermittent failure. Both legs now call
   `_content_hash_uncached` so the comparison is cache-state-independent;
   `_snap_call`'s offload decision (what the test proves) is untouched, and
   `test_small_objects_keep_the_inline_path` still drives the real
   `content_hash` through it.
