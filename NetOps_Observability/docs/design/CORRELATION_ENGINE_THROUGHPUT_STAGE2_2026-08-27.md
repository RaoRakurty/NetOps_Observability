# Correlation engine — Stage 2 (throughput) design (2026-08-27)

Fable design. Raises engine throughput toward the ~1,000 eps/core target
(`CORRELATION_THROUGHPUT_TARGET`) so a storm is ABSORBED, not merely survived
(Stage 1 = survived). Built on the profiling: the hot path is `build_edges`
(engine.py:1127) at ~35µs/candidate-pair.

## The two cost shapes (measured)
- **Diffuse: LINEAR** — bounded device groups; ~108s at ~25k nodes. Scales but
  doesn't explode. Managed by per-pair micro-opt (Lever 3) if needed.
- **Concentrated: QUADRATIC** — the danger. `_emit_candidates` meshes a **rank-7
  shared-token group** ALL-PAIRS: a token shared by N nodes → O(N²) candidate
  pairs (code-measured: "48 groups of 1,000 nodes → ~25.1M pairs"). A storm that
  makes one giant shared-token group (a common interface name, a shared
  identifier) explodes here. THIS is what must be killed.

## Lever 1 (PRIMARY) — cap rank-7 shared-token group fan-out ⚠️ SEMANTIC CHANGE
A token shared by more than K nodes is a **non-specific HUB**, not a correlation
signal — exactly tracker #168's ratified concern (a bare interface name must not
weld unrelated devices). Rank-7 is the WEAKEST tier (candidate only, w=0.5,
never authoritative). **Excluding hub-token groups (size > K) from candidate
generation kills the O(N²) AND improves correlation quality** (drops spurious
hub-welding noise).

**This CHANGES correlation output** (fewer rank-7 candidate edges for hub tokens)
— so it is NOT a transparent optimization; it is a #168-class **quality decision**
that must be owner-visible and its tests updated to the new (better) reference,
not silently. Design:
- A token whose group size > `CORR_TOKEN_HUB_CAP` (proposed default: conservative,
  e.g. 64 or a small fraction of the window — tuned so only genuine hubs drop and
  real small-group correlations are untouched) does not emit all-pairs candidates.
- Deterministic (size is a pure function of the window). Higher-rank groundings
  (ranks 1–6: real identity/seam/adjacency/path) are UNAFFECTED — only the weak
  rank-7 token mesh is capped, so authoritative correlations never change.
- **Test:** a hub token (>K nodes) drops its rank-7 mesh; every non-hub group and
  every rank 1–6 edge is byte-identical to today. Update `test_engine_complexity`'s
  brute-force reference to the capped semantics + add a hub-noise regression.

## Lever 2 (SECONDARY, RESULTS-PRESERVING) — index `find_merges`
`find_merges` (engine.py:2335) is O(survivors × stale) with no index — a second
storm cost. Apply the tracker-162 `ContinuationIndex` pattern: index stale snaps
by entity so each survivor probes only plausible merge candidates. **Same merges,
sub-quadratic.** Results byte-identical (pin against the brute-force cross-product).

## Lever 3 (TERTIARY) — per-pair grounding micro-opt, only if profiling shows ROI
`_grounded` is already precomputed (per-node views, set intersections). Profile
first; only optimize if there's real headroom. Results-preserving.

## Correctness constraints (bread-and-butter)
- **Determinism / replay preserved** for Levers 2 & 3 (byte-identical output).
- **Lever 1 is a DELIBERATE semantic change** — authoritative (rank 1–6)
  correlations untouched; only the weak rank-7 hub-token mesh drops. Owner-visible,
  tests updated to the new reference, framed as a #168-class quality win.
- Tenant isolation, purity (no IO/clock/dict-order) unchanged.

## Test plan
1. Lever 1: hub-token cap drops the O(N²) mesh; non-hub + rank 1–6 byte-identical;
   concentrated-storm candidate count drops from O(N²) to O(N·K).
2. Lever 2: find_merges index yields byte-identical merges vs brute force.
3. Throughput: measured build_edges time + eps/core at the concentrated storm
   shape before/after (target: no quadratic; toward ~1,000 eps/core).
4. Full correlation pytest suite + golden-wire/replay/166/162/168 green (with
   test_engine_complexity's reference updated for Lever 1).

## Sequencing (Opus builds; Fable verifies)
- **Lever 2 first** (results-preserving, safe) → verify byte-identical.
- **Lever 1** (semantic) — build with the updated reference + hub-noise
  regression; FLAGGED to owner as a correlation-quality change.
- **Lever 3** only if profiling after 1+2 shows the linear per-pair cost still
  blocks the target.
- Then the deferred **formal storm-gate re-run** (the faster engine settles the
  stack to idle, unblocking the clean baseline).

---

## Lever 3 — TRUE cause (profiled 2026-08-28): C `json.dumps` GIL-hold in object hashing

Profiling REFUTED the finding/insert hypothesis (single-row `netops.findings`
writes are ~12µs, always yield). The real stall: **`ObjectSnapshot.content_hash()`
(engine.py:1868)** and the object serializers (`material_hash`, `to_object_row`,
`to_evidence_rows`, `to_typed_edge_rows`) — all `json.dumps`-heavy over large
storm objects. Measured: 300n/45k-edge object → content_hash 1.54s; 600n/180k →
6.2s. Scales with EDGE count.

**The GIL subtlety:** these are OFFLOADED, but the C `json.dumps`/`iterencode`
holds the GIL through long C stretches, so `run_in_executor` frees the loop
thread yet the heartbeat coroutine still starves — measured heartbeat gap = 20–25%
of the call (6.5s call → 1.7s gap; several concurrent → the 15.7s worst-case).
Pure-Python offload releases the GIL at the switch interval (1% gap); the C json
encoder does NOT. This is what the 2026-08-27 CORRECTION got half-right.

### Fix (Opus measures & picks; determinism is NON-NEGOTIABLE)
`content_hash`/`material_hash` are the **replay pin + damping detector** — output
MUST stay BYTE-IDENTICAL to `json.dumps(..., separators=(",",":"), sort_keys=True)`
or (a) replay drifts and (b) every open object re-versions once on deploy.
- **Option A — chunked in-process serialization:** serialize the big `edges`/
  `signals` lists element-by-element (each element via C `json.dumps`, fast) in a
  PYTHON loop that yields the GIL periodically, feeding `hashlib.update()` per
  chunk. Byte-identical (match json.dumps' `[e1,e2,…]` separators/brackets exactly).
  No pickle. Delicate byte-exact boundary reproduction.
- **Option B — ProcessPool for the hash:** compute in a subprocess (own GIL → main
  heartbeat free); RESULT is a tiny hash string (no big-object unpickle, unlike the
  refuted run_window ProcessPool). Trivially byte-identical (same json.dumps in the
  child). Cost = INPUT pickle of the large object — MEASURE it vs the serialize cost.
- Pin against the golden-wire/replay/damping suite; a known object's content_hash
  MUST equal its pre-change value.
