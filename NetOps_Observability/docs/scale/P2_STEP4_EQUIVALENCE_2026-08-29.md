# P2 step 4+4a — 2.5K A/B semantic-equivalence audit (LEG A c19dcc7d vs LEG B 87973a36)
2026-08-29, read-only. `netops.corr_objects`, `tenant_scope='__all__'`; storm-aggregate cid
`bb1e46d6…` excluded automatically (`min(window_start)` = 2026-08-28 15:22, outside both scopes).
Device names normalized by stripping the run token (`mlx-<runid>-NNNNN` → `dNNNNN`); entity sets from
persisted `affected` (devices ∪ interfaces), per `P1_2P5K_EQUIVALENCE_2026-08-28.md`.
Leg definitions reproduce **exactly**: A 16,172 / 53,002; B 11,664 / 44,286.

## 0. Conditions
- Only `netops-correlation-3` does work (`-4`: 0 cohorts, 0 merges) — same as P1.
- **Leg A's container is gone** (`-3` started 06:50:58, B only): A's `/metrics` and logs are
  unrecoverable, so every A-side lifecycle counter below is inference, never measurement.
- Both legs are settled in id population but truncated in lifecycle (B 2,312 open, A 2,440), so
  open-vs-closed is not compared.

## 1. Where the 4,508 incidents went

### (c) Scope leakage — **FALSIFIED, exactly zero**
Crosstab of persist window × scope window over `legs AS (SELECT correlation_id, min(window_start) ws, min(created_at) fca FROM netops.corr_objects GROUP BY correlation_id)`:

| persist window (`min(created_at)`) | scope A | scope B | other |
|---|---|---|---|
| A [04:13, 06:30) | **16,172** | 0 | 0 |
| B [06:55, 09:30) | 0 | **11,664** | 0 |

No incident persisted in B's window has a `window_start` outside B's scope. Nothing hid.

### (b) Merge / cap / quiesce absorbing ids — **STRUCTURALLY IMPOSSIBLE, contributes 0**
Merge keeps the id (`state='merged'` + `merged_into`; main.py:4392-4405); quiesce/cap keep it too
(terminal `state='closed'`). **Nothing destroys a correlation_id once minted**, so A's 11 merges and
B's 0 contribute **0** to the −4,508.
Force-close pushes the count the *other* way (a deleted OPEN_OBJECTS entry cannot be adopted by
`find_continuation`, so the next cohort mints a fresh cid): B fired the 163 cap 4× for
`force_closed_total = 9,468`. Also: no incident in either leg is closed at v1, and every incident
has ≥2 versions in both legs — there is no "born-closed" population.

### (a) Continuation adoption — **CONFIRMED, and it over-explains the delta**
| | LEG A | LEG B | Δ |
|---|---|---|---|
| incidents | 16,172 | 11,664 | −4,508 (−27.9 %) |
| **total raw signals covered** `Σ max(signal_count)` | **48,627** | **54,053** | **+5,426 (+11.2 %)** |
| Σ final `signal_count` | 48,255 | 49,505 | +1,250 |
| mean max `signal_count` / incident | 3.007 | 4.634 | +54 % |
| mean max `node_count` | 2.623 | 4.072 | +55 % |
| versions / incident | 3.277 | 3.797 | +16 % |
| lifespan p90 (s) | 3,892 | 2,954 | −24 % |

**B covers 11 % MORE raw signal in 28 % FEWER objects.** The delta is concentrated in singletons:

| bucket | A count | A signals | B count | B signals | mean sc A→B |
|---|---|---|---|---|---|
| max `signal_count` = 1 | 9,831 | 9,831 | 5,934 | 5,934 | 1 → 1 |
| max `signal_count` > 1 | 6,341 | 38,796 | 5,730 | 48,119 | 6.12 → **8.40** |

−3,897 of the −4,508 (**86 %**) is singletons that no longer get minted; the remaining −611
multi-signal objects carry +9,323 more signal between them. Supporting: B logged **16,632**
"continued under re-keyed window (identity adopted, no tombstone)" events;
`corr_cohort_components_touched_total = 17,269 / 144,090`. A's equivalent is unrecoverable, so the
decomposition is quantified on B's side only — **the mechanism is inferred, the outcome is measured.**

## 2. Device coverage — **complete in both legs, no device lost**
Devices = `affected.devices` ∪ the device half of `affected.interfaces` (some objects carry only interfaces).

| | LEG A | LEG B |
|---|---|---|
| distinct devices with ≥1 incident | **2,500 / 2,500** | **2,500 / 2,500** |
| devices in A only / B only | **0** | **0** |
| incidents per device mean / p50 / max | 6.52 / 5 / 15 | 4.81 / 4 / 11 |
| Σ max `signal_count` | 48,627 | 54,053 |
| mean signal share per device | 19.5 | 21.6 |

Per-device delta (B−A): 1,431 devices fewer, 648 more, 421 equal; range −9…+3. Only **12 / 2,500**
devices see their covered-signal share fall below half of A's. **The 4,508 is consolidation, not
blind spots.**

## 3. Matched-incident equivalence
### Primary — key = (normalized device set, `top_hypothesis`), n = 200 of 1,058 1:1 keys (seed 11)
`top_hypothesis` is in the key, so its 100 % is definitional.

| field | agreement | mismatches (A→B) |
|---|---|---|
| `hypotheses.ranking.hypotheses[0].verdict.owner` | **200/200 = 100 %** | — |
| `verdict_tier` | **200/200 = 100 %** | — |
| `top_confidence` | **200/200 = 100 %** | — |
| `node_count` | 143/200 = **71.5 %** | (1→2) 20, (1→3) 18, (7→6) 6, (9→7) 5, (8→6) 3, (8→7) 2, (9→6) 2, (3→9) 1 |

Bi-directional: 39 of the 57 disagreements have B **larger** (more nodes folded in), 18 smaller
(truncation). P1's node_count agreement was 96.5 % — this is the one field that moved materially.

### Supplementary, non-circular — key = device set only, all 59 1:1 keys
| field | agreement | mismatches (A→B) |
|---|---|---|
| `verdict_tier` | **59/59 = 100 %** | — |
| `top_hypothesis` | 48/59 = 81.4 % | spine-leaf-path-degradation→lastmile-circuit-flap ×9, +2 stp/lastmile swaps |
| `owner` | 48/59 = 81.4 % | netops→carrier ×10, carrier→netops ×1 |
| `top_confidence` | 50/59 = 84.7 % | 0.55→1.0 ×9 |
| `node_count` | 17/59 = 28.8 % | (9→7) 13, (3→6) 9, (7→6) 7, (8→6) 4, (9→6) 4, (8→7) 2, (9→2) 1, (2→6) 1 |

The 9 owner/confidence/hypothesis flips are ONE shape, the same one P1 recorded:
`spine-leaf-path-degradation` (conf 0.55, netops) re-ranks to `lastmile-circuit-flap` (conf 1.0,
carrier) once more evidence lands. **Population-level:** `spine-leaf-path-degradation` is the
final hypothesis of 502 A incidents and **0 B incidents** — yet it appears on 1,078 B *versions*
(A: 1,053). It is never absent; it is always re-ranked away by the final version. INFERENCE: this
is the intended direction of the adoption change, not a lost hypothesis class — but a whole final
class going to zero deserves a named check before acceptance.

## 4. Merge regression — **B's 0 merges is a REAL 4a REGRESSION, proven from the live gauges**
`_epoch_lifecycle` (main.py:4382-4384) builds
`survivors = OPEN_OBJECTS ∩ merge_seen`, `stale_snaps = OPEN_OBJECTS \ merge_seen`, and
`_lifecycle_merge_seen` (main.py:4306-4329) sets `merge_seen = epoch.seen ∪ (last K cohorts)` with
`K = CORR_LIFECYCLE_COHORT_WINDOW = CORR_ENGINE_DRAIN_COHORTS = 20`. **Widening `merge_seen`
widens survivors and, by the same set difference, empties `stale_snaps`.**

Live `/metrics` on `netops-correlation-3` (the B run, port 8443 mTLS):
```
corr_lifecycle_seen_window_cohorts 20      corr_engine_cohorts_total 33
corr_lifecycle_seen_window_ids     2312    corr_open_objects        2312
corr_lifecycle_passes_total        43      corr_engine_epochs_total 43
```
`seen_window_ids == open_objects == 2312`: **every open object was a survivor, the stale list was
empty, `find_merges` was called with `candidates = []` and could not return a pair.** Not "no
predicate-satisfying pairs" — *the pass was handed nothing to test*. B's run has 33 cohorts total
and K = 20, so the window covers ~60 % of the entire run's cohorts; anything older than the window
has already been closed by quiesce (900 s) or the 163 cap, so the stale set is **systematically**
empty. Step 4a's cure for "merges 378 → 11" overshot into "merges → 0".

**Counterfactual pair counts** (final snapshots — the same self-biased proxy the P1 report used;
`find_merges` runs on *live* snapshots, so these are loose proxies, not bounds):

| leg | pairs sharing an entity | Jaccard ≥ 0.4 | + window overlap | + same hypothesis + shared device | actually merged |
|---|---|---|---|---|---|
| A | 17,922 | 4,303 | **1,587** | **607** | 11 |
| B | 11,462 | 643 | **475** | **272** | **0** |

B has 3.3× fewer split-brain pairs than A (adoption already folded most), but **272 full-signature
pairs stand un-merged and the pass structurally cannot see them.** A leaves 596/607 un-merged too —
the pass is far from exhaustive in *both* legs; the regression is that B's ceiling is now zero.

**Fix direction (not implemented):** widen the *survivor* side only — keep
`stale_snaps = OPEN_OBJECTS \ epoch.seen` (the epoch's own set, as quiesce and the cap already do)
and use the K-cohort union for `survivors` alone. Today both sides derive from one set.

## 5. Bottom line
1. **−4,508 = fewer objects minted, not lost data.** Zero scope leakage, zero devices lost, +11.2 %
   raw signal covered, 86 % of the drop is singletons. Correct direction.
2. **Verdict semantics hold** where the device set and hypothesis agree: owner / tier / confidence
   200/200. `node_count` fell to 71.5 % (P1: 96.5 %), two-directional.
3. **B's 0 merges is a code regression in 4a**, proven by `seen_window_ids == open_objects`: the
   stale candidate list is empty by construction. Merges consume no ids, so this does **not**
   explain the −4,508 — it is an independent correctness defect.
4. **Confounders:** A's container/metrics are gone; B's rank memo ran at 7.2 % hit rate with
   `rank_memo_bytes` pinned at the 96 MiB cap (4.7 GB evicted) — a performance, not semantic,
   confound, but this is not a clean single-variable A/B.
