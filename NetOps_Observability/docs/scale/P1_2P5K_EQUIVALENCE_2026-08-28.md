# P1 cohort-touch gate — OLD vs NEW 2.5K A/B semantic-equivalence audit
2026-08-28, read-only. SQL against `netops.corr_objects` with `tenant_scope='__all__'`. The brief's leg definitions reproduce exactly: OLD **14,472**, NEW **13,188** ids.

## 0. Conditions that qualify everything below
1. **The NEW leg was still running.** `netops-correlation-3` (started 19:11:03, flags at defaults ⇒ gate ON + cadence ON) was still emitting versions at 21:32. The id population is settled (0 cids first-seen after 21:20) but the lifecycle is not: at the 21:25 cutoff NEW reads closed 8,480 / open 4,330; uncapped at 21:27 it reads closed 10,460 / open 2,350. **Open-vs-closed comparison between the legs is invalid.** OLD is truncated too — last write 18:00:34 with 6,038 objects still open.
2. Only `netops-correlation-3` does work (`-4`: 0 merges, 0 cap firings).
3. States use `argMax(..., created_at)`, which reproduces the brief's OLD figures exactly (7,706/5,548/717/490/11). The brief's NEW figures were a read of a moving target; the same query now gives 7,475/4,016/1,005/378/314 — same 13,188 ids, **merged = 378** (brief said 375).

## 1. MERGES 11 → 378
### 1a. Every NEW merge satisfies the predicate (measured on all 378, not a sample)
Predicate = `find_merges` (engine.py:3011-3082): same tenant, `_windows_overlap`, entity Jaccard ≥ 0.4 **or** `_seam_bridged`. Entity sets from persisted `affected` (engine.py:1739-1769); survivor taken at its latest version ≤ the merge row's `created_at`.

| check | result |
|---|---|
| window overlap held | 378 / 378 |
| Jaccard ≥ 0.4 **and** window overlap | **378 / 378** |
| zero shared entities / no shared device | 0 / 0 |
| same `top_hypothesis` | 378 / 378 |
| Jaccard min / median / max | **0.400** / 0.429 / 0.727 |
| merge chains: max depth / cycles | 2 / **0** |

Minimum Jaccard sits exactly on the 0.4 threshold — the gate is applied, not bypassed. No merge crosses sites or unrelated entities. **378 is not a bug.**

### 1b. The brief's mechanism (a) is structurally FALSE
`_epoch_lifecycle` builds `survivors` from `seen` and `stale` from its complement (main.py:3692-3693). Per-cohort passes `seen = S_i`; the epoch form passes `seen = ∪S_i` (main.py:4106, 4113-4116, 4217-4218). Per-cohort pair space = `∪_i (S_i × (OPEN \ S_i))`; epoch pair space = `(∪S) × (OPEN \ ∪S)`. Any epoch pair `(s∈S_i, c∉∪S)` also has `c∉S_i`, so it already lay in cohort *i*'s pair space. **The epoch pass evaluates a SUBSET of the pairs the per-cohort passes evaluated** — "it sees the union so it finds more pairs" cannot be the cause.

### 1c. The surviving explanation (INFERENCE — not measured on OLD)
Within one pass, quiesce (main.py:3717-3730) and the 163 cap (main.py:3740-3762) run right after `find_merges` and **delete** from `OPEN_OBJECTS`; the cap's victims are ordered least-recently-**seen** (main.py:3742-3743) — exactly the stale merge candidates. Pre-P1 that ran after *every* cohort (up to `CORR_ENGINE_DRAIN_COHORTS=20` per epoch), so a candidate whose live survivor sat in cohort 7 was closed by cohorts 1-6 before cohort 7's merge pass could see it. Post-P1 the pass runs once, merge first, against the full survivor union. This is §4 delta 2 generalized from *continuation* to *merge*. Supporting measurement: NEW fired the cap **twice in the whole run** (force_closed_total = 4,962; 20:33:32 and 21:15:42). **Not proven** — the OLD container and its `/metrics` are gone, so its cap/quiesce firing counts are unrecoverable.

### 1d. OLD counterfactual — a weak, self-biased proxy
Pairs over each leg's *final* snapshots satisfying (Jaccard ≥ 0.4 + window overlap):

| leg | predicate pairs | never merged | (closed,open) | same hypothesis |
|---|---|---|---|---|
| OLD | 594 | 581 | 304 | 21 |
| NEW | 1,133 | 774 | 684 | 684 |

Under the full NEW-merge signature (+ same hypothesis + shared device): OLD 27 pairs, **21 never merged**; NEW 1,043, 684 never merged. **Caveat:** `find_merges` runs on *live* snapshots, and a final snapshot's window reflects when the object closed — OLD closed earlier, so the effect under test shrinks OLD's apparent overlap. 21 and 581 are loose proxies, not bounds.

### 1e. Verdict
**Correctness improvement, small magnitude.** +367 split-brain pairs are now tombstoned with a backlink (one incident) instead of one twin silently quiesce-closing as an independent one. No over-merge signal. 684 predicate-satisfying pairs still go un-merged in NEW, so the pass remains far from exhaustive.

## 2. STORM AGGREGATE — no regression; the scoping query lost it
`agg_cid = uuid5(SIGNAL_NS, "corrobj|<tenant>|storm-noise")` (engine.py:2910) is **tenant-constant, not per-run**. For `global` it is `bb1e46d6-5462-54dc-8465-777c707b9329`; both legs wrote that one id — 31 versions: OLD v1-15 (15:35:01 → 17:53:27), NEW v1-16 (19:55:14 → 20:57:52; counter reset by the container restart). NEW's aggregate is healthy: node_count 6,005 → … → 378 across v1-16, `storm_mode=true`, undetermined. Storm mode was declared in NEW (log at 19:28:51, 20:34:06).

Why NEW's leg set lacks it: the filter takes `min(window_start)` over rows with `created_at < 21:25`, which **includes the OLD rows for the same cid** ⇒ `min(window_start) = 15:22:18.258` ⇒ it falls in the OLD range only. Hence NEW's `max(node_count)` = 20 vs OLD's 7,595.

Two corrections to the brief: (i) OLD's aggregate does not *end* at 7,595 nodes — that is v7's peak; its final v15 has node_count 11, and that is the row in OLD's open/undetermined bucket. (ii) "NEW's largest undetermined object has 1 node" is the same artefact — set the aggregate aside and every undetermined object in *both* legs is a node_count-1 singleton. **Not a P1 regression.** §2 step 1 held: the below-floor/aggregate branch (engine.py:2731-2748) is unchanged and sits above the gate; the emit branch (engine.py:2882-2932) fired in both legs.

## 3. INCIDENT COUNT 14,472 → 13,188 (−1,284, −8.9 %)
- **Merges consume no ids inside a leg.** A merged object keeps its id and rows; it just ends `state='merged'`. The 367 extra merges contribute 0 to the −1,284.
- **The aggregate contributes exactly −1 id to NEW** — the §2 scoping artefact, not node absorption (the fold is the same branch in both legs).
- **What changed is how many distinct cids were minted.** NEW produced fewer, larger, less-churned objects: mean `node_count` 3.00 → **3.41**; mean versions/object 4.19 → **3.08**; total persisted versions 60,572 → **42,455** (−30 %).
- **Mechanism (INFERENCE):** the same attrition. `find_continuation` searches `OPEN_OBJECTS`; pre-P1 quiesce/cap deleted continuation targets mid-epoch, so a later cohort's re-keyed snapshot found nothing to adopt and minted a fresh cid. NEW logged **29,929** "continued under re-keyed window (identity adopted, no tombstone)" events; OLD's equivalent is unrecoverable, so **the −1,284 is not decomposed quantitatively.**
- **Undetermined 1,207 → 1,319 (+112) is UNEXPLAINED.** Every undetermined object in both legs is node_count 1 (OLD: 1,206 singletons + the aggregate's v15 at 11; NEW: 1,319). By storm marker: OLD 1,207 storm / 0 non-storm; NEW 1,292 / **27**. A related real difference: **100 % of OLD objects carry `storm_mode=true` (14,472/14,472) vs 93.5 % of NEW (12,327/13,188)** — 861 NEW objects lived at least partly outside a declared storm because the faster engine held the buffer below the threshold. That is a change in run *conditions caused by* P1; it confounds a strict equivalence claim but does not by itself account for +112.

## 4. FINAL-VERDICT EQUIVALENCE SAMPLE
Device names carry a per-run prefix (`mlx-08281519gjez-NNNNN` OLD vs `mlx-08281911zaz6-NNNNN` NEW); the numeric suffix is the stable device id, so names were normalized by stripping the run token first.

**Primary — key = (normalized device set, `top_hypothesis`), n = 200**, drawn uniformly (seed 11) from the 1,554 keys 1:1 in both legs. `top_hypothesis` is *in the key*, so its 100 % is definitional; the other four are free:

| field | agreement |
|---|---|
| `hypotheses.ranking.hypotheses[0].verdict.owner` | **200/200 = 100.0 %** |
| `verdict_tier` | **200/200 = 100.0 %** |
| `top_confidence` | **200/200 = 100.0 %** |
| `node_count` | 193/200 = **96.5 %** |
| all four together | 193/200 = 96.5 % |

The 7 `node_count` disagreements are small and two-directional (old,new): (4,3) (5,4) (3,9) (4,3) (5,4) (5,4) (7,9) — consistent with different truncation points, not a ranking difference.

**Supplementary, non-circular — key = device set only** (only 39 keys are 1:1): `top_hypothesis` 37/39 (94.9 %), owner 37/39, `verdict_tier` **39/39**, `top_confidence` 37/39, `node_count` 37/39. Both hypothesis disagreements have the same shape — OLD `sig.ent.fabric.spine-leaf-path-degradation` → NEW `sig.ent.middle-mile.lastmile-circuit-flap` — and in both the NEW object is larger (3→8, 3→9 nodes): NEW correlated more evidence into one object and re-ranked it — the intended direction of the merge/continuation change, not verdict drift.

Population mix moves (`local-link-fault` 4,685 → 5,919; `ospf-adjacency-flap` 1,554 → 534; `bgp-peer-flap` 1,118 → 470); owner mix is stable (netops ~70 % / carrier ~30 % both legs). With both legs truncated at different points this is **not** safe to read as a semantic shift.

## 5. Bottom line + uncertainties
- **No correctness defect found.** 378/378 merges satisfy the predicate; the storm aggregate is intact in both legs; owner/tier/confidence agree 200/200 on the sample.
- **The merge rise is a behaviour change in the correct direction**; the brief's mechanism (a) is provably not the cause; the cause is candidate-attrition ordering (§1c), which could not be measured on the OLD leg.
- **Blocking for a §9.4 "equal verdicts" acceptance claim:** the NEW leg was still running. Re-run every open/closed and per-hypothesis comparison after it converges; id and merge counts are already settled and can stand.
- **Second uncertainty:** storm mode was declared for 100 % of OLD objects but 93.5 % of NEW ones — the legs did not run under identical degradation state, so this A/B is not a clean test of the gate alone.
- **Third:** entity sets came from `affected`, a projection of the node set (drops unmapped types, adds app_impact apps), so Jaccard can differ slightly from `_entity_ids`. Every measured value cleared 0.4 with the minimum landing exactly on the threshold, which argues the projection is faithful here.

Working files: `new_merged.tsv`, `old_merged.tsv`, `{old,new}_final.tsv`, `{old,new}_aff.tsv`, `an1.py`–`an4.py`, `legs.sql`, `q.sh` in this scratchpad.
