# Tracker 167 — the provably-inapplicable template fast path

**Date:** 2026-08-21 · **Status:** offline PASS. Live re-run pending.
**Scope note:** 167 was rescoped by the post-168 live run from *per-pair candidate
cost* to *per-object template cost*. This is the rescoped work.

---

## Why the obvious design is wrong

The obvious optimisation is "index kinds → templates, score only the candidates."
**That would have changed RCA output.**

`rank()` does not discard low scorers. It uses the full score list three times:

* `evidence_missing = sorted(scores, key=-coverage)[:2]` — the "what would
  confirm this" field, which is **persisted and hashed**;
* forced competitors are pulled back from `scores[TOP_K:]`;
* contradicted look-alikes — the "ruled out because…" rows — likewise.

A zero-coverage template is therefore *load-bearing output*, not dead weight.
Omitting it changes what an operator sees on every undetermined object.

## What was built instead

Nothing is skipped. A template that **cannot** match is scored **analytically**,
because its result is fully determined:

```
satisfied ()   missing = every required clause   coverage 0.0
no contradictions (a discriminator needs a matching kind too)
no notes (the role note is only emitted on a hit)
confidence 0.0   gate = assess((), required_modalities)
```

What gets skipped is the expensive part — `_satisfying` over every clause × every
signal — not the template. `score_template` remains the sole semantic authority
for anything that could match.

### Soundness

The index keys on `kind` alone. `entity_type` and `min_deviation` only make a
clause **stricter**, so kind-intersection is a sound **superset**: anything that
survives the filter falls through to the real scorer.

    false positive in the filter = wasted CPU
    false negative in the filter = changed RCA semantics

so the design optimises for **zero false negatives** and accepts false positives.

### The applicability matrix (Phase 11)

100 enabled templates; 1–4 clauses each (mode 3); 197 distinct kinds across
`requires`; 57 carry discriminators; 93 declare `required_modalities`; 2 declare
a causal chain. Everything that can make a template react:

| Source | Indexed | Why it must be |
|---|---|---|
| required clauses (`Clause.kinds()`, alternation-aware) | ✅ | the primary match path |
| **optional** clauses | ✅ | they grant a coverage **bonus** |
| **discriminator** `absent` kinds | ✅ | they produce a visible *contradicted* row |
| **causal-chain** witnesses | ✅ | descriptive rungs on the persisted object |
| `entity_type` / `min_deviation` / `role` | ❌ by design | strictly narrowing — ignoring them only widens the superset |
| **`active_verification_result` corroboration** | ✅ | matches on `attrs.corroborates_kinds`, **not** on the signal's own kind — a kind-only view of the evidence pool would index the witness away. This is the one true false-negative trap and it is closed in `evidence_kinds()`. |
| `active_verification_healthy` refutation | ❌ needed | only refutes an **already-satisfied** clause |

### Lifecycle

`_catalog_kind_index` is `lru_cache`d on the `Catalog` value (the model is frozen
and hashable), so a reload produces a new key and the old entry ages out — there
is no stale-index path. Built once: **2.36 ms, 70.7 KiB**.

---

## Equivalence (Phases 14–15)

The exhaustive scan is retained verbatim as the oracle. `test_template_index_167.py`
(25 tests) requires **exact** `HypothesisScore` equality field-by-field, plus
`RankingResult.to_dict()` equality including `evidence_missing`, `top_hypothesis`,
`verdict_tier` and hypothesis ordering.

Coverage includes: every template against nothing; **every template against its
own first declared kind**; multi-kind objects; objects with unrelated noise; every
alternation token; optional clauses; discriminator kinds; causal-chain witnesses;
verification corroboration and refutation; debug-only probes; the empty pool.

The oracle earned its keep immediately: the first implementation dropped five
`Template` metadata fields (`deployment_scope`, `operator_phrase`,
`manager_phrase`, `blast_radius`, `false_positives`) from the analytic score. The
suite caught it on the first run.

**End-to-end on the benchmark: 1,111 objects, identical `correlation_id` and
`content_hash` for every one. 0 semantic mismatches.**

### Mutation results (Phase 16)

Mutating the **shipped** source; each must turn the suite red:

| Mutant | Result |
|---|---|
| A — forget optional clause kinds | **killed** (16 failed) |
| B — forget discriminator kinds | **killed** (18 failed) |
| F — forget causal-chain witnesses | **killed** (15 failed) |
| V — forget verification corroboration | **killed** |
| D — intersection instead of union (`<=` not `&`) | **killed** |
| Analytic score: drop `deployment_scope` | **killed** (19 failed) |
| Analytic score: drop `false_positives` | **killed** (19 failed) |
| Analytic score: re-sort `missing` | **killed** (18 failed) |
| Analytic score: include optional in `missing` | **killed** (19 failed) |
| Analytic score: coverage 0.0 → 0.01 | **killed** (19 failed) |
| H — drop the DEBUG_ONLY exclusion | **survives — correctly** |
| M6 — constant `_empty_gate` key | **survives — correctly** |

The two survivors are reported rather than forced:

* **H** only *widens* the candidate set. A debug-only signal that slips into the
  kind view sends the template to `score_template`, which filters it in
  `_satisfying` and returns the same zero. A benign false positive, which the
  design explicitly permits.
* **M6**: `assess([], m)` returns an identical verdict for all **11** distinct
  modality sets in the catalog, so the memo key is defensive, not load-bearing.
  Verified and **pinned by a test**, so if `assess` ever starts distinguishing
  them the assumption goes red instead of silently returning a wrong gate.

---

## Performance (Phase 17)

Same shape that identified the bottleneck: 6,000 signals → **1,111 objects**,
100-template catalog, 5,000-node cohort, cProfile.

| Metric | Exhaustive | Indexed | Delta |
|---|---:|---:|---:|
| objects | 1,111 | 1,111 | 0 |
| **`score_template` calls** | **111,100** | **24,442** | **−78.0 %** |
| `verdicts.coverage` calls | 111,100 | 24,451 | −78.0 % |
| `catalog.kinds` calls | 2,064,000 | 486,344 | −76.4 % |
| **`score_template` cumulative** | **20.17 s** | **7.19 s** | **−64.3 %** |
| `build_edges` cumulative | 4.93 s | 5.70 s | +0.76 s (run-to-run noise; unchanged code) |
| **`run_window` wall** | **33.81 s** | **23.42 s** | **−30.8 %** |
| semantic mismatches | — | — | **0** |

**Selectivity: 22 candidate templates per object of 100** on this workload. Index
build 2.36 ms, 70.7 KiB, once per catalog.

Against Phase 18's stop condition — "if the candidate count remains close to
100/object, report that signal-kind selectivity is insufficient" — 22/100 clears
it comfortably.

**Honest caveat on generality.** This workload is single-kind
(`link_state_change`), which is the friendly case for a kind index. A
multi-modality estate will select more templates per object and see a smaller
win. 22 % is the selectivity of the qualification workload, not a platform
constant, and the live re-run is what will say whether it holds under a realistic
mix.

Suite: **1434 passed, 9 skipped** (1410 before), ruff / mypy / bandit clean.
