# A COMPACT cached form for the level-1 rank memo — measurement + prototype

**2026-08-29 · worktree pinned to `c9db1839` · patch `rankmemo_compact.patch` (verified to apply and pass on `8e55a1cf` too)**

## 0. Answer

**Yes — and by more than the 5 KiB/entry the question asked for.** The memo can
hold its whole 20,117-key population in **~24 MiB**, not 96 MiB, at **1,191
bytes per entry measured in situ** (against 26,711 B today — **22.4x**), with
every output byte unchanged (`test_golden_wire.py` + the existing T1/T4
equality/blob oracles + 8 new `C*` tests all green, in both the new and the
kill-switch mode).

The design is **not** the one the question sketched. The decisive measurement is
that **none of the 24.5 KiB is catalog-derivable text** — it is already free.
See §1.

---

## 1. (a) Where the ~27 KiB actually goes

Per-field attribution over **800 real rank-key-distinct storm-shaped
`RankingResult`s** captured from a drain sweep
(`bench_memflat_p2._capture_evidence`, 400 dev / 3k sig / 3 epochs, storm on;
2,446 distinct keys total, **11.33 hypotheses per result** — TOP_K=4 plus forced
competitors plus contradicted look-alikes). Charged with the *same* rules
`estimate_result_bytes` uses (id-`seen`, catalog-owned = 0, per-instance
`__dict__` counted). Mean **22,398 B/entry**; the 1,200-result superset reads
24,561 B/entry estimated and **25,042 B/entry by `tracemalloc`** (0.98x — the
estimator is honest).

| field | B/entry | share |
|---|---:|---:|
| `HypothesisScore` object + `__dict__` (x11.33) | 3,059 | 13.7 % |
| `EvidenceCoverage.observer_ids` frozenset | 2,417 | 10.8 % |
| `.modality_classes` frozenset | 2,360 | 10.5 % |
| `.trusted_modalities` frozenset | 2,360 | 10.5 % |
| `.low_authority_probe_scopes` frozenset | 2,360 | 10.5 % |
| `EvidenceCoverage` object + `__dict__` | 2,097 | 9.4 % |
| `Verdict.reasons` (generated strings) | 1,886 | 8.4 % |
| `Verdict` object + `__dict__` | 1,660 | 7.4 % |
| `HypothesisScore.missing` | 483 | 2.2 % |
| `RankingResult.evidence_missing` | 477 | 2.1 % |
| `causal_chain` | 437 | 2.0 % |
| `EvidenceCoverage.fate_groups` | 437 | 2.0 % |
| `contradictions` / `forced_competitors` | 352 each | 3.1 % |
| `satisfied` | 268 | 1.2 % |
| `coverage`, `confidence_rank`, `contradicted`, `supporting_hit` | 262 each | 4.7 % |
| `RankingResult` object + `hypotheses` tuple + `catalog_version` | 348 | 1.6 % |
| **`title`, `owner`, `first_steps`, `seams`, `deployment_scope`, `operator_phrase`, `manager_phrase`, `blast_radius`, `false_positives`, `template_id`, `notes`, `verdict_tier`, `independent_pair`, `excluded_debug`** | **0** | **0 %** |

### The two findings that decide the design

1. **Catalog-derived content already costs zero marginal bytes.** `score_template`
   copies the template's strings and tuples **by reference** (`tuple(t.seams)` on
   a tuple *is* that tuple; `first_steps=template.verdict.first_steps` is the
   template's own object), and the estimator charges catalog-owned ids 0 — a rule
   the `tracemalloc` reference independently confirms at 0.98x. So a
   "delta vs catalog" *object* form removes nothing that is being paid for.
2. **The cost is the object count and CPython's fixed set header.** ~34 dataclass
   instances per entry (11.3 x `HypothesisScore` + `Verdict` +
   `EvidenceCoverage`), each carrying a per-instance `__dict__` — 6,816 B/entry
   (30 %) of pure object overhead — plus **four frozensets per hypothesis at a
   flat 216 B each** whether they hold 0 or 4 members: 9,497 B/entry (42 %).
   `frozenset()` is *not* interned in CPython, so an empty one is a fresh 216 B.

**Conclusion: the only way to delete an object's overhead is to stop having the
object.** That is what makes serialization the answer — and it is *there* that
the delta-vs-catalog rule finally pays, because in serialized bytes the catalog
text is 62 % of a naive dump (11,317 B whole-object pickle vs 2,924 B delta
pickle).

---

## 2. (b), (c) The candidates, measured

Same capture, **n = 1,200**. Bytes include the `bytes` object header. Encode and
decode are best-of-3 warm passes. `rank()` on the same corpus is **2.47 ms**.
Every row round-trips to an object that compares `==` to the original for all
1,200 results.

| candidate | B/entry | encode | decode | equal |
|---|---:|---:|---:|---|
| **object form (today)** | **24,561** (25,042 by tracemalloc) | — | — | — |
| (b) delta value-tuple, *kept as objects* | 10,405 est / **4,133 tracemalloc** | 0.051 ms | 0.117 ms | 1200/1200 |
| (c) `pickle`(whole object) | 11,317 | 0.112 ms | 0.115 ms | 1200/1200 |
| (c) `pickle`(whole object) + zlib-1 | 4,592 | 0.375 ms | 0.195 ms | 1200/1200 |
| (b+c) `marshal`(delta) | 3,414 | 0.068 ms | 0.133 ms | 1200/1200 |
| **(b+c) `marshal`(delta) + zlib-1 — CHOSEN** | **918** | **0.130 ms** | **0.151 ms** | 1200/1200 |
| (b+c) `marshal`(delta) + zlib-3 | 894 | 0.129 ms | 0.161 ms | 1200/1200 |
| (b+c) `pickle`(delta) + zlib-1 | 861 | 0.124 ms | 0.147 ms | 1200/1200 |

Notes:

* **zstd is not available in this image** — no `zstandard`, no 3.14
  `compression.zstd`. zlib level 1 is the measured compressor; level 3 buys
  2.5 % of bytes for 7 % of decode and is not taken.
* **`marshal` over `pickle`** for a 6 % byte penalty: marshal can only build the
  builtin types this codec writes — it cannot *name* a class, so it cannot
  construct one (CLAUDE.md §8, no unsafe deserialization). Its format is
  interpreter-version-locked, which is irrelevant to an in-process cache that
  never outlives the interpreter that wrote it.
* (b) alone (delta kept as a Python value-tuple, no serialization) is a real
  6.1x by `tracemalloc` — but it is 4.5x *worse* than (b+c) and still pays the
  container-per-field tax the attribution identified.

---

## 3. (d) Sharing / interning

Over the same 1,200 entries: **13,589 `HypothesisScore` instances, 8,742 distinct
object identities, only 4,094 distinct VALUES**; 1,735 distinct `Verdict` values.
A process-wide value-interning table (frozen dataclasses are hashable and
weak-referenceable, so a `WeakValueDictionary` would self-evict with the LRU):

| | B/entry | put cost | decode cost |
|---|---:|---:|---:|
| object form, aggregate marginal | 24,458 | — | 0 |
| **interned, aggregate marginal** | **3,794 (6.4x)** | +0.23 ms | **0** |

Distinct-value growth: 725 @ 100 entries → 1,251 @ 200 → 2,093 @ 400 →
3,801 @ 800 → 4,094 @ 1,200.

**Not taken**, but a genuine fallback: 6.4x against 22x, and its ratio at 20,000
entries is an *extrapolation* from a 1,200-entry curve, where the codec's
1.2 KiB is a per-entry constant. Its one advantage is that it keeps the
zero-cost hit and keeps sharing with the live working set. If decode-on-hit ever
proves too expensive, this is the next lever — and the two compose.

---

## 4. In-situ A/B (the number that matters)

`bench_rankmemo_insitu.py`, the same drain sweep, one process per arm, memo
wired into `main.RANK_MEMO`:

| | compact (new default) | object (`CORR_RANK_MEMO_COMPACT=0`) |
|---|---:|---:|
| entries | 2,446 | 2,446 |
| hits / misses | **499 / 2,446** | **499 / 2,446** |
| evicted | 0 | 0 |
| `corr_rank_memo_bytes` | **2,912,555** | 65,334,452 |
| **B/entry** | **1,191** | **26,711** |
| process RSS | **158 MiB** | 183 MiB |
| wall | **26.13 s** | 26.81 s |

Identical hit/miss/entry counts — the memo is functionally the same object.
**22.4x fewer bytes, −25 MiB RSS, and not slower**: the 0.130 ms encode replaces
the 0.24–0.30 ms `estimate_result_bytes` graph walk it no longer needs (the
charge is now `len(blob)`, exact rather than calibrated), which pays for the
0.151 ms decode on hits.

---

## 5. Projected hit rate at 96 MiB

Per-entry total = 918 B blob (+ header = 933) + **245 B measured bookkeeping**
(OrderedDict node 132 B + the 64-hex key string 113 B the memo retains) ≈
**1,178 B**; in situ, 1,191 B.

| | today | compact |
|---|---:|---:|
| B/entry (live-metered) | ~34,100 (96 MiB / 2,954 entries) | ~1,191 |
| entries admitted at 96 MiB | 2,954 (measured, p2-s05) | **84,500** |
| the 20,117 distinct keys the unbounded run minted | 655 MiB — impossible | **23.9 MiB (25 % of the bound)** |
| binding constraint | the BYTE bound | the ENTRY bound (50,000 = 59.5 MiB) |
| **hit rate** | **34 %** (17,674 / 51,696, 31,068 evicted) | **≈66 %** — the unbounded rate, because nothing evicts |

Key-frequency data: the bench's synthetic shape mints 2,446 keys with no
re-use, so it cannot produce a hit-rate curve; the projection uses the live
figures (`docs/scale/P2_STEP5_2P5K_VERDICT_2026-08-29.md` §3 for the bounded
run, the P2 steps-0–2 verdict's 38,936 / 59,053 = 66 % at 20,117 minted keys for
the unbounded one). The projection is not an extrapolation of the hit *rate* — it
is the observation that **at 24 MiB the bound cannot evict anything**, so the
memo behaves exactly as the unbounded run did.

**Wall-clock consequence** (s05 arithmetic): 34,022 misses become ~17,600, so
~16,400 `rank()` calls at 2.6–5.4 ms are avoided = **43–89 s off
`run_window`**, against 34,100 decodes x 0.151 ms = **5.1 s** added and
~2–3 s *saved* on the miss path. Net **−46 to −92 s** — the right order for the
104 s (unbounded) → 283–336 s (bounded) regression this exists to undo.

---

## 6. Recommendation

**Ship the compact form: `marshal`(delta-vs-catalog) + zlib-1, decode on hit,
default ON with `CORR_RANK_MEMO_COMPACT=0` as the kill switch.** Leave
`CORR_RANK_MEMO_BYTES_MAX` at 96 MiB and `CORR_RANK_MEMO_MAX` at 50,000 — at
1.2 KiB/entry the entry bound becomes the binding one again, at 59.5 MiB, which
is what it was always meant to be.

### What it costs, honestly

* **0.151 ms per hit** where the object form cost 0. Against `rank()` at 2.47 ms
  (live 2.6–5.4 ms) a hit still avoids 94 % of the work it exists to avoid.
* **Sharing with the live working set ends.** Today ~52 % of entries share their
  `RankingResult` with an open `ObjectSnapshot` and cost no marginal RSS; a
  decoded hit is a fresh graph the snapshot then owns. Bound: `open_objects x
  24.8 KiB` (~26 MiB at the 1,041 open objects the bench held) moved from the
  memo to the working set — where an unshared object would have been charged
  anyway once its sharer closed. The in-situ RSS (−25 MiB net) shows this does
  not dominate.
* One more encoding to keep in step with `score_template`. Mitigated by
  fail-closed verification (below), not by discipline.

### Correctness: fail-closed, not assumed

`encode_result` **refuses** (returns `None`; the memo then stores the object
exactly as before) whenever anything it would drop is not provably
reconstructible:

* a `template_id` the catalog does not carry;
* a `catalog_version` no live `Catalog` answers to;
* a `causal_chain` whose length, key set, `stage`, `root` or `note` does not
  match the template's rule (`note` is the template's only when the rung is
  unwitnessed);
* **any** catalog-derived field that does not compare equal to the template's own
  (`title`, `owner`, `first_steps`, `seams`, `deployment_scope`,
  `operator_phrase`, `manager_phrase`, `blast_radius`, `false_positives`) —
  one tuple comparison per hypothesis.

`get` is fail-closed too: if the catalog that minted a blob is gone, the entry is
dropped and the lookup reports a **miss**, so the caller ranks in full. A drift
in `score_template` therefore degrades to today's behaviour; it cannot mint a
wrong verdict.

---

## 7. Prototype

Patch: `rankmemo_compact.patch` (882 lines) — `git apply` verified clean against
`8e55a1cf` (current `main` HEAD) as well as the pinned `c9db1839`.

| file | change |
|---|---|
| `src/correlation/rank_memo.py` | +~330 lines: the `THE COMPACT CACHED FORM` section (measurements inline), `_CatalogView` / `_catalog_view`, `encode_result` / `decode_result`, `entry_bytes` / `_stored_bytes`, `RankMemo(compact=…)`, `RankMemo.entry()`, blob-aware `get`/`put`. `estimate_result_bytes` and `_owned_ids` are **unchanged** and remain the meter for the object mode. **No `engine.py` or `main.py` change** — the catalog is resolved from `scoring._CATALOG_PLAN_CACHE`, exactly as `_owned_ids` already does. |
| `src/correlation/test_p2_memflat_bounds.py` | B1–B4, B7–B9, B12 now count in `RM.entry_bytes` (the unit the bound is denominated in) instead of `estimate_result_bytes`; **8 new `C*` tests**: C0 premise, C1 round-trip equality + `hypotheses_blob()` byte identity + `to_dict()` over the whole 27-fixture corpus, C2 size/exactness, C3 determinism, C4 (x6 params) + C4b fail-closed refusals with named mutants, C5 unresolvable-catalog fail-closed, C6 kill switch, C7 end-to-end drain byte identity. |
| `src/correlation/test_p2_rank_memo.py` | T6/T7/T7b: `is` → `==` for a rebuilt hit; T7 now asserts the store holds `bytes` (structurally *stronger* than "holds no evidence objects") and walks the decoded value as well. |
| `src/correlation/bench_rankmemo_insitu.py` | new: the reproducible A/B of §4. |

### Verification run in the worktree

```
python3 -m pytest test_p2_rank_memo.py test_p2_memflat_bounds.py test_golden_wire.py -q
369 passed
CORR_RANK_MEMO_COMPACT=0 …  369 passed          # the kill switch is also green
```

Wider sweep (`test_p2_evidence_async`, `test_bounded_cohort_166`,
`test_template_index_167`, `test_verdicts`, `test_engine`,
`test_cohort_touch_gate_p1`): 545 passed, 1 failed —
`test_E10_the_consumer_drains_between_cohorts_without_the_queue_being_full`,
**a pre-existing flake**: at unmodified HEAD it fails 2 runs in 6 on its own.
`ruff check` clean on every file the patch touches (the one pre-existing I001 in
`test_p2_memflat_bounds.py` is untouched).

### Measurement scripts

`probes/bench_rankmemo_compact.py` (field attribution),
`probes/bench_rankmemo_phase2.py` + `probes/rank_memo_codec_probe.py`
(candidate A/B) are kept beside this report rather than in the patch — they are
throwaway probes superseded by the shipped codec. `bench_rankmemo_insitu.py` is
in the patch because §4 should be re-runnable.

### Follow-ups not done here

* `corr_rank_memo_bytes` will drop ~22x on the next run; the alert/operator note
  that reads it as "the memo is nearly full" needs re-baselining.
* Interning (§3) composes with this and is the next lever if decode-on-hit shows
  up in a profile.
* A `--compact` arm in `bench_memflat_p2 --calibrate` would let the estimator
  calibration and the codec be re-measured in one pass.
