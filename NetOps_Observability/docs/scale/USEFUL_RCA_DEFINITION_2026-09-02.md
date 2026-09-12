# Useful RCA — the definition, and its first measurement (2026-09-02)

**Tracker 205, STEP 1 ONLY: define and measure. No optimization, no tail
classification.** The 15-dimension tail breakdown the tracker row calls for is
step 2 and is deliberately absent from this document.

Instrument: `scripts/scale-rca-latency.py --ground-truth <run-dir>` (new mode;
the existing T0–T6 modes are untouched). Tests:
`tests/test_scale_rca_latency_useful.py`. Fixture: `tests/fixtures/ttur-gt/`.

---

## 0. Terminology, before anything else

`T1` remains **time to first correlated version** — an engineering lifecycle
metric published, never gated, by `CORRELIX_REFERENCE_CAPACITY_V1.md` §8(b).
**It is not TTUR and is never to be printed as TTUR** (standing rule:
`HOST_CEILING_2026-08-31.md`, `PROJECT1_DONE_2026-09-01.md`, tracker 205).

This document adds four *new*, explicitly-named quantities. The first of them,
`time_to_first_candidate`, is the same *kind* of quantity T1 measures — but
measured from a different zero (see §4 and §6.3), so the two numbers are not
interchangeable and are never to be quoted as one another.

---

## 1. What a "Useful RCA" is

An incident's RCA is **useful at time _t_** when, evaluated over the engine
state persisted at or before _t_, **every** clause below holds simultaneously.
Each clause names the exact field it reads. A clause with no data source today
is marked **NOT MEASURABLE** and is *excluded* from `time_to_useful` rather
than approximated — the output carries the list it actually evaluated
(`useful_clauses_measured`).

Scoring rules are **reused from scorer v2 verbatim** (`scripts/lab/twin/scorer.py`,
`SCORER_VERSION = 2`), not re-invented:

* **membership** — an object belongs to a story when **any** of its versions'
  `affected` names one of the story's entities (`ScoreContext._objects_for_many`);
* **coverage clauses** are evaluated over the **union** of the touching objects
  (tracker 191);
* **quality clauses** are evaluated on the single deterministic `_best_object`
  (tier → `node_count` → `top_confidence` → `correlation_id` ASC);
* an object whose current state is `merged` contributes nothing.

The one extension: everything is **time-indexed**. The "union at time _t_" is
the latest version of each touching object persisted at or before _t_. That is
the only way a *latency* can exist at all — scorer v2 grades the end state.

### (a) `cause_named` — correct cause / seam

| | |
|---|---|
| truth field | `ground_truth.jsonl` → `expect.rca.affected_includes` (the storm generator puts exactly the **cause device** there; it is the same list `ground-truth.json` → `incidents[].cause_entity.device` names) |
| engine field | `netops.corr_objects.affected` (JSON `{"devices":[…],"interfaces":[…]}`) |
| rule | scorer v2 `affected_includes`, verbatim: **every** name in `expect.rca.affected_includes` appears in the `affected` of **some** object in the union at _t_ |
| measurable | **YES** |

Note on the literal wording of the tracker row ("the version's top hypothesis
names the ground-truth cause entity"): `corr_objects.top_hypothesis` holds a
**hypothesis-catalog id** (`sig.ent.middle-mile.lastmile-circuit-flap`), never
an entity id, so a top-hypothesis-names-the-entity test is not expressible
against the schema. Scorer v2's own cause rule on this corpus is
`affected_includes`, and that is what is implemented. `hypothesis_matches` —
scorer v2's regex-over-`top_hypothesis` clause — exists but **no story in the
storm ground truth asserts it** (all 345 `expect` blocks are exactly
`{affected_includes, verdict_tier_at_least}`), so there is nothing to reuse it
against here.

### (b) `ownership_domain` — correct ownership domain — **NOT MEASURABLE**

| | |
|---|---|
| truth field | `ground_truth.jsonl` → `labels.expected_owner_class` / `labels.expected_seam_class` (also `ground-truth.json` → `incidents[].expected_owner_class` / `expected_seam_class`) |
| engine field | `hypotheses` → `ranking.hypotheses[top].verdict.owner`; seam grounding would be `netops.corr_edges` `grounding_kind='seam'` |
| measurable | **NO** |

The truth side **does** exist and **is** deterministic — one value per template,
verified on storm-s11's 345 stories:

| template | `expected_owner_class` | `expected_seam_class` | n |
|---|---|---|--:|
| `local_link_fault` | `device_local` | `lan_access` | 150 |
| `bgp_peer_flap` | `peer_transit` | `wan_transport` | 100 |
| `ospf_adjacency_flap` | `igp_internal` | `lan_core` | 60 |
| `upstream_link_failure` | `upstream_transport` | `wan_transport` | 20 |
| `enterprise_outage` | `upstream_transport` | `wan_transport` | 15 |

What does **not** exist is the other half of the comparison:

1. the engine speaks a **different vocabulary** — measured on the same corpus,
   `verdict.owner` over the 345 best objects is `netops` 318 / `carrier` 27,
   which is not even cardinality-compatible with the four truth classes;
2. **no ratified crosswalk** between `{device_local, peer_transit,
   igp_internal, upstream_transport}` and `{netops, carrier, isp, app_team, …}`
   exists in the tree;
3. the ground-truth contract itself declares those labels **informational**:
   the miniladder onboards `mlx-` devices with **no seam configuration**, so the
   engine has nothing to attribute ownership to. Confirmed on s11:
   `grounding_context.seams` is `[]` and no story asserts `expect.seam`.

Deriving the expected class from the template is trivial (the table above) —
but comparing it to `verdict.owner` would require inventing the crosswalk, and
an invented crosswalk would manufacture either a 100 % or a 0 % ownership score
out of nothing. So the clause is **excluded from `time_to_useful`**, and both
sides are emitted as diagnostics (`best_owner`, `expected_owner_class`,
`expected_seam_class` per story; `owner_diagnostic` in the summary) so a
crosswalk can be *built from measured data* when the harness provisions seams.

**To make it measurable:** provision seams on the miniladder fleet (so
`corr_edges grounding_kind='seam'` and `expect.seam` become non-empty), then
ratify the class↔owner crosswalk. Both are tracker-205 step-2/3 work, not
step 1.

### (c) `blast_radius` — meaningful blast radius

| | |
|---|---|
| truth field | `expect.rca.affected_includes` (gated); `labels.blast_radius` (diagnostic) |
| engine field | `corr_objects.affected` |
| rule | scorer v2 `affected_includes` over the union — **the same predicate as (a)** |
| measurable | **YES (gated)** / recall **reported, not gated** |

Honest statement of a collapse: scorer v2 defines exactly **one** blast-radius
rule and it is `affected_includes`; on the storm corpus its argument *is* the
cause device, so clauses (a) and (c) are the same test by construction. The
clause is kept named and separate because a future workload may assert a wider
`affected_includes`, and it is **not** re-derived with an invented "meaningful"
threshold. Alongside it the tool reports **blast-radius recall** — the fraction
of `labels.blast_radius` devices named by the union — as an ungated diagnostic
(s11: p50 1.000, mean 0.973, min 0.300, 330/345 stories at full recall).

### (d) `sufficient_evidence` — verdict tier + ≥ 2 independent streams

| | |
|---|---|
| engine fields | `corr_objects.verdict_tier` (Enum8 `undetermined`/`suspected`/`confirmed`) and `hypotheses` → `ranking.hypotheses[top].verdict.modality_coverage` |
| rule | best object's tier ≥ the story's `expect.rca.verdict_tier_at_least` (always `suspected` here) **AND** `len(verdict.modality_coverage) ≥ 2` |
| measurable | **YES** |

"Independent streams" is **the engine's own test**, not one invented here: when
a hypothesis covers a single modality class the engine writes its own reason
string into `ranking.evidence_missing` —
`"single modality class (control_plane); need ≥2 — every modality has a blind
spot"`. `modality_coverage` is therefore the field that decides the clause.
Two neighbouring fields are read and **reported** but not gated, because
neither is the engine's independence test:

* `verdict.observer_coverage` — distinct observing devices;
* `verdict.independent_pair` — the named corroborating pair (`null` when none).

Threshold is `--independent-streams` (default 2).

### (e) `no_ignored_contradiction` — no unresolved contradiction outranking the top

| | |
|---|---|
| engine field | `hypotheses` → `ranking.hypotheses[].contradicted` (bool), `[].contradictions` (list), `[].confidence` |
| rule | **no** ranked hypothesis with `confidence ≥ top.confidence` carries `contradicted == true` (the top hypothesis itself included) |
| measurable | **YES** |

`ranking.hypotheses` is confidence-descending, so "outranking" is expressible as
a confidence comparison; the `≥` makes a *tied* contradicted hypothesis count,
which is the conservative reading. Evaluated server-side as
`length(arrayFilter(x -> JSONExtractBool(x,'contradicted') AND
JSONExtractFloat(x,'confidence') >= tconf, hs))`.

---

## 2. The four timings

All four are measured **relative to the story's ONSET** — the first injected
scenario event — not to `window_start`:

> `onset_wall = burst_start + ground-truth incidents[].onset_ts`
>
> `burst_start` comes from the leg's own `report.json` via
> `scale-ab-driver.burst_scope()` (imported, not re-derived — the same scope
> V1 §8(b) publishes T1 over). `onset_ts` is cross-checked against the twin
> record's `t0_offset_s`; a disagreement is fatal.

| timing | definition |
|---|---|
| `time_to_first_candidate` | onset → the first persisted version of **any** object that touches the story. **This is T1 for that story** (time to first correlated version). NOT TTUR. |
| `time_to_first_correct` | onset → the first moment clause **(a)** holds |
| `time_to_useful` | onset → the first moment **every clause in `useful_clauses_measured`** holds simultaneously — today `(a) (c) (d) (e)`, with **(b) excluded as NOT MEASURABLE** |
| `time_to_stable` | onset → the earliest event after which the story's top hypothesis (the `_best_object`'s `top_hypothesis`) **never changes again** through the last version |

Two auxiliary per-clause timings are emitted so a censored `time_to_useful` is
diagnosable rather than merely absent: `time_to_first_evidence` (clause d) and
`time_to_first_uncontradicted` (clause e).

**Negative values are reported, not clamped.** Onset is generator event time
(quantised to the scenario's `chunk_secs`, 10 s here); the four T's are engine
persist wall clock (`created_at`). Every latency straddles two clocks.

### Censoring — how a story that never gets there is counted

A story that never reaches a stage is **censored**: its timing is `None` (an
**empty** TSV cell, never `0`), a per-stage flag is set, and it is **excluded
from that stage's percentiles while being counted in the censored total**. No
story is ever silently dropped.

| flag | meaning |
|---|---|
| `censored_no_candidate` | no object ever touched the story — every timing censored |
| `censored_not_correct` | clause (a) never held |
| `censored_not_useful` | the measured clause set never held simultaneously |
| `censored_never_stable` | only possible when there is no candidate (the last event is trivially stable) |

Every published percentile therefore travels with `n`, `censored` and
`censored_pct`. A fully censored timing reports `n: 0` and `null` percentiles —
never `0.0`, which would read as "instant".

---

## 3. Outputs

`ttur-useful.tsv` — one row per story, columns:

```
story_id · template · onset_offset_s · onset_ms · objects · versions ·
time_to_first_candidate · time_to_first_correct · time_to_useful ·
time_to_stable · time_to_first_evidence · time_to_first_uncontradicted ·
blast_recall · best_owner · expected_owner_class · expected_seam_class ·
max_modality_coverage · max_observer_coverage · independent_pair_seen ·
top_hypothesis_final · censored_no_candidate · censored_not_correct ·
censored_not_useful · censored_never_stable · useful_clauses_measured
```

`ttur-useful-summary.json` — p50/p95/p99 (+ min/max/mean) per timing over the
non-censored stories, the censored counts, `n`, the run's scope and digest,
`useful_clauses_measured`, `useful_clauses_not_measurable`, the ownership and
independence diagnostics, and the caveats.

Query safety (tracker 201: an unbounded `corr_objects` read is the defect): the
version scan is **tenant-bounded, burst-window-bounded, excludes the
storm-aggregate object** (whose `hypotheses` blob is ~1 GiB) and is issued in
`--gt-slices` slices (default 6), each with `max_execution_time=60`,
`max_memory_usage=2 GiB`, `max_block_size=256`, `max_threads=2`. The 26 KB
`hypotheses` column is parsed **server-side** and never crosses the wire.

---

## 4. First measurement (storm-s11)

**The s11 corpus was still resident.** Checked read-only before running:
`netops.corr_objects` holds **10,826 versions across 2,070 objects** in
`2026-09-01 21:41:13 .. 22:19:31` (tenant `global`, 1 tenant). Applying V1
§8(b)'s scope — `min(window_start)` inside the burst window, storm-aggregate
`bb1e46d6-5462-54dc-8465-777c707b9329` excluded — gives **1,624 objects /
10,371 versions**, digit-identical to the leg's published `ttur.tsv`. The
harness cleanup purged the device registry, not the correlation history.

Run: `python3 scripts/scale-rca-latency.py --ground-truth
/var/tmp/scale-runs/storm-s11-09012138 --tenant global --out-dir <dir>`
(run `090121382mk4`, seed 20260829, digest `0e1a8d7b…`, 345 stories, ~3 min,
6 slices, read-only).

### The four tracker-205 timings — storm-s11, 345 stories

| timing | n | censored | min s | **p50 s** | **p95 s** | **p99 s** | max s | mean s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `time_to_first_candidate` | 345 | 0 | 19.30 | **349.40** | **883.64** | **1,039.93** | 1,058.03 | 408.17 |
| `time_to_first_correct` | 345 | 0 | 19.30 | **349.40** | **883.64** | **1,039.93** | 1,058.03 | 411.77 |
| `time_to_useful` | 0 | **345** | – | **–** | **–** | **–** | – | – |
| `time_to_stable` | 345 | 0 | 19.30 | **384.04** | **952.29** | **1,902.00** | 1,992.14 | 445.72 |

`useful_clauses_measured = [cause_named, blast_radius, sufficient_evidence,
no_ignored_contradiction]`; `ownership_domain` NOT MEASURABLE (§1b).

Censored counts: `no_candidate 0 · not_correct 0 · not_useful 345 ·
never_stable 0`. Negative latencies: 0.

Per-clause first satisfaction:

| clause | never satisfied | p50 s | p95 s |
|---|--:|--:|--:|
| `cause_named` | 0 / 345 | 349.40 | 883.64 |
| `blast_radius` | 0 / 345 | 349.40 | 883.64 |
| `sufficient_evidence` | **345 / 345** | – | – |
| `no_ignored_contradiction` | 0 / 345 | 349.40 | 883.64 |

### What the measurement says

1. **`time_to_useful` is 100 % censored, and the reason is structural, not an
   engine defect.** `sufficient_evidence` never holds because
   `modality_coverage` is **1 for all 345 stories** — the miniladder injects
   **syslog only**, so every hypothesis covers exactly one modality class
   (`control_plane`) and the engine correctly refuses to call the evidence
   independent. `independent_pair` is `null` on every version. The *observer*
   axis does move (`max_observer_coverage`: 1 → 225 stories, 2 → 100, 24 → 20),
   which is why it is reported: 120/345 stories would qualify under an
   observer-based reading. **A real `time_to_useful` number needs a
   multi-modality workload**, not a threshold change. This is the single most
   actionable finding of step 1.
2. **Correct is essentially free once a candidate exists.** 319/345 stories are
   correct at their first candidate version; the other 26 take up to 84 s more
   (p50 of the delta 0 s). The cost being measured here is *time to any
   correlated version*, not time to the right answer.
3. **Stability lags correctness in the tail, not the middle.** 331/345 stories
   never change their top hypothesis; the p99 gap (1,902 s vs 1,040 s) is
   14 stories that flip late.
4. **Blast-radius recall is high but not total**: p50 1.000, mean 0.973,
   min 0.300, 330/345 at full recall.

### Contradiction with the tracker-205 premise (recorded, not resolved)

The row implies `time_to_first_candidate` *is* T1. It is the same quantity —
but **measured from a different zero**, and the numbers are therefore not
interchangeable:

* §8(b) T1 is `min(created_at) − min(window_start)` **per correlation object**
  (1,624 objects): p50 **80 s**, p95 **876 s**;
* tracker-205 `time_to_first_candidate` is `first created_at − ground-truth
  onset` **per story** (345 stories): p50 **349 s**, p95 **884 s**.

The p95s nearly coincide; the p50s differ by 4.4×. Two causes, both real:
(i) the base differs — `window_start` is the *object's own* first event time,
which on this storm workload is typically minutes after the injected onset;
(ii) the populations differ — 1,624 objects vs 345 stories. Anyone quoting
"T1" and "time_to_first_candidate" as one number will be wrong by that gap.

**Also contradicted:** the row's clause (b) ("correct ownership domain") is not
scoreable at all on the reference workload (§1b), and clauses (a) and (c)
collapse to one predicate under scorer v2's actual rule set (§1c). Neither is a
reason to loosen a rule; both are step-2 inputs.

Raw artifacts for this run:
`/tmp/claude-1000/…/scratchpad/ttur-s11/{ttur-useful.tsv,ttur-useful-summary.json,run.log}`
(scratchpad, deliberately not committed — this leg's outputs belong to the run
dir when the mode is wired into qualification, see §5).

---

## 5. Wiring it into release qualification (NOT DONE — one line)

`scripts/release-qualify.py` `stage_ttur()` already derives the §8(b) scope and
writes `ttur.tsv` / `ttur-scope.json`. Adding this measurement is one call,
immediately after `write_text(scope_path, …)` and before `self.publish_t1(ev)`:

```python
self.runner([sys.executable, os.path.join(SCRIPT_DIR, "scale-rca-latency.py"),
             "--ground-truth", self.leg_dir, "--tenant", self.args.tenant,
             "--out-dir", self.leg_dir], CH_TIMEOUT)
```

It must stay **published, never gated**, exactly as T1 is — and it must run
**before** the leg's `cleanup` phase only if the correlation history is purged
there; on s11 it was not, so a post-hoc run works. `release-qualify.py` was
just committed and is **not edited here**.

---

## 6. Standing caveats (they travel with every number above)

1. These four numbers are the **tracker-205 definitions**.
   `time_to_first_candidate` is T1's quantity; **it is not TTUR.**
2. Onset is **ground-truth event time** (generator clock, ≥ `chunk_secs`
   quantisation); the four T's are **engine persist wall clock**. Every latency
   straddles two clocks.
3. Clause evaluation reuses scorer v2 verbatim, time-indexed. It is not a
   second scorer: on the end state it reduces to scorer v2's own answer.
4. `ownership_domain` is NOT MEASURABLE and excluded from `time_to_useful`;
   every output states which clauses it actually evaluated.
5. Censored stories are counted, never dropped. Percentiles are nearest-rank
   over the non-censored subset only.
6. 5 of 10,826 versions carried a `top_hypothesis` id absent from their own
   `ranking.hypotheses`; those fall back to ranked entry 1 and are counted
   (`top_hypothesis_rank_fallbacks`) rather than dropped.
