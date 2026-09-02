# Tail classification — storm-s11, tracker 205 STEP 2 (2026-09-02)

**Tracker 205, STEP 2 ONLY: classify the tail. No optimization is proposed
here** — the row's rule is *"only optimize after identifying the actual tail
contributor"*, and this document identifies it. Step 1 is
`docs/scale/USEFUL_RCA_DEFINITION_2026-09-02.md`; its timings are **read, not
re-measured**.

Instrument: `scripts/scale-rca-tail.py <run-dir>` (read-only; two bounded,
tenant- and burst-scoped `corr_objects` scans, storm-aggregate excluded).
Tests: `tests/test_scale_rca_tail.py` (47). Artefacts:
`/var/tmp/scale-runs/storm-s11-09012138/{tail-dimensions.tsv,
tail-classification.json,tail-classification.md}`. Corpus: 345 stories,
10,826 versions / 1,624 in-scope objects, run `090121382mk4`, seed 20260829,
digest `0e1a8d7b…`.

---

## The one sentence

> **No identity class dominates the tail. The tail is ONSET-SHAPED: all 34 of
> the `time_to_first_candidate` tail stories were injected in the last third of
> the 900 s burst (onset 598.9–756.9 s), latency ≈ `1.405 × onset − 96.6 s`
> (r = 0.978, n = 345) — the contributor is the burst-drain backlog, i.e. an
> incident's ARRIVAL POSITION, not its root-cause class, seam, size, topology,
> evidence shape, candidate count or ownership.**

`onset_band` is the only dimension of the fifteen that clears the tracker's own
test (a bucket holding > 50 % of the tail while holding < 25 % of the stories),
and it clears it on all three classifiable timings. It is a *position*, not an
identity: the tail is where the queue was deepest, not what kind of incident it
was.

## What dominates, in numbers

`time_to_first_candidate`, tail = the 34 stories above the overall p90
(821.4 s):

| onset band | stories | tail | tail share | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|
| 0–99 s | 41 | 0 | 0.000 | 0.000 | 59.7 | 138.0 |
| 100–199 s | 54 | 0 | 0.000 | 0.000 | 122.7 | 173.0 |
| 200–299 s | 50 | 0 | 0.000 | 0.000 | 219.2 | 283.5 |
| 300–399 s | 46 | 0 | 0.000 | 0.000 | 328.0 | 412.8 |
| 400–499 s | 51 | 0 | 0.000 | 0.000 | 487.6 | 656.8 |
| 500–599 s | 57 | 1 | 0.029 | 0.018 | 704.7 | 806.7 |
| **600–699 s** | **39** | **26** | **0.765** | **0.667** | **877.0** | **976.0** |
| **700–799 s** | **7** | **7** | **0.206** | **1.000** | **1,039.9** | **1,058.0** |

Monotone, with a knee: **1 of the 299 stories injected before 600 s is in the
tail; 33 of the 46 injected after it are.** `time_to_stable` shows the same
band at lower contrast (`600–699 s`: 0.559 of the tail in 0.113 of the stories,
lift 4.94). `time_to_useful` is **not classified** — it is 100 % censored for
the structural reason step 1 recorded (syslog-only workload, `modality_coverage
== 1` on every story); that censoring is reported, never scored as a win.

## The onset-band check (the 5k clue, re-run here)

| population | n | tightest window holding 80 % | width |
|---|--:|---|--:|
| all stories | 345 | 49.4 – 555.8 s | **506.4 s** |
| tail stories | 34 | 641.1 – 724.7 s | **83.6 s** |

The tail's onsets are **6.1× tighter** than the corpus'. And, exactly as
`HOST_CEILING_2026-08-31.md` §3 records for the 5k rung, **the band is not the
storm's own peak**: scenario load in the 600–750 s chunks runs 17–164 events per
10 s chunk against a corpus mean of 178 and a peak of 833. The band is a
property of the *queue*, not of the offered load inside it.

## What does NOT dominate

* **Root-cause class / seam type.** The tail is `local_link_fault` 17 +
  `bgp_peer_flap` 17, zero from the other three templates — but that is
  **confounded by onset**: no `ospf_adjacency_flap`, `upstream_link_failure` or
  `enterprise_outage` story was injected after 600 s at all. Neither template
  clears the dominance test (each 0.500 of the tail at 0.290 / 0.435 of the
  stories). `seam_type` splits the tail 50/50 (excess +0.11 / +0.07).
* **Affected-device count, component size, candidate count, evidence
  recurrence, aggregation suppression, vantage/observer count, blast-wave
  depth** — every one of them has a top bucket whose excess is below +0.23, and
  none clears the test. `component_size` `2-4` looks large (0.941 of the tail)
  only because it is 0.716 of the corpus.
* **`modality_count`** is a single bucket (`1`) on this workload: it holds
  100 % of every tail *by construction* and explains nothing. That is why the
  ranking is by **excess** (tail share − story share), not raw tail share.
* **`cohorts_before_verdict`** has the largest raw excess (+0.710; `10+` holds
  100 % of the tail in 29 % of the stories) but is **partly circular** — it is
  counted over `(onset, first_correct]`, so it grows *with* the latency it would
  explain. It is a restatement of the tail in cohort units, not a cause, and the
  tool says so in its own output.

## One residual, honestly stated

Template selectivity **survives inside the band**, weakly: among the 45 stories
injected in 600–750 s, `bgp_peer_flap` is in the tail 16/18 (0.89) against
`local_link_fault` 16/27 (0.59). So onset is the dominant axis and template is
a secondary modifier within it — which is a *partial* echo of the 5k rung's
"template-selective" finding, not a reproduction of it, and it is **not** enough
to make template an identity class that dominates.

## NOT MEASURABLE — 3 of the 15, plus 1 with no per-object record

| owner's dimension | why not |
|---|---|
| **incident size (scenario events per story)** | no artefact carries a per-story event count: `ground-truth.json counts.chain_events_by_type` is corpus-global, `burst-chunks.json` is per-10 s-chunk global with no story id, and only the 15 `enterprise_outage` stories carry `unpromotable_events`. Labelled proxy emitted: `engine_evidence_size` (`signal_count` at first candidate) — post-aggregation and object-shared, so not the owner's quantity. |
| **topology depth** | no topology is provisioned on the miniladder fleet: `grounding_context.seams` is `[]` and `topology_gap_hints` is `0` on all 10,826 versions. Labelled proxy emitted: `blast_wave_depth` (injected propagation waves). |
| **ownership lookup path** | `corr_objects.attribution` is `{}` on **0 of 10,826** in-scope versions; `verdict.owner` is *declared* by the matched catalog template rather than resolved through a lookup, so there is no path to bucket. Same gap step 1 recorded for the `ownership_domain` clause. |
| **template-index hit vs fallback** | the tracker-167 kind index keeps only process-wide counters (`corr_template_scored_total` / `_candidates_total` / `_ungrounded_total`); nothing per-object records the index's decision, and the tracker-157 structural refusal never fired on this corpus (0 versions carry the "suppressed: this signature names" note). Labelled proxies emitted: `hyp_satisfied_count` and step 1's `top_rank_fallback`. |

`seam_type` is measurable on the **truth** side only (the engine grounds no
seams here); `cohorts_before_verdict` is a **reconstruction** — cohort
boundaries are gaps > 2 s in the global `created_at` stream, giving 44 cohorts
against the engine's own `corr_engine_cohorts_total` = 46 over the whole
process lifetime (the reconstruction covers burst → converged only). Both
numbers are printed together.

## Contradictions with the tracker row / the 5k clue (recorded, not resolved)

1. **The row expects all 15 dimensions to be classifiable.** Three are not, and
   a fourth has no per-object record (table above). Every one of them is
   emitted with its reason rather than approximated.
2. **The 5k clue reads as "template-selective".** On s11 the corpus-level
   template split is *confounded by onset* (three of five templates have no
   story injected after 600 s). Template selectivity is real but secondary, and
   only visible after conditioning on the band.
3. **The 5k clue is an ACCURACY finding; this is a LATENCY one.** s11 scored
   345/345, so at 1× the ceiling the same onset band costs *time*, not
   *correctness*. The two bands are the same shape at different loads, and the
   claim that they are the same phenomenon is **not proven here**.
4. **`cohorts_before_verdict` is not an independent dimension** (circularity
   above). The owner's list treats it as one.

---

The generated report follows verbatim.

---

# Tail classification — tracker 205 STEP 2

Run `090121382mk4` (`t-storm-2.5k`, seed 20260829), tenant `global`, 345 stories. Generated 2026-09-02T02:10:45Z. READ-ONLY.

Timings are READ from step 1's `ttur-useful.tsv` (`docs/scale/USEFUL_RCA_DEFINITION_2026-09-02.md`); they are not re-measured here.

## 0. The owner's 15 dimensions (+ the labelled proxies) — where each comes from

| # | owner's dimension | status | column | source |
|--:|---|---|---|---|
| 1 | seam type | **MEASURABLE** | `seam_type` | ground_truth.jsonl labels.expected_seam_class (== ground-truth.json incidents[].expected_seam_class) |
| 2 | root-cause class (template) | **MEASURABLE** | `template` | ground_truth.jsonl template (== ground-truth.json cause_kind) |
| 3 | incident size (scenario events per story) | **NOT MEASURABLE** | `—` | no artifact carries a per-story scenario event count |
| 4 | incident size — engine-side proxy | **PROXY** | `engine_evidence_size` | corr_objects.signal_count of the best object at first candidate |
| 5 | topology depth | **NOT MEASURABLE** | `—` | no topology is provisioned on the miniladder fleet |
| 6 | topology depth — injected-propagation proxy | **PROXY** | `blast_wave_depth` | ground-truth.json incidents[].blast_radius_waves (count of waves) |
| 7 | affected-device count | **MEASURABLE** | `affected_devices` | ground_truth.jsonl labels.blast_radius (length) |
| 8 | evidence-modality count | **MEASURABLE** | `modality_count` | hypotheses.ranking.hypotheses[top].verdict.modality_coverage (length) at first candidate |
| 9 | independent vantage (observer) count | **MEASURABLE** | `observer_count` | hypotheses.ranking.hypotheses[top].verdict.observer_coverage (length) at first candidate |
| 10 | independent vantage count — truth side | **MEASURABLE** | `truth_vantage_count` | ground-truth.json incidents[].vantages (length) |
| 11 | template-index hit vs fallback | **NOT MEASURABLE** | `—` | the tracker-167 kind index keeps only GLOBAL counters |
| 12 | template-index hit — per-object proxy | **PROXY** | `hyp_satisfied_count` | count of ranking.hypotheses[] with a non-empty `satisfied` list, at first candidate |
| 13 | candidate (hypothesis) count | **MEASURABLE** | `candidate_count` | length(hypotheses.ranking.hypotheses) at first candidate |
| 14 | first occurrence vs repeated evidence | **MEASURABLE** | `evidence_recurrence` | hypotheses.grounding_context.aggregation.classes (the DeltaClass histogram: first / state_transition / recovery / repeat / count_threshold), at first candidate — the bucket is the sorted set of classes present |
| 15 | aggregation forwarded vs suppressed | **MEASURABLE** | `agg_suppression` | hypotheses.grounding_context.aggregation: forwarded = `deltas`, suppressed = `raw_signal_count` - `deltas`, at first candidate |
| 16 | incident creation time relative to burst | **MEASURABLE** | `onset_band` | ground-truth.json incidents[].onset_ts (seconds into the 900 s burst), in fixed 100 s bands |
| 17 | number of cohorts before first verdict | **PROXY** | `cohorts_before_verdict` | reconstructed: cohort boundaries are gaps > --cohort-gap-s in the GLOBAL corr_objects created_at stream; the dimension counts cohorts that started in (onset, first_correct] |
| 18 | ownership lookup path | **NOT MEASURABLE** | `—` | corr_objects.attribution is '{}' on every version in scope |
| 19 | component size | **MEASURABLE** | `component_size` | corr_objects.node_count of the best object at first candidate |

* **seam_type** (MEASURABLE) — TRUTH SIDE ONLY. The engine persists no seam grounding on this corpus: `grounding_context.seams` is [] on every version and corr_edges carries no grounding_kind='seam' row, because the miniladder onboards devices with no seam configuration (step 1 §1b). The bucket is therefore the INJECTED seam class, which is exactly what a tail classification needs — it identifies the story, it does not score the engine.
* **incident_size** (NOT MEASURABLE) — ground-truth.json counts.chain_events_by_type is CORPUS-GLOBAL; burst-chunks.json is per-10 s-chunk global (lanes/scenario totals, no story id); only the 15 enterprise_outage stories carry `unpromotable_events`, and no story carries a promoted-event count. The engine-side stand-in `engine_evidence_size` (signal_count at first candidate) is emitted as a SEPARATE, explicitly-labelled proxy — it is post-aggregation and is shared by every story folded into the same correlation object, so it is not the owner's quantity.
* **engine_evidence_size** (PROXY) — Post-aggregation and object-shared; a proxy for incident size, NOT the scenario event count the owner named.
* **topology_depth** (NOT MEASURABLE) — `grounding_context.seams` is [] and `topology_gap_hints` is 0 on all 10,826 versions; there is no adjacency graph to take a depth over. The INJECTED propagation depth is available and is emitted as the labelled proxy `blast_wave_depth`.
* **blast_wave_depth** (PROXY) — The number of propagation waves the generator injected from the cause entity. A depth in the INJECTED fault, not in the estate's topology.
* **modality_count** (MEASURABLE) — DEGENERATE on this corpus: the V1 workload is syslog-only, so every story sits in one bucket. Reported, and its single-bucket state is stated rather than dressed up as a 100 % concentration.
* **template_index** (NOT MEASURABLE) — `corr_template_scored_total` / `corr_template_candidates_total` / `corr_template_ungrounded_total` (scoring.py) are process-wide counters in the metrics exposition; nothing per-object records whether a given template was admitted by the kind index or elided. The per-object stand-ins are emitted as labelled proxies: `hyp_satisfied_count` (ranked hypotheses whose `satisfied` clause list is non-empty = templates the evidence actually reached) and `top_rank_fallback` (the object's top_hypothesis id is absent from its own ranking — step 1's `top_fallback`, 5 versions of 10,826). The tracker-157 structural refusal never fired on this corpus (0 versions carry the 'suppressed: this signature names' note), so that gate contributes no variance either.
* **hyp_satisfied_count** (PROXY) — A template with a satisfied clause is one the evidence REACHED — the same population the kind index admits — but this counts the ranking's OUTPUT, not the index's decision, and it cannot see a template the index elided analytically. A proxy for the gate, not the gate.
* **agg_suppression** (MEASURABLE) — `raw_signal_count` is a LOWER BOUND on raw coverage by the engine's own docstring (Σ over key of MAX(agg_count)); repeats arriving after a key's last delta are absorbed and never re-announced. So 'some_suppressed' is sound and 'forwarded_only' means 'no suppression VISIBLE to the object', not a proof of none.
* **cohorts_before_verdict** (PROXY) — No per-object cohort id is persisted. The reconstruction is validated against the engine's own `corr_engine_cohorts_total` in metrics-final.txt and BOTH numbers are reported; a disagreement is printed, never hidden. AND IT IS PARTLY CIRCULAR: the count is taken over (onset, first_correct], so it grows WITH the latency it is meant to explain — a story that took longer necessarily spans more cohorts. It is measured because the owner named it, and it must be read as a RESTATEMENT of the latency in cohort units, never as a cause.
* **ownership_lookup** (NOT MEASURABLE) — Measured, not assumed: 0 of 10,826 in-scope versions carry a non-empty `attribution`, `grounding_context.seams` is [] everywhere, and `verdict.owner` is DECLARED by the matched catalog template rather than resolved through a lookup — so there is no path to bucket. Step 1 already recorded the same gap for the ownership_domain clause.

## 0b. Cohort reconstruction (dimension 13)

Gap threshold 2.0 s over the global `created_at` stream reconstructs **44** cohorts; the engine's own `corr_engine_cohorts_total` reads **46** (engine counter covers the WHOLE process lifetime; the reconstruction covers the burst..converged scope only).

## time_to_first_candidate

n = 345 scored (0 censored). Tail = above the overall p90 = **821.42 s**.

### Top 5 dimensions by tail concentration

Ordered by the dominance test first, then by **excess** (tail share − story share). Raw tail share is shown but is NOT the ordering: a dimension with one bucket holds 100 % of the tail for free.

| rank | dimension | top bucket | tail share | story share | excess | lift | dominates? |
|--:|---|---|--:|--:|--:|--:|---|
| 1 | `onset_band` | `600-699s` | 0.765 | 0.113 | 0.652 | 6.76 | **YES** |
| 2 | `cohorts_before_verdict` | `10+` | 1.000 | 0.290 | 0.710 | 3.45 | no |
| 3 | `component_size` | `2-4` | 0.941 | 0.716 | 0.225 | 1.31 | no |
| 4 | `affected_devices` | `2` | 0.500 | 0.290 | 0.210 | 1.73 | no |
| 5 | `template` | `bgp_peer_flap` | 0.500 | 0.290 | 0.210 | 1.73 | no |

**A small identity class DOES dominate this timing's tail:** `onset_band` (> 50% of the tail in < 25% of the stories).

### Onset-band check (the 5k clue)

| population | n | need | tightest window (80%) | width |
|---|--:|--:|---|--:|
| all stories | 345 | 276 | 49.4 – 555.8 s | 506.4 s |
| tail stories | 34 | 28 | 641.1 – 724.7 s | 83.6 s |

### Every measurable dimension, bucket by bucket

#### `seam_type`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `lan_access` | 150 | 0.435 | 17 | 0.500 | 0.065 | 0.113 | 429.13 | 880.93 |
| `lan_core` | 60 | 0.174 | 0 | 0.000 | -0.174 | 0.000 | 275.39 | 659.13 |
| `wan_transport` | 135 | 0.391 | 17 | 0.500 | 0.109 | 0.126 | 313.13 | 975.33 |

#### `template`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `bgp_peer_flap` | 100 | 0.290 | 17 | 0.500 | 0.210 | 0.170 | 427.71 | 975.84 |
| `enterprise_outage` | 15 | 0.043 | 0 | 0.000 | -0.043 | 0.000 | 250.47 | 629.08 |
| `local_link_fault` | 150 | 0.435 | 17 | 0.500 | 0.065 | 0.113 | 429.13 | 880.93 |
| `ospf_adjacency_flap` | 60 | 0.174 | 0 | 0.000 | -0.174 | 0.000 | 275.39 | 659.13 |
| `upstream_link_failure` | 20 | 0.058 | 0 | 0.000 | -0.058 | 0.000 | 156.37 | 487.56 |

#### `engine_evidence_size`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `1-4` | 320 | 0.927 | 34 | 1.000 | 0.072 | 0.106 | 378.15 | 886.62 |
| `17-64` | 18 | 0.052 | 0 | 0.000 | -0.052 | 0.000 | 156.37 | 584.22 |
| `5-16` | 7 | 0.020 | 0 | 0.000 | -0.020 | 0.000 | 235.88 | 582.75 |

#### `blast_wave_depth`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `1` | 310 | 0.899 | 34 | 1.000 | 0.101 | 0.110 | 382.93 | 890.52 |
| `2` | 15 | 0.043 | 0 | 0.000 | -0.043 | 0.000 | 250.47 | 629.08 |
| `3` | 20 | 0.058 | 0 | 0.000 | -0.058 | 0.000 | 156.37 | 487.56 |

#### `affected_devices`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `1` | 210 | 0.609 | 17 | 0.500 | -0.109 | 0.081 | 378.15 | 877.46 |
| `2` | 100 | 0.290 | 17 | 0.500 | 0.210 | 0.170 | 427.71 | 975.84 |
| `25-39` | 20 | 0.058 | 0 | 0.000 | -0.058 | 0.000 | 156.37 | 487.56 |
| `40+` | 15 | 0.043 | 0 | 0.000 | -0.043 | 0.000 | 250.47 | 629.08 |

#### `modality_count`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `1` | 345 | 1.000 | 34 | 1.000 | 0.000 | 0.099 | 349.40 | 883.64 |

#### `observer_count`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `1` | 228 | 0.661 | 18 | 0.529 | -0.132 | 0.079 | 353.26 | 877.02 |
| `10+` | 18 | 0.052 | 0 | 0.000 | -0.052 | 0.000 | 156.37 | 584.22 |
| `2` | 98 | 0.284 | 16 | 0.471 | 0.186 | 0.163 | 419.36 | 982.82 |
| `3-9` | 1 | 0.003 | 0 | 0.000 | -0.003 | 0.000 | 46.82 | 46.82 |

#### `truth_vantage_count`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `1` | 210 | 0.609 | 17 | 0.500 | -0.109 | 0.081 | 378.15 | 877.46 |
| `10+` | 20 | 0.058 | 0 | 0.000 | -0.058 | 0.000 | 156.37 | 487.56 |
| `2` | 115 | 0.333 | 17 | 0.500 | 0.167 | 0.148 | 349.40 | 975.84 |

#### `hyp_satisfied_count`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `2` | 64 | 0.185 | 0 | 0.000 | -0.185 | 0.000 | 302.57 | 659.13 |
| `3` | 2 | 0.006 | 0 | 0.000 | -0.006 | 0.000 | 93.86 | 629.08 |
| `4` | 101 | 0.293 | 17 | 0.500 | 0.207 | 0.168 | 427.71 | 975.84 |
| `7` | 153 | 0.444 | 17 | 0.500 | 0.057 | 0.111 | 416.77 | 880.93 |
| `8` | 25 | 0.072 | 0 | 0.000 | -0.072 | 0.000 | 216.47 | 582.75 |

#### `candidate_count`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `1-4` | 66 | 0.191 | 0 | 0.000 | -0.191 | 0.000 | 302.57 | 659.13 |
| `13-17` | 178 | 0.516 | 17 | 0.500 | -0.016 | 0.096 | 349.24 | 879.78 |
| `5-8` | 101 | 0.293 | 17 | 0.500 | 0.207 | 0.168 | 427.71 | 975.84 |

#### `evidence_recurrence`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `first` | 308 | 0.893 | 34 | 1.000 | 0.107 | 0.110 | 349.40 | 890.52 |
| `first+recovery` | 24 | 0.070 | 0 | 0.000 | -0.070 | 0.000 | 440.73 | 728.68 |
| `first+recovery+repeat+state_transition` | 1 | 0.003 | 0 | 0.000 | -0.003 | 0.000 | 232.24 | 232.24 |
| `first+recovery+state_transition` | 12 | 0.035 | 0 | 0.000 | -0.035 | 0.000 | 235.88 | 584.22 |

#### `agg_suppression`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `forwarded_only` | 340 | 0.986 | 34 | 1.000 | 0.015 | 0.100 | 351.19 | 883.64 |
| `some_suppressed` | 5 | 0.015 | 0 | 0.000 | -0.015 | 0.000 | 235.88 | 582.75 |

#### `onset_band`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `0-99s` | 41 | 0.119 | 0 | 0.000 | -0.119 | 0.000 | 59.70 | 138.04 |
| `100-199s` | 54 | 0.157 | 0 | 0.000 | -0.157 | 0.000 | 122.75 | 172.97 |
| `200-299s` | 50 | 0.145 | 0 | 0.000 | -0.145 | 0.000 | 219.22 | 283.52 |
| `300-399s` | 46 | 0.133 | 0 | 0.000 | -0.133 | 0.000 | 328.04 | 412.80 |
| `400-499s` | 51 | 0.148 | 0 | 0.000 | -0.148 | 0.000 | 487.56 | 656.78 |
| `500-599s` | 57 | 0.165 | 1 | 0.029 | -0.136 | 0.018 | 704.70 | 806.72 |
| `600-699s` | 39 | 0.113 | 26 | 0.765 | 0.652 | 0.667 | 876.99 | 976.01 |
| `700-799s` | 7 | 0.020 | 7 | 0.206 | 0.186 | 1.000 | 1,039.93 | 1,058.03 |

#### `cohorts_before_verdict`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `1` | 67 | 0.194 | 0 | 0.000 | -0.194 | 0.000 | 73.40 | 159.31 |
| `10+` | 100 | 0.290 | 34 | 1.000 | 0.710 | 0.340 | 760.43 | 976.01 |
| `2` | 62 | 0.180 | 0 | 0.000 | -0.180 | 0.000 | 170.89 | 231.88 |
| `3` | 17 | 0.049 | 0 | 0.000 | -0.049 | 0.000 | 250.47 | 273.93 |
| `4` | 24 | 0.070 | 0 | 0.000 | -0.070 | 0.000 | 299.10 | 335.13 |
| `5` | 34 | 0.099 | 0 | 0.000 | -0.099 | 0.000 | 394.21 | 446.25 |
| `6` | 7 | 0.020 | 0 | 0.000 | -0.020 | 0.000 | 443.81 | 463.44 |
| `7` | 18 | 0.052 | 0 | 0.000 | -0.052 | 0.000 | 491.62 | 529.37 |
| `9` | 16 | 0.046 | 0 | 0.000 | -0.046 | 0.000 | 598.83 | 639.36 |

#### `component_size`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `1` | 78 | 0.226 | 2 | 0.059 | -0.167 | 0.026 | 336.01 | 742.20 |
| `17-64` | 18 | 0.052 | 0 | 0.000 | -0.052 | 0.000 | 156.37 | 584.22 |
| `2-4` | 247 | 0.716 | 32 | 0.941 | 0.225 | 0.130 | 412.80 | 891.82 |
| `5-16` | 2 | 0.006 | 0 | 0.000 | -0.006 | 0.000 | 46.82 | 157.41 |

## time_to_first_correct

n = 345 scored (0 censored). Tail = above the overall p90 = **821.42 s**.

### Top 5 dimensions by tail concentration

Ordered by the dominance test first, then by **excess** (tail share − story share). Raw tail share is shown but is NOT the ordering: a dimension with one bucket holds 100 % of the tail for free.

| rank | dimension | top bucket | tail share | story share | excess | lift | dominates? |
|--:|---|---|--:|--:|--:|--:|---|
| 1 | `onset_band` | `600-699s` | 0.765 | 0.113 | 0.652 | 6.76 | **YES** |
| 2 | `cohorts_before_verdict` | `10+` | 1.000 | 0.290 | 0.710 | 3.45 | no |
| 3 | `component_size` | `2-4` | 0.941 | 0.716 | 0.225 | 1.31 | no |
| 4 | `affected_devices` | `2` | 0.500 | 0.290 | 0.210 | 1.73 | no |
| 5 | `template` | `bgp_peer_flap` | 0.500 | 0.290 | 0.210 | 1.73 | no |

**A small identity class DOES dominate this timing's tail:** `onset_band` (> 50% of the tail in < 25% of the stories).

### Onset-band check (the 5k clue)

| population | n | need | tightest window (80%) | width |
|---|--:|--:|---|--:|
| all stories | 345 | 276 | 49.4 – 555.8 s | 506.4 s |
| tail stories | 34 | 28 | 641.1 – 724.7 s | 83.6 s |

### Every measurable dimension, bucket by bucket

#### `seam_type`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `lan_access` | 150 | 0.435 | 17 | 0.500 | 0.065 | 0.113 | 429.13 | 880.93 |
| `lan_core` | 60 | 0.174 | 0 | 0.000 | -0.174 | 0.000 | 275.39 | 659.13 |
| `wan_transport` | 135 | 0.391 | 17 | 0.500 | 0.109 | 0.126 | 313.57 | 975.33 |

#### `template`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `bgp_peer_flap` | 100 | 0.290 | 17 | 0.500 | 0.210 | 0.170 | 427.71 | 975.84 |
| `enterprise_outage` | 15 | 0.043 | 0 | 0.000 | -0.043 | 0.000 | 250.47 | 662.99 |
| `local_link_fault` | 150 | 0.435 | 17 | 0.500 | 0.065 | 0.113 | 429.13 | 880.93 |
| `ospf_adjacency_flap` | 60 | 0.174 | 0 | 0.000 | -0.174 | 0.000 | 275.39 | 659.13 |
| `upstream_link_failure` | 20 | 0.058 | 0 | 0.000 | -0.058 | 0.000 | 213.29 | 531.50 |

#### `engine_evidence_size`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `1-4` | 320 | 0.927 | 34 | 1.000 | 0.072 | 0.106 | 382.25 | 886.62 |
| `17-64` | 18 | 0.052 | 0 | 0.000 | -0.052 | 0.000 | 213.29 | 668.17 |
| `5-16` | 7 | 0.020 | 0 | 0.000 | -0.020 | 0.000 | 235.88 | 582.75 |

#### `blast_wave_depth`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `1` | 310 | 0.899 | 34 | 1.000 | 0.101 | 0.110 | 382.93 | 890.52 |
| `2` | 15 | 0.043 | 0 | 0.000 | -0.043 | 0.000 | 250.47 | 662.99 |
| `3` | 20 | 0.058 | 0 | 0.000 | -0.058 | 0.000 | 213.29 | 531.50 |

#### `affected_devices`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `1` | 210 | 0.609 | 17 | 0.500 | -0.109 | 0.081 | 378.15 | 877.46 |
| `2` | 100 | 0.290 | 17 | 0.500 | 0.210 | 0.170 | 427.71 | 975.84 |
| `25-39` | 20 | 0.058 | 0 | 0.000 | -0.058 | 0.000 | 213.29 | 531.50 |
| `40+` | 15 | 0.043 | 0 | 0.000 | -0.043 | 0.000 | 250.47 | 662.99 |

#### `modality_count`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `1` | 345 | 1.000 | 34 | 1.000 | 0.000 | 0.099 | 349.40 | 883.64 |

#### `observer_count`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `1` | 228 | 0.661 | 18 | 0.529 | -0.132 | 0.079 | 353.26 | 877.02 |
| `10+` | 18 | 0.052 | 0 | 0.000 | -0.052 | 0.000 | 213.29 | 668.17 |
| `2` | 98 | 0.284 | 16 | 0.471 | 0.186 | 0.163 | 419.36 | 982.82 |
| `3-9` | 1 | 0.003 | 0 | 0.000 | -0.003 | 0.000 | 115.13 | 115.13 |

#### `truth_vantage_count`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `1` | 210 | 0.609 | 17 | 0.500 | -0.109 | 0.081 | 378.15 | 877.46 |
| `10+` | 20 | 0.058 | 0 | 0.000 | -0.058 | 0.000 | 213.29 | 531.50 |
| `2` | 115 | 0.333 | 17 | 0.500 | 0.167 | 0.148 | 349.40 | 975.84 |

#### `hyp_satisfied_count`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `2` | 64 | 0.185 | 0 | 0.000 | -0.185 | 0.000 | 302.78 | 659.13 |
| `3` | 2 | 0.006 | 0 | 0.000 | -0.006 | 0.000 | 112.55 | 662.99 |
| `4` | 101 | 0.293 | 17 | 0.500 | 0.207 | 0.168 | 427.71 | 975.84 |
| `7` | 153 | 0.444 | 17 | 0.500 | 0.057 | 0.111 | 416.77 | 880.93 |
| `8` | 25 | 0.072 | 0 | 0.000 | -0.072 | 0.000 | 235.88 | 582.75 |

#### `candidate_count`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `1-4` | 66 | 0.191 | 0 | 0.000 | -0.191 | 0.000 | 302.78 | 662.99 |
| `13-17` | 178 | 0.516 | 17 | 0.500 | -0.016 | 0.096 | 349.24 | 879.78 |
| `5-8` | 101 | 0.293 | 17 | 0.500 | 0.207 | 0.168 | 427.71 | 975.84 |

#### `evidence_recurrence`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `first` | 308 | 0.893 | 34 | 1.000 | 0.107 | 0.110 | 349.40 | 890.52 |
| `first+recovery` | 24 | 0.070 | 0 | 0.000 | -0.070 | 0.000 | 440.73 | 728.68 |
| `first+recovery+repeat+state_transition` | 1 | 0.003 | 0 | 0.000 | -0.003 | 0.000 | 232.24 | 232.24 |
| `first+recovery+state_transition` | 12 | 0.035 | 0 | 0.000 | -0.035 | 0.000 | 240.34 | 668.17 |

#### `agg_suppression`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `forwarded_only` | 340 | 0.986 | 34 | 1.000 | 0.015 | 0.100 | 351.19 | 883.64 |
| `some_suppressed` | 5 | 0.015 | 0 | 0.000 | -0.015 | 0.000 | 235.88 | 582.75 |

#### `onset_band`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `0-99s` | 41 | 0.119 | 0 | 0.000 | -0.119 | 0.000 | 62.77 | 146.21 |
| `100-199s` | 54 | 0.157 | 0 | 0.000 | -0.157 | 0.000 | 127.33 | 187.16 |
| `200-299s` | 50 | 0.145 | 0 | 0.000 | -0.145 | 0.000 | 224.14 | 284.62 |
| `300-399s` | 46 | 0.133 | 0 | 0.000 | -0.133 | 0.000 | 334.40 | 416.77 |
| `400-499s` | 51 | 0.148 | 0 | 0.000 | -0.148 | 0.000 | 489.28 | 659.13 |
| `500-599s` | 57 | 0.165 | 1 | 0.029 | -0.136 | 0.018 | 704.70 | 806.72 |
| `600-699s` | 39 | 0.113 | 26 | 0.765 | 0.652 | 0.667 | 876.99 | 976.01 |
| `700-799s` | 7 | 0.020 | 7 | 0.206 | 0.186 | 1.000 | 1,039.93 | 1,058.03 |

#### `cohorts_before_verdict`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `1` | 67 | 0.194 | 0 | 0.000 | -0.194 | 0.000 | 88.20 | 159.31 |
| `10+` | 100 | 0.290 | 34 | 1.000 | 0.710 | 0.340 | 760.43 | 976.01 |
| `2` | 62 | 0.180 | 0 | 0.000 | -0.180 | 0.000 | 176.87 | 234.50 |
| `3` | 17 | 0.049 | 0 | 0.000 | -0.049 | 0.000 | 250.47 | 273.93 |
| `4` | 24 | 0.070 | 0 | 0.000 | -0.070 | 0.000 | 299.10 | 335.13 |
| `5` | 34 | 0.099 | 0 | 0.000 | -0.099 | 0.000 | 405.85 | 446.25 |
| `6` | 7 | 0.020 | 0 | 0.000 | -0.020 | 0.000 | 447.68 | 463.44 |
| `7` | 18 | 0.052 | 0 | 0.000 | -0.052 | 0.000 | 494.32 | 531.50 |
| `9` | 16 | 0.046 | 0 | 0.000 | -0.046 | 0.000 | 598.83 | 639.36 |

#### `component_size`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `1` | 78 | 0.226 | 2 | 0.059 | -0.167 | 0.026 | 336.01 | 742.20 |
| `17-64` | 18 | 0.052 | 0 | 0.000 | -0.052 | 0.000 | 213.29 | 668.17 |
| `2-4` | 247 | 0.716 | 32 | 0.941 | 0.225 | 0.130 | 412.80 | 891.82 |
| `5-16` | 2 | 0.006 | 0 | 0.000 | -0.006 | 0.000 | 115.13 | 157.41 |

## time_to_useful

**Not classified.** every story is CENSORED for this timing — there is no tail to classify (step 1's structural finding, not a failure here) (censored 345 of 345).

## time_to_stable

n = 345 scored (0 censored). Tail = above the overall p90 = **876.99 s**.

### Top 5 dimensions by tail concentration

Ordered by the dominance test first, then by **excess** (tail share − story share). Raw tail share is shown but is NOT the ordering: a dimension with one bucket holds 100 % of the tail for free.

| rank | dimension | top bucket | tail share | story share | excess | lift | dominates? |
|--:|---|---|--:|--:|--:|--:|---|
| 1 | `onset_band` | `600-699s` | 0.559 | 0.113 | 0.446 | 4.94 | **YES** |
| 2 | `cohorts_before_verdict` | `10+` | 0.765 | 0.290 | 0.475 | 2.64 | no |
| 3 | `truth_vantage_count` | `2` | 0.647 | 0.333 | 0.314 | 1.94 | no |
| 4 | `seam_type` | `wan_transport` | 0.647 | 0.391 | 0.256 | 1.65 | no |
| 5 | `component_size` | `2-4` | 0.941 | 0.716 | 0.225 | 1.31 | no |

**A small identity class DOES dominate this timing's tail:** `onset_band` (> 50% of the tail in < 25% of the stories).

### Onset-band check (the 5k clue)

| population | n | need | tightest window (80%) | width |
|---|--:|--:|---|--:|
| all stories | 345 | 276 | 49.4 – 555.8 s | 506.4 s |
| tail stories | 34 | 28 | 276.5 – 739.8 s | 463.3 s |

### Every measurable dimension, bucket by bucket

#### `seam_type`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `lan_access` | 150 | 0.435 | 12 | 0.353 | -0.082 | 0.080 | 429.13 | 880.93 |
| `lan_core` | 60 | 0.174 | 0 | 0.000 | -0.174 | 0.000 | 275.39 | 659.13 |
| `wan_transport` | 135 | 0.391 | 22 | 0.647 | 0.256 | 0.163 | 411.98 | 1,458.08 |

#### `template`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `bgp_peer_flap` | 100 | 0.290 | 14 | 0.412 | 0.122 | 0.140 | 427.71 | 975.84 |
| `enterprise_outage` | 15 | 0.043 | 8 | 0.235 | 0.192 | 0.533 | 1,450.18 | 1,992.14 |
| `local_link_fault` | 150 | 0.435 | 12 | 0.353 | -0.082 | 0.080 | 429.13 | 880.93 |
| `ospf_adjacency_flap` | 60 | 0.174 | 0 | 0.000 | -0.174 | 0.000 | 275.39 | 659.13 |
| `upstream_link_failure` | 20 | 0.058 | 0 | 0.000 | -0.058 | 0.000 | 156.37 | 487.56 |

#### `engine_evidence_size`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `1-4` | 320 | 0.927 | 30 | 0.882 | -0.045 | 0.094 | 393.83 | 891.82 |
| `17-64` | 18 | 0.052 | 0 | 0.000 | -0.052 | 0.000 | 156.37 | 584.22 |
| `5-16` | 7 | 0.020 | 4 | 0.118 | 0.097 | 0.571 | 1,636.47 | 1,903.77 |

#### `blast_wave_depth`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `1` | 310 | 0.899 | 26 | 0.765 | -0.134 | 0.084 | 382.93 | 890.52 |
| `2` | 15 | 0.043 | 8 | 0.235 | 0.192 | 0.533 | 1,450.18 | 1,992.14 |
| `3` | 20 | 0.058 | 0 | 0.000 | -0.058 | 0.000 | 156.37 | 487.56 |

#### `affected_devices`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `1` | 210 | 0.609 | 12 | 0.353 | -0.256 | 0.057 | 378.15 | 877.46 |
| `2` | 100 | 0.290 | 14 | 0.412 | 0.122 | 0.140 | 427.71 | 975.84 |
| `25-39` | 20 | 0.058 | 0 | 0.000 | -0.058 | 0.000 | 156.37 | 487.56 |
| `40+` | 15 | 0.043 | 8 | 0.235 | 0.192 | 0.533 | 1,450.18 | 1,992.14 |

#### `modality_count`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `1` | 345 | 1.000 | 34 | 1.000 | 0.000 | 0.099 | 384.04 | 952.29 |

#### `observer_count`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `1` | 228 | 0.661 | 20 | 0.588 | -0.073 | 0.088 | 401.81 | 891.21 |
| `10+` | 18 | 0.052 | 0 | 0.000 | -0.052 | 0.000 | 156.37 | 584.22 |
| `2` | 98 | 0.284 | 14 | 0.412 | 0.128 | 0.143 | 419.36 | 982.82 |
| `3-9` | 1 | 0.003 | 0 | 0.000 | -0.003 | 0.000 | 46.82 | 46.82 |

#### `truth_vantage_count`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `1` | 210 | 0.609 | 12 | 0.353 | -0.256 | 0.057 | 378.15 | 877.46 |
| `10+` | 20 | 0.058 | 0 | 0.000 | -0.058 | 0.000 | 156.37 | 487.56 |
| `2` | 115 | 0.333 | 22 | 0.647 | 0.314 | 0.191 | 447.68 | 1,636.47 |

#### `hyp_satisfied_count`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `2` | 64 | 0.185 | 1 | 0.029 | -0.156 | 0.016 | 302.78 | 676.98 |
| `3` | 2 | 0.006 | 1 | 0.029 | 0.024 | 0.500 | 662.99 | 1,450.18 |
| `4` | 101 | 0.293 | 14 | 0.412 | 0.119 | 0.139 | 431.35 | 975.84 |
| `7` | 153 | 0.444 | 14 | 0.412 | -0.032 | 0.091 | 434.11 | 883.36 |
| `8` | 25 | 0.072 | 4 | 0.118 | 0.045 | 0.160 | 219.22 | 1,902.00 |

#### `candidate_count`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `1-4` | 66 | 0.191 | 2 | 0.059 | -0.133 | 0.030 | 325.94 | 728.68 |
| `13-17` | 178 | 0.516 | 18 | 0.529 | 0.013 | 0.101 | 411.98 | 891.82 |
| `5-8` | 101 | 0.293 | 14 | 0.412 | 0.119 | 0.139 | 431.35 | 975.84 |

#### `evidence_recurrence`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `first` | 308 | 0.893 | 29 | 0.853 | -0.040 | 0.094 | 378.15 | 891.82 |
| `first+recovery` | 24 | 0.070 | 1 | 0.029 | -0.040 | 0.042 | 443.57 | 742.20 |
| `first+recovery+repeat+state_transition` | 1 | 0.003 | 1 | 0.029 | 0.026 | 1.000 | 1,902.00 | 1,902.00 |
| `first+recovery+state_transition` | 12 | 0.035 | 3 | 0.088 | 0.053 | 0.250 | 362.05 | 1,903.77 |

#### `agg_suppression`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `forwarded_only` | 340 | 0.986 | 30 | 0.882 | -0.103 | 0.088 | 382.25 | 891.21 |
| `some_suppressed` | 5 | 0.015 | 4 | 0.118 | 0.103 | 0.800 | 1,897.98 | 1,903.77 |

#### `onset_band`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `0-99s` | 41 | 0.119 | 2 | 0.059 | -0.060 | 0.049 | 62.77 | 163.98 |
| `100-199s` | 54 | 0.157 | 1 | 0.029 | -0.127 | 0.018 | 122.75 | 174.00 |
| `200-299s` | 50 | 0.145 | 4 | 0.118 | -0.027 | 0.080 | 220.14 | 1,902.00 |
| `300-399s` | 46 | 0.133 | 1 | 0.029 | -0.104 | 0.022 | 336.01 | 436.37 |
| `400-499s` | 51 | 0.148 | 0 | 0.000 | -0.148 | 0.000 | 487.56 | 659.13 |
| `500-599s` | 57 | 0.165 | 0 | 0.000 | -0.165 | 0.000 | 704.70 | 806.72 |
| `600-699s` | 39 | 0.113 | 19 | 0.559 | 0.446 | 0.487 | 876.99 | 976.01 |
| `700-799s` | 7 | 0.020 | 7 | 0.206 | 0.186 | 1.000 | 1,039.93 | 1,058.03 |

#### `cohorts_before_verdict`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `1` | 67 | 0.194 | 1 | 0.029 | -0.165 | 0.015 | 74.41 | 162.10 |
| `10+` | 100 | 0.290 | 26 | 0.765 | 0.475 | 0.260 | 760.43 | 976.01 |
| `2` | 62 | 0.180 | 3 | 0.088 | -0.091 | 0.048 | 176.83 | 246.59 |
| `3` | 17 | 0.049 | 3 | 0.088 | 0.039 | 0.176 | 253.94 | 1,903.77 |
| `4` | 24 | 0.070 | 1 | 0.029 | -0.040 | 0.042 | 299.10 | 437.97 |
| `5` | 34 | 0.099 | 0 | 0.000 | -0.099 | 0.000 | 405.85 | 446.25 |
| `6` | 7 | 0.020 | 0 | 0.000 | -0.020 | 0.000 | 443.81 | 463.44 |
| `7` | 18 | 0.052 | 0 | 0.000 | -0.052 | 0.000 | 491.62 | 529.37 |
| `9` | 16 | 0.046 | 0 | 0.000 | -0.046 | 0.000 | 598.83 | 639.36 |

#### `component_size`

| bucket | stories | story share | tail | tail share | excess | tail rate | p50 s | p95 s |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `1` | 78 | 0.226 | 1 | 0.029 | -0.197 | 0.013 | 351.19 | 779.12 |
| `17-64` | 18 | 0.052 | 0 | 0.000 | -0.052 | 0.000 | 156.37 | 584.22 |
| `2-4` | 247 | 0.716 | 32 | 0.941 | 0.225 | 0.130 | 432.39 | 975.84 |
| `5-16` | 2 | 0.006 | 1 | 0.029 | 0.024 | 0.500 | 46.82 | 1,636.47 |

## Caveats (they travel with every number above)

* The timings are READ from step 1's ttur-useful.tsv, not re-measured: this tool classifies the published measurement rather than a second one.
* Engine-side dimensions are sampled AT THE STORY'S FIRST CANDIDATE (the state at the moment the latency ends). Run-maximum variants are emitted as diagnostics and are never used as buckets.
* A story whose dimension has no value gets the explicit bucket "NA". NA is reported with its counts and is EXCLUDED from the concentration test — an unmeasured story must never look like a small identity class.
* The tail is defined per timing as "above the overall p90 of that timing", over that timing's NON-CENSORED stories only. A fully censored timing (time_to_useful on the V1 syslog-only workload) yields no tail and is reported as such, never as an empty win.
* Percentiles are NEAREST-RANK (step 1's `pct`, imported), so a bucket of n<20 has a p95 that is one story. Bucket n travels with every number.
* Dimensions are RANKED by EXCESS (a bucket's tail share minus its story share), not by raw tail share: a dimension with only one bucket holds 100 % of the tail by construction and explains nothing. Raw tail share is reported beside it.
* Correlation, not causation: a bucket that holds the tail is where the latency IS, not proof of why. The row asks to NAME the contributor before optimizing, and that is all this tool does.
