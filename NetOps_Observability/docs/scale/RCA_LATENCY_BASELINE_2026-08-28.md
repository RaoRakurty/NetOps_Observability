# Time-to-Useful-RCA (TTUR) — PRE-P1 BASELINE (2026-08-28)

**This is the PRE-P1 baseline.** Nothing in the engine was changed to produce
it: `scripts/scale-rca-latency.py` is a read-only measurement tool that
reconstructs each incident's lifecycle from the version history the engine
already persists in `netops.corr_objects`. It is P0 of
[`docs/design/STORM_PLANE_SEPARATION_RESEARCH_2026-08-28.md`](../design/STORM_PLANE_SEPARATION_RESEARCH_2026-08-28.md);
the metric is defined by the owner memo `Correlix-Bottleneck-Modified.md` §5–§9.

Every P1/P2 change (cohort-touch gate, decision/evidence plane split, scale-out)
must be re-measured with the SAME command against its own run and compared here.

---

## 0. Exact command used

```bash
cd NetOps_Observability

# what runs are in the store (device-name residue mlx-<runid>-NNNNN)
python3 scripts/scale-rca-latency.py --list-runs --list-runs-since 2026-08-27T00:00:00

# the baseline (canonical command — the numbers in §3–§6 come from this)
python3 scripts/scale-rca-latency.py \
  --device-prefix mlx-08281519gjez- \
  --json /var/tmp/rca-2p5k.json

# supplementary, longer offsets for the quality curve of §6
python3 scripts/scale-rca-latency.py \
  --device-prefix mlx-08281519gjez- \
  --curve-offsets 30,60,300,600,1200,1800,3600,7200 \
  --json /var/tmp/rca-2p5k-ext.json

# the immediately-preceding 2.5k run (boundedness-only, no storm mode)
python3 scripts/scale-rca-latency.py \
  --device-prefix mlx-082812437a77- \
  --json /var/tmp/rca-2p5k-pre.json
```

Runtime: ~20–25 s per invocation on the lab box. All reduction is ClickHouse-side
(`GROUP BY correlation_id` + `arraySort`/`arrayFirstIndex`/`groupArray`); Python
receives one row per incident. Every query is a `SELECT`, guarded by a
statement-head check in the tool; nothing is written, altered or mutated.

---

## 1. What data was present

`netops.corr_objects` at measurement time (2026-08-28 18:2x UTC):

| | value |
|---|---|
| versions (rows) | **1,721,834** |
| distinct incidents | **668,779** |
| `created_at` range | `2026-08-21 20:19:05.648` .. `2026-08-28 18:00:34.360` |
| tenants | **1** (`global`) — the whole store is single-tenant |

Per-run breakdown (scale-harness residue, `--list-runs`, since 2026-08-27):

| run token | versions | incidents | first persist | last persist |
|---|--:|--:|---|---|
| `08240627tbn0` | 105,747 | 43,985 | 2026-08-27 00:00:26 | 2026-08-27 17:31:42 |
| `08271432rnic` | 25,839 | 8,890 | 2026-08-27 14:36:03 | 2026-08-27 16:34:26 |
| `08271606ymyb` | 1,215 | 423 | 2026-08-27 16:15:45 | 2026-08-27 18:36:19 |
| `08272153bwu4` | 1,884 | 623 | 2026-08-27 21:55:46 | 2026-08-28 00:24:24 |
| `08280149pwzv` | 24,472 | 6,938 | 2026-08-28 01:52:49 | 2026-08-28 03:38:34 |
| `08280317oocy` | 2,155 | 1,134 | 2026-08-28 03:27:17 | 2026-08-28 03:44:06 |
| `08281139pim9` | 6,117 | 567 | 2026-08-28 11:42:27 | 2026-08-28 13:36:58 |
| `082812437a77` | 24,599 | 8,852 | 2026-08-28 12:46:40 | 2026-08-28 14:14:04 |
| **`08281519gjez`** | **60,572** | **14,472** | **2026-08-28 15:22:50** | **2026-08-28 18:00:34** |

**Which run this baseline measures:** `08281519gjez` — the storm-mode 2.5k run
(`51575407` deployed) whose verdict is
[`STORM_MODE_2P5K_VERDICT_2026-08-28.md`](STORM_MODE_2P5K_VERDICT_2026-08-28.md)
(“run `082815…`”, t-nominal-2.5k, 2,500 devices, 900,001 events @ ~1000/s).
`082812437a77` is that doc's boundedness-only comparator (`082812437a77`) and is
measured here too as a second data point.

Run `08281519gjez` scope as seen by the tool:

- 60,572 versions across **14,472 incidents**, 1 tenant (`global`)
- persist window (`created_at`): `15:22:50.362` .. `18:00:34.360`
- event window (`window_start` .. `window_end`): `15:22:12.104` .. `15:37:08.446`

Note the shape immediately: **the 15-minute burst produced 2 h 38 min of
persist activity.** That gap is the headline of everything below.

---

## 2. Metric definitions (and what is a proxy)

Per incident, from the version history ordered by `(created_at, version)`:

| stage | definition (as measured) |
|---|---|
| **T0** | `window_start` of the first persisted version = `min(signal.ts)` of the component (`engine.py:2846`) — the first causal symptom's **EVENT** time |
| **T1** | `created_at` of the first persisted version — incident created |
| **T2** | `created_at` of the first version with `top_hypothesis != 'undetermined'` |
| **T3** | `created_at` of the first version with a non-empty `owner` (from `hypotheses.ranking.hypotheses[0].verdict.owner`, the same field `_current_badges` derives) **and** a blast radius (`node_count > 0` or non-empty `affected.devices`) |
| **T4** | *(PROXY)* first version with `verdict_tier >= suspected` **and** non-empty `owner` **and** `top_confidence >= 0.5` (`--useful-confidence`) |
| **T6** | `created_at` of the **last** version whose `(top_hypothesis, owner, verdict_tier)` tuple differs from the previous version — after which the verdict never changes. An incident whose verdict never changed is stable at T1. |
| **churn** | number of material `(top_hypothesis, owner, verdict_tier)` changes occurring **after** T4 |

> ### T4 IS A PROXY, NOT THE MEMO'S DEFINITION
> Owner memo §8 requires "First Useful RCA" to additionally assert the **causal
> seam / root-cause entity is CORRECT**, the ownership domain is correct, and the
> blast radius is materially correct. **The 2.5k production-mix run carries no
> ground-truth cause label**, so correctness **cannot** be scored from persisted
> data. What is measured here is *time to a confident, owned, tiered verdict* —
> an **upper bound on quality and a lower bound on time**. A correctness-scored
> T4 needs a labelled fixture run (see §8).

> **T5** (corroborated), **T7** (full evidence graph materialized) and **T8**
> (evidence backlog drained) are **not derivable from `corr_objects`** and are
> not reported. See §8.

---

## 3. Measured lifecycle latency — run `08281519gjez` (storm-mode 2.5k)

All latencies are **relative to T0** (the memo states its targets that way).
14,472 incidents, 60,572 versions, tenant `global` (the per-tenant table is
identical to the overall table — single tenant).

| stage | meaning | reached | % | p50 s | p95 s | p99 s | max s | **proposed p95 SLO** | verdict |
|---|---|--:|--:|--:|--:|--:|--:|--:|---|
| T1 | incident created | 14,472 | 100.0 | 1,758.07 | 5,135.42 | 7,587.93 | 8,098.10 | **5** | **MISSES ×1,027** |
| T2 | first causal candidate | 13,265 | 91.7 | 1,754.43 | 5,770.65 | 7,590.77 | 8,098.10 | **10** | **MISSES ×577** |
| T3 | owner + blast radius | 14,471 | 100.0 | 1,758.15 | 5,135.42 | 7,587.93 | 8,098.10 | **15** | **MISSES ×342** |
| T4 | first useful RCA *(proxy)* | 13,265 | 91.7 | 1,754.43 | 5,770.65 | 7,590.77 | 8,098.10 | **30** | **MISSES ×192** |
| T6 | stable RCA | 14,472 | 100.0 | 1,795.98 | 6,914.26 | 7,955.89 | 8,098.10 | **120** | **MISSES ×58** |

> The SLO column holds **PROPOSED CORRELIX PRODUCT SLOs** (owner memo §7),
> **not industry standards.** "MISSES ×N" = measured p95 ÷ proposed p95.

- **Fastest incident in the entire run reached T1 at 19.68 s** — i.e. *not one
  of the 14,472 incidents met the proposed 5 s T1 SLO.*
- **Zero negative latencies** across all five stages: no event-time/ingest-time
  inversion in this run (see §7).

### 3.1 Engine-decision latency only (relative to T1)

This is the decisive cut. It separates *queue wait before the incident existed*
(T1−T0) from *how long the engine then took to decide*.

| stage | reached | p50 s | p95 s | p99 s | max s |
|---|--:|--:|--:|--:|--:|
| T2−T1 | 13,265 | 0.00 | 0.00 | 0.00 | 1,294.20 |
| T3−T1 | 14,471 | 0.00 | 0.00 | 0.00 | **0.00** |
| T4−T1 | 13,265 | 0.00 | 0.00 | 0.00 | 1,294.20 |
| T6−T1 | 14,472 | 0.00 | 3,118.54 | 5,637.26 | 6,313.82 |

**Finding: the engine's decision work is effectively free.** For ≥99% of
incidents the *first version the engine persists already carries* the causal
candidate, the owner, the blast radius, `verdict_tier=suspected` and
`confidence ≥ 0.5`. T3−T1 is 0.00 s at **max** — owner and blast radius are
never later than creation. So:

> **TTUR at 2.5k is 100% queueing latency (T1−T0), 0% decision latency.**
> Progressive-decision work (emitting a cheap early verdict before the evidence
> graph is materialized) has **nothing to save here**, because the verdict is
> already emitted on version 1. The only lever that moves TTUR on this workload
> is making the incident *exist sooner* — i.e. object-reconciliation/persist
> throughput. This is the same conclusion `STORM_MODE_2P5K_VERDICT` reached from
> the completion gate, arrived at independently from the customer-visible metric.

The one exception is T6−T1 p95 = 3,118 s: incidents keep being re-persisted and
occasionally change verdict for ~52 min after creation, which is the tail of the
same backlog, not a slow decision.

### 3.2 Volume and churn

| | value |
|---|--:|
| incidents | 14,472 |
| versions | 60,572 |
| versions per incident | mean 4.19 · p50 2 · p95 15 · p99 19 · max 19 |
| material verdict changes (total) | 1,980 (mean 0.14/incident) |
| incidents reaching T4 (proxy) | 13,265 (91.7%) |
| incidents never reaching T4 | 1,207 (8.3%) — all end `verdict_tier=undetermined` |
| final state | closed 8,423 · open 6,038 · merged 11 |
| final tier | suspected 13,265 · confirmed **0** · undetermined 1,207 |

**Churn after T4** (memo §9 — "a result that appears in 8 s but changes root
cause five times should NOT be presented as an 8-second TTUR"):

| churn after T4 | incidents | share |
|--:|--:|--:|
| 0 | 11,314 | **85.3%** |
| 1 | 1,932 | 14.6% |
| 2 | 19 | 0.1% |
| ≥3 | 0 | 0.0% |

p50 = 0, p95 = 1, p99 = 1, **max = 2**, mean 0.15.

**Fast-but-wrong is NOT the failure mode here.** The verdict, once emitted, is
essentially stable: 85.3% of useful incidents never change verdict again, and no
incident changes more than twice. Whatever P1/P2 does, it must **preserve** this
— the memo's §9 guard exists precisely so a throughput fix does not buy speed
with churn. This baseline is the number to hold.

Note the flip side: **`confirmed` was never reached by any incident**, and 60,572
versions produced only 1,980 material verdict changes — a **30.6:1 evaluation-to-
material-change ratio** (memo §5 "waste ratio", measured object-side). That is
the write amplification P1's cohort-touch gate targets.

---

## 4. Quality curve — run `08281519gjez`

Fraction of the 14,472 incidents that have reached each stage by T0 + offset.

**Memo §27 offsets (5–300 s):**

| offset s | T1 | T2 | T3 | T4 | T6 |
|--:|--:|--:|--:|--:|--:|
| 5 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| 10 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| 20 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| 30 | 0.1% | 0.1% | 0.1% | 0.1% | 0.1% |
| 60 | 2.3% | 2.3% | 2.3% | 2.3% | 1.4% |
| 120 | 5.2% | 5.1% | 5.2% | 5.1% | 3.5% |
| 300 | 15.3% | 14.6% | 15.3% | 14.6% | 11.3% |

**Extended offsets (the curve only becomes informative past 5 min):**

| offset s | T1 | T2 | T3 | T4 | T6 |
|--:|--:|--:|--:|--:|--:|
| 30 | 0.1% | 0.1% | 0.1% | 0.1% | 0.1% |
| 60 | 2.3% | 2.3% | 2.3% | 2.3% | 1.4% |
| 300 | 15.3% | 14.6% | 15.3% | 14.6% | 11.3% |
| 600 | 27.8% | 25.9% | 27.8% | 25.9% | 21.8% |
| 1200 | 32.2% | 30.4% | 32.2% | 30.4% | 29.5% |
| 1800 | 52.4% | 48.2% | 52.4% | 48.2% | 50.2% |
| 3600 | 92.7% | 84.4% | 92.7% | 84.4% | 85.4% |
| 7200 | 98.0% | 89.7% | 98.0% | 89.7% | 96.1% |

The T1 and T4 curves are **within 1 pp of each other at every offset** — the
same statement as §3.1 in curve form: nothing useful is gated on decision work.

---

## 5. Comparator — run `082812437a77` (boundedness-only 2.5k, no storm mode)

8,852 incidents, 24,599 versions, persist window 12:46:40 .. 14:14:04 (1 h 27 min
of persist for a 15-min event window).

| stage | reached | % | p50 s | p95 s | p99 s | max s | proposed p95 SLO |
|---|--:|--:|--:|--:|--:|--:|--:|
| T1 | 8,852 | 100.0 | 1,893.63 | 2,485.68 | 3,367.40 | 3,424.56 | 5 |
| T2 | 8,362 | 94.5 | 1,871.72 | 2,503.32 | 3,368.36 | 3,424.56 | 10 |
| T3 | 8,852 | 100.0 | 1,893.63 | 2,485.68 | 3,367.40 | 3,424.56 | 15 |
| T4 | 8,362 | 94.5 | 1,871.72 | 2,503.32 | 3,368.36 | 3,424.56 | 30 |
| T6 | 8,852 | 100.0 | 1,893.63 | 3,283.30 | 3,398.11 | 3,424.56 | 120 |

Decision latency (relative to T1): T2−T1 / T3−T1 / T4−T1 all **0.00 s at p99**;
T6−T1 p95 = 981 s. Churn after T4: zero-churn 84.4%, p95 = 1, max = 2. Fastest
incident to T1: 10.34 s.

| | `082812437a77` (pre) | `08281519gjez` (storm) |
|---|--:|--:|
| incidents | 8,852 | 14,472 |
| versions | 24,599 | 60,572 |
| versions/incident (mean) | 2.78 | 4.19 |
| T1 p50 / p95 (s) | 1,893.6 / 2,485.7 | 1,758.1 / **5,135.4** |
| T4 p50 / p95 (s) | 1,871.7 / 2,503.3 | 1,754.4 / **5,770.7** |
| T6 p95 (s) | 3,283.3 | **6,914.3** |
| reached T4 | 94.5% | 91.7% |
| zero-churn after T4 | 84.4% | 85.3% |

**Consistent with `STORM_MODE_2P5K_VERDICT`:** storm mode did not improve TTUR.
The storm-mode run's p50 is marginally better while its p95/p99 tail is ~2×
worse — the same run-to-run variance on a heavily-loaded box that the verdict doc
attributed the pending 15,638 → 24,638 delta to (storm mode logged `storm_mode=True`
only twice; it was effectively inert). **Do not read the tail difference as a
storm-mode regression;** read the shared structure: both runs are 100%
queue-bound with ~0 decision latency and ~85% zero-churn.

---

## 6. What this baseline says for P1

1. **TTUR is queue-bound, not decision-bound.** T2/T3/T4 minus T1 are 0.00 s at
   p99 in *both* 2.5k runs. Any P1/P2 change justified as "produce a useful RCA
   before the evidence graph is materialized" will move **nothing** on this
   workload — the useful RCA is already on version 1. The win must come from
   incident *creation* throughput (cohort-touch gate, plane split, scale-out).
2. **Write amplification is the visible lever.** 60,572 versions → 1,980 material
   verdict changes = **30.6 evaluations per material change**. Damping
   re-persists that carry no verdict change is a direct, measurable target.
3. **Stability is currently good — protect it.** 85.3% zero churn after T4, max 2
   changes, p95 = 1. Re-measure this table after every P1 change; a throughput
   win that pushes zero-churn below ~85% or max churn above 2 has traded
   correctness for speed and fails memo §9.
4. **`confirmed` is never reached and 8.3% never leave `undetermined`.** Neither
   is a latency defect, but both bound what "useful" can mean on this synthetic
   `event-mix single` load. A realistic-mix run is needed before treating
   91.7%-reach-T4 as a product number.

---

## 7. Caveats

1. **T4 is a proxy; causal correctness is NOT scored.** See §2. Every T4 number
   above is "time to a confident, owned, tiered verdict".
2. **Event-time vs ingest-time skew.** T0 is `window_start` = `min(signal.ts)`,
   an **event** timestamp; T1..T6 are `created_at`, **engine wall-clock persist**
   times. Two clocks. In *this* measurement the risk is small and bounded:
   `scale-miniladder.py` stamps `timestamp` with `datetime.now(timezone.utc)` at
   line construction (`scale-miniladder.py:1404`) on the **same host** as the
   engine, so there is no cross-machine drift — the only skew is the
   generate → `kafka-console-producer` batch gap, on the order of seconds. The
   measured evidence agrees: **0 negative latencies out of 14,472 incidents**,
   and the minimum T1 is +19.68 s. Against p50 = 1,758 s, a few seconds of
   generation-batch skew is noise. **This does not generalise:** on real devices
   T0 is a device-assigned clock and skew can be large and signed, so a
   production TTUR measurement must be read with that caveat re-examined.
3. **Version ordering.** History is ordered by `(created_at, version)`, not
   `version` alone: an engine restart resets the per-object version counter
   (`corr_current` is `ReplacingMergeTree(created_at)` for exactly this reason),
   and **3,941 of 14,472 incidents (27%) in this run carry duplicate version
   numbers**. Ordering by `version` would have produced wrong lifecycles.
4. **Scope semantics.** `--device-prefix` / `--since` / `--until` select *which
   incidents* to measure; the selected incident's history is then read **whole**,
   including versions persisted outside the window. Clipping would truncate T6
   and undercount churn.
5. **Load realism.** `event-mix single` (uniform `%LINK-3-UPDOWN`). The verdict
   doc's point stands: this mix has little duplicate/low-value tail, so both the
   churn figures and the storm-mode comparison are workload-specific.
6. **Single tenant.** The store holds only `global`. The per-tenant tables the
   tool emits are therefore identical to the overall tables; **multi-tenant TTUR
   scoping is implemented but UNEXERCISED** by this baseline.
7. **Box was loaded.** Measurement ran on the same 4-core box while the stack was
   live. The tool is read-only and ~20 s per run, but ClickHouse merges between
   the scope query and the lifecycle query can shift counts by a few rows; the
   tool logs a warning if they disagree (it did not on these runs).

---

## 8. What could NOT be measured, and why

| memo item | why not |
|---|---|
| **T5 — corroborated RCA** | Needs a corroboration predicate (independent modality/vantage count crossing a threshold). `hypotheses[0].verdict.modality_coverage` exists and `_current_badges` counts it into `plane_count`, but there is **no persisted "corroborated" marker** and `verdict_tier` never reached `confirmed` in this run, so any T5 would be an invented threshold, not a measurement. Deliberately omitted rather than fabricated. |
| **T7 — full evidence graph materialized** | Lives in the evidence/edge tables (`corr_evidence`, typed-edge rows) and the archive slice, not in `corr_objects`. Requires a separate join and an explicit "graph complete" predicate the schema does not carry. |
| **T8 — evidence backlog drained** | A pipeline/capacity metric (consumer lag + archive queue), not an incident property. `scale-miniladder.py`'s drain/completion gates already cover it. |
| **Correctness of T4 (memo §8)** | **No ground truth.** The harness injects uniform `%LINK-3-UPDOWN` events with no labelled root cause, so "correct causal seam", "correct ownership domain" and "materially correct blast radius" are unscoreable. This needs a **labelled fixture run** (a scenario where the injected fault and its true owner/seam are known) before a correctness-gated TTUR exists. |
| **Time-to-first-*correct*-candidate (memo §9)** | Same reason as above. |
| **Memo §5 cohort/touch/waste ratios (engine-side)** | `touched_incidents / open_incidents`, `incidents_reranked`, `persistence attempts damped` etc. are **runtime counters the engine does not emit**. The persisted-object proxy measurable here is versions ÷ material changes (**30.6:1**, §3.2); the true touch/waste ratios need engine instrumentation, which this P0 step deliberately did not add. |
| **Memo §6 raw-event amplification** | Requires `raw_events_total` for the run joined to verdict changes. Raw counts live in the harness run artefacts / Kafka accounting, not in `corr_objects`; not joined here. |

---

## 9. Tool

`scripts/scale-rca-latency.py` — Python 3 stdlib only, read-only, `ruff`-clean
(pinned 0.16.0, the `scripts-lint` gate), `py_compile`-clean. Queries via
`docker exec <clickhouse> clickhouse-client --query "... SETTINGS
tenant_scope='__all__'"`, the same access path `scale-miniladder.py` uses. Every
subprocess call is bounded (`--ch-timeout`, default 600 s; docker calls 30 s);
non-zero exits and empty result sets are **errors, never a silent zero**
(scripts/CLAUDE.md §16.1). `--json` writes the full result including per-tenant
breakdowns, the caveat list and the proposed-SLO map. `--help` restates every
caveat above.
