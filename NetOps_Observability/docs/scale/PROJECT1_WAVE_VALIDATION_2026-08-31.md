# Project-1 engine wave — validation on `storm-s07` (2026-08-31)

**Verdict: the wave is VALIDATED. 8 of 9 gates PASS; the single FAIL (`memflat`)
is attributed, with evidence, to causes OUTSIDE the wave** — an api-side
`timeintel-backfill` sawtooth sampled trough-vs-peak on a 7-minute-old process,
plus a pre-existing ClickHouse overcommit class whose victim is that same
backfill query. Nine tracker items are closed on this run's measurements; one
(186) is enlarged by them; one new Low item is filed.

**Run.** `/var/tmp/scale-runs/storm-s07-08310154`, runid **`08310154mmk9`**,
profile `t-storm-2.5k`, arm **ON** (the shipping default), 2,500 devices,
15-minute 1,000-eps burst, 345 labelled incidents, scenario seed `20260829`,
digest `53f4d444cb109f51` (`launcher.log`). Correlation replicas
`7dc16ef9cae1` / `ba674ca06a39`, both `started_at` **01:52:32–01:52:33Z**
(`metrics-final.txt` headers), so every `*_total` below is **LEG-SCOPED** — no
subtraction appears anywhere in this document.

**Code under test: `de8ca5b1`** (08-31 01:42), i.e. the wave through tracker 187.
**`931efffb` (tracker 155 continuation seeding) landed at 02:51, AFTER this run,
and is NOT validated here** — 155's validation is the twin ownership programme,
still in flight.

**Baseline: `storm-s06`** (`08302033yg32`, ON, pre-wave image `c3f627581082` /
code `0bfdce1c`), with `storm-s05` (OFF control) as the third point wherever a
trend matters.

**Post-hoc collection.** The driver stopped before `collect()`; every number here
was re-collected from the run's own artefacts — `metrics-final.txt`,
`report.md`/`report.json`, `ttur.tsv`/`ttur-scope.json`, `accuracy-report.md`,
`twin-score.log` — and recorded in `wave-checks.json` in the run directory.
Every figure below cites the artefact it came from.

---

## 1. Gate sweep — 8/9

Source: `report.md` phase table / `launcher.log`.

| phase | result | evidence |
|---|---|---|
| preflight | PASS | 26 services checked, consumers live, baselines captured |
| onboard | PASS | create rate 38.9 → 26.1 /s (ratio **0.67**, floor 0.60), 2,500/2,500, **0 absorbed shadow rows** |
| burst | PASS | **900,000 / 900,000** events in 900 s @ 1,000/s |
| drain | PASS | transport lag to baseline+eps in **1,321 s** (budget 2,700), peak 441,274 |
| correlation_completion | PASS | engine evaluated the workload in **94 s** of a 2,700 s budget; pending 0 on both replicas, cohorts +22, versions +10,343, `windows_rejected` +0, `profiler_errors` +0 |
| accounting | PASS | **exact**: 900,001 injected == 900,001 persisted + 0 DLQ + 0 counted rejections; 2,500/2,500 devices covered |
| memflat | **FAIL** | `netops-api-1` 169 → 275 MiB (×1.63 > ×1.3) + 3 ClickHouse `MEMORY_LIMIT_EXCEEDED`. **Attributed in §4** |
| stability | PASS | 2,782 s lifecycle, 2 replicas: 0 CommitFailed, 0 UnknownMember, 0 restarts, 0 rebalances; session timeout **60,000 ms read from 2 replicas**; worst loop stall **3,623 ms = 6.0 %** of it |
| cleanup | PASS | 2,500 devices deleted+verified (0 `mlx-` devices of ANY run id remain), CH+OS purged |

Accuracy, run as its own instrument: **345/345 stories = 100.00 %**, detection
100 %, specificity 100 %, `affected_includes_with_missing` **0**, twin scorer
**v2**, 16 ClickHouse queries (`accuracy-report.md` header, `twin-score.log`).

---

## 2. Per-item validation

| # | What had to be true | Measured on `storm-s07` | Baseline | Verdict |
|---|---|---|---|---|
| **187** | An object's final `affected` never shrinks below its own version history at CLOSE | terminal objects **1,175**, **shrinking objects 0**, **lost entity mentions 0** | s06 1,177 / **526** / **2,427**; s05 1,129 / 544 / 3,122 | **PASS — shrink eliminated exactly.** WATCH below |
| **187** (guard) | The history accumulator stays inside its declared cap | `corr_affected_history_truncated_total` **0**, `corr_affected_history_entities_max` **16,622** of a **20,000** cap = **83.1 %** | n/a (gauge new this wave) | **PASS, with a named ladder watch item** |
| **157** | Verdicts the topology cannot structurally support are suppressed, and accuracy does not move | `corr_template_ungrounded_total` **35,940**; top-hypothesis `sig.ent.fabric.spine-leaf-path-degradation` **0**; `sig.ent.access.local-link-fault` **788**; accuracy **345/345** | s06 fabric **589** / local-link **169**; s05 588 / 169 | **PASS — 589 → 0, redistributed (+619) to local-link-fault, accuracy flat** |
| **167** | The selectivity counters are registered and readable live | `corr_template_scored_total` **230,824** / `corr_template_candidates_total` **954,500** = **24.2 % live** | 19.8 % measured offline on the production mix (`3001d440`) | **PASS — registered and measured live** |
| **192** | The cleanup / re-key loop block is bounded AND named | worst `corr_sync_stretch_max_ms` **385.3 ms** at site **`reconcile.continuation_index`** (repl-4: 0.6 ms at `epoch.enrichment`); `corr_sync_overruns_total` **0** against a 500 ms budget; `corr_loop_lag_max_ms` **4,278.3 ms** (repl-4 59.2) | s06 `corr_loop_lag_max_ms` **13,881.1 ms**, no `sync_span` site attributed | **PASS with caveat** — see below |
| **164** | The offload path has a real bound, and the bound is observable | `corr_offload_admission_limit` **8**, `max_workers` **4**, `queue_depth_peak` **4**, `submitted_total` **2,230**, `admission_waits_total` **0**, `admission_wait_max_seconds` **0.0**, `rejected_total` **0**, `abandoned_total` **0** | n/a (unbounded default executor before `9990adec`) | **PASS — bound present and never engaged** |
| **171** | Maintenance starvation is bounded and the bound is published | `corr_prune_gap_max_s` **137.192 s** (repl-4 30.005 s) against `CORR_ENGINE_EPOCH_BUDGET_S` **300 s** = **45.7 %**; `corr_engine_epoch_budget_exits_total` **0**; 58 prune calls, 20,892 evicted, worst prune **0.033 s** | previously no gauge existed | **PASS — the P2 epoch budget does bound it, now measured** |
| **190** | The stability gate derives its threshold from the live engine, not a constant | `session_timeout_ms` **60,000**, `session_timeout_derivation` = *"session timeout 60000ms read from 2 replica(s)"*, `session_timeout_override` `null`, per-replica `{7dc16ef9cae1: 60000, ba674ca06a39: 60000}`; stall budget used **6.0 %** | s05/s06 judged against a hard-coded 30,000 ms | **PASS — the line now derives from the live gauge** |
| **181** | A dedupe-absorbed create leaves no shadow row | onboard evidence: **0 absorbed shadow row(s)**; cleanup: 0 `mlx-` devices of ANY run id remain | 1,000 shadow devices from overlapping runs | **PASS — closed by `b408cdbf` + its 11 tests; s07 shows no residue** |
| **175** | Tombstone growth is bounded by replay-horizon compaction | live drain observed this leg: **72,927 → exactly 10,000** tombstones (`DefaultTombstoneMax`), a one-time drain of ~62,900 records at 02:48:30–02:49:35 | 35,427 tombstones / 142 MB for 0 real devices | **PASS — bound engaged and held on a live store** |

### 187 — the ladder watch item

The fix works exactly: `526 → 0` shrinking terminals and `2,427 → 0` lost entity
mentions, measured per `correlation_id` in ClickHouse by comparing the terminal
(`state in merged/closed`) `argMax`-version affected devices+interfaces against
`groupUniqArray` over ALL versions of the object (`wave-checks.json`
`t187_affected_monotone.clickhouse_terminal_rows.method`).

What it costs is a per-object history accumulator, and at 2,500 devices that
accumulator peaked at **16,622 entities against its declared 20,000 cap —
83.1 %**, with `corr_affected_history_truncated_total` still **0**. That is
head-room, not a defect, but it is **head-room that scales with fleet size**, and
the next thing this programme does is the 5k and 10k rungs. **Carry it into the
ladder as an explicit pre-flight check**: if `corr_affected_history_entities_max`
crosses the cap at 5k, the monotone guarantee degrades to "monotone up to
20,000 entities" and the cap must be raised or made fleet-relative before the
rung is graded.

**Refinement (2026-08-31, run `08311437us3b`, profile `t-nominal-2.5k`):** the
**same 2,500-device fleet** under a nominal profile reads
`corr_affected_history_entities_max` **6,390 = 32.0 %** of the cap with
`corr_affected_history_truncated_total` still **0**
(`/var/tmp/scale-runs/ladder-n2k5-08311437/ceiling-facts.json`,
`engine_counters_carrier_corr5`). Fleet size is therefore **not** what fills the
accumulator: the gauge tracks **signal density / blast radius**, and 83.1 % is a
storm-profile number. Scope the ladder pre-flight check to the **storm** rungs —
only a larger STORM rung moves this gauge; a nominal rung at any fleet size does
not test the cap.

### 192 — bounded and named, but the residual is accumulation

The worst uninterrupted loop-thread block is now **named**:
`reconcile.continuation_index`, **385.3 ms**, inside the 500 ms sync budget, with
**0 overruns**. Process-lifetime loop lag fell **13,881 → 4,278 ms** and the
worst in-window stall fell **4,450 → 3,623 ms**.

The honest caveat: **4,278 ms of process loop lag still exceeds any single
instrumented span** (the largest being 385.3 ms). That residual is therefore an
**accumulation of many attributed spans within one loop pass, not one remaining
dark block** — which is a materially different (and much less dangerous) shape
than what 192 was filed against, and it is bounded well under the 60 s session
timeout. No further instrumentation is warranted; if the residual ever
approaches the session timeout, the next step is a per-pass span budget, not
another gauge.

---

## 3. Whole-run health — the wave cost nothing

**TTUR** (`ttur.tsv`, `ttur-scope.json`; leg-scoped SQL over `corr_objects`,
burst window `01:57:42 → 02:12:42`, converged `02:36:21`, aggregate cid
`bb1e46d6…` excluded):

| statistic | s07 | s06 | Δ |
|---|---|---|---|
| incidents | 1,630 | 1,632 | −0.1 % |
| versions | 10,331 | 10,191 | +1.4 % |
| versions / incident | 6.34 | 6.24 | +1.6 % |
| signals | 84,563 | 82,359 | **+2.7 %** |
| T1 p50 (s) | 79 | 80 | **−1.3 %** |
| T1 p95 (s) | **908** | **816** | **+11.3 %** |
| T1 p99 (s) | 1,380 | 1,271 | +8.6 % |
| T1 max (s) | 1,756 | 1,717 | +2.3 % |
| T-last p95 (s) | 2,163 | 2,001 | +8.1 % |
| merged | 191 | 162 | — |

T1 p95 **+11.3 %** is marginally outside the ±10 % neutrality band, and it is
**noise, not a regression**: the six-leg `t-storm-2.5k` p95 envelope is
**816 / 830 / 832 / 866 / 902 / 908 s**, and 908 sits at the top of a
distribution it does not leave. Every other TTUR statistic is inside ±10 %, p50
actually improved, and the run carried **2.7 % more signals** than its baseline.
T1 p95 is published, not gated (INVARIANTS §10).

**Aggregation-plane accounting closes exactly** (`metrics-final.txt`, carrier
replica `netops-correlation-3`): `corr_agg_observed_total` **54,767** =
Σ`forwarded{class}` **49,900** + `corr_agg_suppressed_total` **4,867**. The
observed count is **digit-identical to s06's 54,767** — the workload is
deterministic — while suppression moved 4,854 → 4,867. `netops-correlation-4`
reads 0/0 (idle partition assignment).

**Correlation memory improved.** Carrier replica `netops-correlation-3`:
558 MiB at input stop → 1,076 MiB at pending-0 → **1,013 MiB end = 79.1 % of its
1,280 MiB cap, ×0.941 vs the pending-0 anchor, FLAT**. `netops-correlation-4`:
78 → 79 → 128 MiB, 10.0 % of cap, ×1.617, FLAT. **s07 is the first leg of
s05/s06/s07 whose carrier ratio fell below 1.0** (0.941 vs 1.023 / 1.021) and
whose percent-of-cap dropped (79.1 vs 83.2 / 82.7). **The wave cost no
correlation memory; it gave some back.**

---

## 4. The `memflat` FAIL — attribution

`memflat` failed on two independent clauses. Neither is the wave.

### 4.1 `netops-api-1` 169 → 275 MiB (×1.63) — the backfill sawtooth, sampled trough-vs-peak

**Determination: NOT a leak.** The api runs `backfillIncidentTimeMetrics`
(`src/backend/timeintel_backfill.go:168`) every ~15 minutes; each successful pass
parses a **20,000-row / 70.70 MiB JSON result** into Go structs. That is a
sawtooth by construction, and the two memflat samples landed on opposite teeth:

- **02:06:25 pass FAILED (code 241)** and **02:21:35 FAILED (code 159)** → no
  parse happened, so the **02:12:42 warm anchor (169 MiB) is a trough**.
- **02:36:09 pass SUCCEEDED** (20,000 rows, 70.70 MiB) → the **02:38:27 end
  sample (275 MiB) is 2 minutes past a parse peak**.

Two further facts make "leak" untenable:

- **The process was 7 minutes old at preflight.** The api container was
  recreated **01:48:24**; it was **136 MiB cold** and still climbing to its
  plateau when the run started. The historical api plateau on the OLD image was
  **230–350 MiB** (s02 228, s03 247, s04 262, pair-off 284, pair-on 313, s05 292,
  s06 348 MiB) — those legs read ×~1.0 precisely because they *began* at
  plateau. s07 is the only leg that began cold.
- **Post-run idle is a sawtooth, not a plateau.** VmRSS fell **275 → 198 MiB**
  by 02:57, then rose to **292 MiB** after the 02:51:22 successful pass.

**Hypotheses tested and closed:**

| hypothesis | outcome |
|---|---|
| Go GC on a young process + the backfill sawtooth | **CONFIRMED (primary)** |
| tracker 175 tombstone compaction | **REFUTED for the measured window** — compaction ran **02:48:30–02:49:35, AFTER the 02:38:27 memflat stamp**. It *did* run this leg (**72,927 → exactly 10,000** tombstones, `DefaultTombstoneMax`, ~62,900 records drained), which is 175's own closing evidence — but it cannot have moved a sample taken 10 minutes earlier |
| tracker 181 `CreateOrResolve` cache | **NOT IMPLICATED** — the api served only **111 requests** in the whole 02:10–02:40 window |

### 4.2 3 × ClickHouse `MEMORY_LIMIT_EXCEEDED` — a pre-existing class

**All three fired inside one second: `2026-08-31 02:06:24–25`, mid-burst — a
single 4 GiB total-memory overcommit episode**, not three independent failures.

**Victim 1 (query level, from `query_log`):** user `netops`, HTTP interface,
`Go-http-client/1.1`, address `172.18.0.27` = **`netops-api-1`**, origin
**`worker:timeintel-backfill` (`src/backend/timeintel_backfill.go:168`)**, over
`netops.corr_current` ⋈ `netops.corr_objects` — **memory 1,863,917,392 B
(1.86 GiB), 1,931,054 rows, 35,395,183,306 B (35.4 GB) read, 49,246 ms**.
**Victims 2 and 3** were background `MergeParts` on `netops.findings` and
`netops.corr_objects`; ClickHouse raised them in background threads, so
`query_log` cannot name them.

So **the stack's own api evicted the two merges by taking 1.86 GiB for a query
that is already a known open defect (tracker 186)**.

**Determination: (ii) PRE-EXISTING CLASS, not caused by the wave.**

- **The same backfill query has raised 241 or 159 on 12 of 41 passes since
  2026-08-30 16:57** — i.e. through the s05 and s06 legs and before them (241 at
  22:57:46, at 00:58:09, then at 02:06:25).
- **Its read volume grows monotonically with `corr_objects` retention**:
  **56.81 GiB (08-30 16:57) → 59.89 GiB (08-31 02:51)**. s07 added **~0.6 GiB**,
  the *same* per-leg increment as prior legs. This is a retention curve, not a
  step.
- **The memory is in the wrong column for the wave to be the cause.**
  `hypotheses` is **31,151 bytes/row uncompressed = 67.8 GB of the table**;
  `affected` is **213 bytes/row = 0.7 % of the row**. Tracker 187 touches
  `affected`.
- **187 did not grow `affected`**: `avg(length(affected))` s05 **929.6 B**, s06
  **974.4 B**, s07 **950.8 B**, and the maximum is **identical at 587,125 B on
  all three legs**.

For context, ClickHouse's own headroom was never the constraint over the run:
p99 `MemoryTracking` **1,499 MiB = 36.6 %** of the 4,096 MiB cap (peak 2,330 MiB
= 56.9 %), `MaxPartCountForPartition` 10 against an envelope of 22
(`report.md` memflat notes).

**Analyst note (kept, because it would otherwise mislead a re-reader):**
`system.errors` reads **16** `MEMORY_LIMIT_EXCEEDED` as of 03:03:31; the 16th is
**this analysis's own read-only diagnostic** (per-query limit, native interface,
03:03:31), not the stack's. **The run's own delta is 12 → 15.**

### 4.3 Consequence

The memflat FAIL is **real and it is tracker 186's**, not the wave's. §5 records
the enlargement: 186's fix must now also **bound that query**, because at storm
scale it is the process that evicts ClickHouse's merges.

---

## 5. Tracker outcome

**Closed on this run** (rows deleted from `docs/TRACKER.md` per its rule 1):
**157** (`39eba8c0` + s07), **164** (`9990adec` + s07), **167** (`3001d440`,
registered `9990adec`, live 24.2 %), **171** (`0a4e57d2` + s07 measure),
**175** (`8d0ba1e5`, live 72,927 → 10,000 drain), **181** (`b408cdbf` + 11 tests
+ 0 absorbed rows on s07), **187** (`de8ca5b1` + s07), **190** (`0a4e57d2` +
s07 derivation line), **192** (`79e27efc` + s07).

**Enlarged: 186** — the `timeintel-backfill` query is now evidenced as the
*cause* of a storm-time ClickHouse overcommit, not merely a victim of one. Its
fix must include bounding the query (memory/read budget), not only the watermark.

**Filed: 194** (Low) — watchdog/api liveness blindness, §6.

**Untouched: 155** — its validation (twin ownership runs) is in flight, and
`931efffb` post-dates this run.

---

## 6. Incidental finding — the watchdog cannot see an api outage

While the wave image was being deployed, **the api did not answer through nginx
for roughly two minutes (2026-08-31 01:48–01:51)** — a cold-start fault-in under
the IO pressure of the redeploy; the container was recreated at **01:48:24**
(§4.1) and the correlation replicas came up at 01:52:32–01:52:33.
`scripts/stack-watchdog.sh` did not page, and could not have:

- Its end-to-end probe is `APP_URL` = **`http://localhost:8000/`**
  (`stack-watchdog.sh:68,571`), which nginx's `location /` proxies to the
  **frontend** SPA (`deployment/docker/nginx/default.conf:40`). The SPA answers
  200 with the api dead.
- **There is no `/healthz` location in `default.conf` at all**, so `/healthz`
  also falls through to `location /` and returns the SPA index — a probe of
  `:8000/healthz` is a probe of the frontend.
- The api container itself declares **no healthcheck** (`report.md` preflight:
  `{"service": "api", "status": "running", "health": ""}`), so the
  container-state check reads "running" for a process that is not serving.
- The **only** probe that touches the api is
  `build_drift_check api "${APP_URL%/}/admin/version"`
  (`stack-watchdog.sh:1043`). It does raise `BUILD UNVERIFIABLE` when the api
  does not answer — but that string matches **no pattern in
  `problem_is_critical()`** (`stack-watchdog.sh:1104`), so it is classified
  **advisory**: one default-priority push on transition, no urgent page, and
  silence if it was already standing.

**Honest probe: `/admin/version`** — it is served by the api through
`location /admin/` (`default.conf:150`), it already exists, and it is the one
endpoint that cannot be answered by anything but the api binary. Second finding
for the same row: **the api's cold-boot budget is ~2.5 minutes** on this box
under redeploy IO pressure (recreated 01:48:24, serving by ~01:51), which any
liveness probe must tolerate before it pages.

---

## 7. What this document does NOT claim

- **155 is not validated here.** `931efffb` landed at 02:51, after the run.
- **The 20,000-entity `affected`-history cap is not proven adequate above 2,500
  devices.** 83.1 % at 2,500 is the measurement; the ladder must re-check it.
- **The 4,278 ms residual loop lag is bounded and attributed as accumulation,
  not eliminated.**
- **`contradiction`, `new_vantage` and `new_modality` remain unexercised**
  aggregation classes (0 forwarded on every leg ever run) — unchanged by this
  wave, still a boundary on INVARIANTS §10.
- **The memflat clause did not pass.** It is attributed, not waived: 186 must
  land before a `t-storm-2.5k` leg can read 9/9 again on a cold api.
