# P3 Aggregation plane — live 2.5K A/B verdict (2026-08-29/30 wave)

> **VERDICT — all five legs collected.** The 10 %, 25 % and 2 % rungs each have
> both arms; L5 (the 2 % neutrality guard) landed 2026-08-30 06:20Z, and L0b's
> missing TTUR row and twin score were recovered from surviving ClickHouse
> evidence so the guard has the two OFF baselines §1 of the run plan requires.
> The decision rule (`docs/scale/RUN_PLAN_P3_AB_2026-08-29.md` §7) is applied
> literally in §3.
>
> **Outcome: `CORR_AGGREGATION_PLANE` does NOT become default ON.** Criterion 2
> is met with margin; criteria 1 and 3 fail at the 2 % rung. The flag stays
> OFF-by-default and the plane stays opt-in. §3.5 records the one additional
> measurement that would settle whether those two failures are the plane's or
> the rig's — as a **recommendation only; nothing was run for it.**
>
> Executes `docs/scale/RUN_PLAN_P3_AB_2026-08-29.md`; projection column from
> `docs/design/AGGREGATION_PLANE_P3_2026-08-29.md` §6b. Every caveat from the
> draft is retained in §4 and three were added.

---

## 1. Scope, image and leg identity

**One image for both arms.** A single `netops-correlation` image, id
`000e7bc3…`, built 21:46Z on 2026-08-29 — i.e. *before* the OFF arm was
switched in — carried every leg of this wave. Both arm switches were
`docker compose up -d --no-deps --force-recreate --scale correlation=2
correlation` with **no build**: the OFF arm is the overlay file's absence, the
ON arm adds `-f compose.agg.yml`. Source: `docs/scale/RESUME_BRIEF_2026-08-28.md`
UPDATE 2026-08-30 03:20Z ("Image parity VERIFIED"). The code sha inside that
image is `12074157` (P3 steps 1–3, flag OFF by default, + the lifecycle index
fix) — `docs/scale/STORM_S03_2P5K_VERDICT_2026-08-29.md` §Verdict. The two
post-wave engine fixes (`2852ad6f`: tracker 188 + 185 part 3) are **committed
and NOT deployed**, deliberately, so both arms share one image
(`RESUME_BRIEF_2026-08-28.md` UPDATE 2026-08-30 00:40Z).

| leg | run dir | runid | profile | arm | replicas at run (container / started_at) | status |
|---|---|---|---|---|---|---|
| L0a | `/var/tmp/scale-runs/storm-s02-08291929` | `08291929iqtm` | `t-storm-2.5k` | OFF | corr-3 `be08cfe50bb8` 19:27:37Z · corr-4 `143e8533f1ee` 19:27:38Z — **replica-4** carried the tenant (window signals 22,917 vs 7,822) | 8/9 (stability FAIL) |
| L0b | `/var/tmp/scale-runs/storm-s03-08292148` | `08292148kdz4` | `t-storm-2.5k` | OFF | corr-3 `cb969ae44891` 21:46:43Z · corr-4 `a678b9a2f942` 21:46:44Z — **replica-3** carried the tenant (31,167 vs 3,503) | 7/9 (accounting + stability FAIL) |
| L1 | `/var/tmp/scale-runs/agg-10-off-08292249` | `0829224959gv` | `t-storm-10-2.5k` | OFF | corr-3 `ac4977f8efe9` 22:43:28Z · corr-4 `cd8ce6063716` 22:43:29Z | **PASS 9/9** |
| L2 | `/var/tmp/scale-runs/agg-25-off-08300014` | `083000149rrs` | `t-storm-25-2.5k` | OFF | same two containers as L1 | **FAIL 6/9 — INCOMPLETE** |
| L3 | `/var/tmp/scale-runs/agg-10-on-08300221` | `08300221w0jg` | `t-storm-10-2.5k` | **ON** | corr-4 `db5a31b7d5a0` 02:21:18Z · corr-3 `1ce6206d8751` 02:21:20Z | **PASS 9/9** |
| L4 | `/var/tmp/scale-runs/agg-25-on-08300356` | `08300356hdmy` | `t-storm-25-2.5k` | **ON** | same two containers as L3 — corr-4 `db5a31b7d5a0` 02:21:18Z · corr-3 `1ce6206d8751` 02:21:20Z | **8/9 — `memflat` FAIL only** |
| L5 | `/var/tmp/scale-runs/agg-2p5k-on-08300516` | `08300516wqrl` | `t-storm-2.5k` | **ON** | **same two containers as L3 and L4** — corr-4 `db5a31b7d5a0` 02:21:18Z · corr-3 `1ce6206d8751` 02:21:20Z; replica-4 carried the tenant (26,616 vs 2,389) | **FAIL 5/9** — onboard, accounting, memflat, stability |

Arm verification is recorded per leg in `<run-dir>/ab-leg.json`
(`arm_verification[]` + `metrics[]`, both read over mTLS `:8443/metrics`):
L1 — `env` null on both, `corr_agg_enabled 0.0` on both. L2 — `env` null on
both, `corr_agg_enabled 0.0` on both. L3, L4 **and L5** — `env "1"` on both,
`corr_agg_enabled 1.0` on both. **No leg in this wave is a mixed arm.**
(L0a and L0b predate the A/B driver and have no `ab-leg.json`; they are OFF by
construction — the overlay file did not exist in the deployment at their run
time. Their container ids and carriers above are read from their own
`report.json` `correlation_completion.final.per_replica`.)

Note for every derived counter in this document: L2 ran on the same containers
as L1, and **L4 and L5 both ran on the same containers as L3** (`db5a31b7d5a0` /
`1ce6206d8751`, started 02:21Z, carried all three ON legs). `corr_*` counters
are monotonic since process start, so the leg-attributable value is *this leg's
capture minus the previous leg's capture on the same container* — L2 = its
capture − L1's, L4 = its capture − L3's, **L5 = its capture − L4's**. L4's
`correlation_completion` baseline reads `versions_persisted` 6,961 — exactly
L3's final value — and L5's reads 16,403, exactly L4's final value: both
independently confirm the carry-over. Gauges (`corr_agg_keys`,
`corr_agg_identities`) and running maxima (`corr_open_objects_epoch_peak`,
`corr_engine_pending_peak`, `corr_loop_lag_max_ms`) are **never** subtracted —
they are reported as-is with that label.

**Three consecutive legs on one container is itself a confound**, and L5 is the
third. It is carried through §2.3, §3.1, §3.3 and caveat 11 rather than netted
out.

*Sources: `<run-dir>/ab-leg.json` for every leg listed; image/sha lines as cited
above.*

---

## 2. Per-rung tables

### 2.1 10 % rung — `t-storm-10-2.5k` — L1 (OFF) vs L3 (ON) — **BOTH ARMS COLLECTED**

Identical scenario on both legs: `storm-10-2.5k`, seed 20260829, shape digest
`d8bf0d5bc872fc77`, target storm share 10.00 % / achieved 10.00 % (+0.0 %),
58,421 promoted / 31,589 unpromotable in the scenario plane, K3 unique 19,124
(67.3 % collapse), chunk peak/mean 2,237/1,000.11 (2.237×), burst
900,000/900,000 @ 1,000/s.

| metric | OFF (L1) | ON (L3) | §6b projection | Δ |
|---|--:|--:|--:|--:|
| **signals reaching the engine** | **98,636** (promoted count) | **58,194** (Σ `corr_agg_forwarded_total{class}`) | 98,635 → 63,382 (−36 %) | **−40,442 = −41.0 %** |
| — `corr_agg_observed_total` | 0 (plane off) | 98,636 | — | — |
| — `corr_agg_suppressed_total` | 0 | 40,442 (41.0 % of observed) | — | — |
| — forwarded `first` | 0 | 43,290 | — | — |
| — forwarded `state_transition` | 0 | 4,934 | — | — |
| — forwarded `recovery` | 0 | 8,802 | — | — |
| — forwarded `count_threshold` | 0 | 1,129 | — | — |
| — forwarded `repeat` | 0 | 39 | — | — |
| — forwarded `contradiction` / `new_vantage` / `new_modality` | 0 | 0 / 0 / 0 | — | never fired |
| engine signals inside correlated incidents (`ttur.tsv sigs`) | 94,942 | 76,680 | — | −18,262 = −19.2 % |
| completion (s) | 170 | 130 | — | −40 s (−23.5 %) |
| transport drain (s; peak lag) | 2,550 (512,566) | 1,745 (455,710) | — | −805 s (−31.6 %) |
| T1 p50 (s) | 434 | 282 | — | −152 s (−35.0 %) |
| T1 p95 (s) | 2,763 | 1,985 | — | −778 s (−28.2 %) |
| T1 p99 (s) | 3,063 | 2,224 | — | −839 s (−27.4 %) |
| T1 max (s) | 3,210 | 2,390 | — | −820 s |
| T-last p95 (s) | 3,273 | 2,426 | — | −847 s (−25.9 %) |
| accuracy (stories pass) | 903/1005 = **89.85 %** | 899/1005 = **89.45 %** | — | **−0.40 pp** |
| positive-story pass / specificity | 89.85 % / 100 % | 89.45 % / 100 % | — | −0.40 pp / flat |
| `corr_agg_evicted_total` | 0 | 18,138 (expired 18,041 + ident_expired 97; capacity/ident_capacity/tenant_capacity 0) | — | — |
| `corr_stream_time_evictions_total` | 41,012 | 23,441 | — | −17,571 = −42.8 % |
| incidents / versions / v-per-inc | 1,274 / 5,168 / 4.06 | 1,371 / 6,701 / 4.89 | — | +97 / +1,533 / +0.83 |
| merged / undetermined / confirmed | 73 / 0 / 0 | 85 / 0 / 0 | — | — |
| gate FAILs | 0 (9/9 PASS) | 0 (9/9 PASS) | — | **none new** |

Harness phase verdicts, both legs 9/9 PASS: preflight · onboard (ratio 0.71 →
0.65, floor 0.6) · burst 900,000/900,000 @ 1,000/s · drain · correlation
completion · accounting **balanced exactly** (900,001 injected == 900,001
persisted + 0 DLQ + 0 counted rejections; 2,500/2,500 devices covered) ·
memflat (9/9 containers; correlation-4 949 → 935 MiB ×0.986 on L1, 1,053 →
1,015 MiB ×0.964 on L3) · stability (0 CommitFailed, 0 UnknownMember, **0
restarts**; lifecycle 4,123 s → 3,294 s; worst loop stall 9,174 ms → 10,575 ms) ·
cleanup (0 `mlx-` devices remain — **residue 0** on both).

Engine counters at convergence, storm replica (idle replica all 0 unless shown):
cohorts 30 → 26 · epochs 67 → 53 · `corr_versions{persisted}` 7,384 → 6,961,
`{damped}` 4,071 → 3,239, `{heartbeat_touch}` 479 → 305 ·
`corr_engine_windows_rejected_total` **0 → 0** ·
`corr_signals_dropped_total{reason="window_rejected"}` **0 → 0** (that is the
only `reason` label present in either file) · `corr_edge_cache_dropped_total`
163,279 → 162,994 · `corr_open_objects_epoch_peak` 1,007 → 1,076 ·
`corr_engine_pending_peak` 5,483 → 3,191 · `corr_lifecycle_passes_total` 66 → 53
(idle replica 181 → 142) · `corr_loop_lag_max_ms` 9,174.0 → 10,574.7 ·
`corr_loop_lag_stalls_total` 982 → 328. Plane-internal on L3: `corr_agg_keys`
37,766, `corr_agg_identities` 18,714, `corr_agg_state_transitions_total` 13,736,
`corr_agg_recoveries_total` 8,802, `corr_agg_late_forwarded_total` 39,
`corr_agg_beyond_lateness_total` 0.

Per-template FAIL distribution (all 1,005 stories are `positive`; there are no
negative-control rows in either report, so specificity 1.0 is reported over an
empty negative set):

| template | stories | FAIL OFF (L1) | FAIL ON (L3) |
|---|--:|--:|--:|
| `local_link_fault` | 437 | 3 | 4 |
| `bgp_peer_flap` | 291 | 11 | 14 |
| `ospf_adjacency_flap` | 175 | 4 | **0** |
| `upstream_link_failure` | 58 | 45 | 46 |
| `enterprise_outage` | 44 | 39 | 42 |
| **total** | **1005** | **102** | **106** |

The two chained templates (`upstream_link_failure`, `enterprise_outage`) carry
84/102 and 88/106 of the failures on the respective legs — the same
`affected_includes` gap tracker 187 records for the OFF baselines, not a
plane-induced regression.

**Measured vs projected — stated explicitly.** §6b projected the plane would
leave **63,382** of 98,635 promoted signals (−36 %). The live plane forwarded
**58,194** of 98,636 (−41.0 %): **5,188 fewer signals than projected, 5.3 pp
more reduction than the projection's upper bound on removal.** Accounting inside
the plane is exact (98,636 observed = 58,194 forwarded + 40,442 suppressed), and
`corr_agg_state_transitions_total` 13,736 against forwarded `state_transition`
4,934 says where the extra removal comes from: transitions that fold inside a
single 60 s bucket rather than being forwarded synchronously, which is precisely
the assumption the §6b upper bound holds fixed. This is a finding about the
classifier's transition handling and is carried forward as an open question for
the equivalence review — it is not a rounding error and must not be reported as
one. (For corroboration, the harness's own in-run fleet-level projection for
this rung, `report.json` `…/shape/achieved/stream_projection`, is 98,273 →
65,155 = −33.7 %, i.e. the same direction of gap.)

**Replica coverage on L3 — reported honestly.** Only ONE replica has non-zero
`corr_agg_*`: `netops-correlation-4` (`db5a31b7d5a0`) with observed 98,636;
`netops-correlation-3` (`1ce6206d8751`) reports observed 0.0. This is **not** a
mixed arm and the leg is **not** void. Evidence: (a) both replicas report
`CORR_AGGREGATION_PLANE=1` from `env` and `corr_agg_enabled 1` from the metrics
endpoint (`ab-leg.json`); (b) replica-3 received **no storm traffic at all** —
`corr_ingest_events{counter="syslog_received"} 0`, `syslog_signals 0`,
`syslog_prefilter_passed 0`, `syslog_prefilter_rejected 0`, and every engine
counter 0 (cohorts 0, epochs from idle lifecycle only, versions 0,
`open_objects_epoch_peak` 0, `stream_time_evictions` 0, `edge_cache_dropped` 0),
so there was nothing for the plane to observe; (c) the identical asymmetry is
present on the OFF leg L1, where replica-3 saw `syslog_received` 30 /
`syslog_signals` 0 while replica-4 saw 910,943 / 98,636; (d) both replicas own
24 partitions with `corr_consumer_zero_assignments_total` 0 and
`corr_consumer_cold_partitions` 0 — assignment is even, the *keys* are not. The
single tenant's storm partitions land on one replica: the "one replica carries
the tenant" behaviour the P2 verdicts already record. Replica-4 carried it on
BOTH legs, so the 10 % A/B is a same-replica comparison.

*Sources: `/var/tmp/scale-runs/agg-10-off-08292249/{ab-leg.json, ttur.tsv,
ttur-scope.json, metrics-final.txt, report.md, report.json, accuracy-report.md,
accuracy-report.json, launcher.log}` and the same file set under
`/var/tmp/scale-runs/agg-10-on-08300221/`; projection from
`docs/design/AGGREGATION_PLANE_P3_2026-08-29.md` §6b.*

---

### 2.2 25 % rung — `t-storm-25-2.5k` — L2 (OFF, **INCOMPLETE**) vs L4 (ON) — **BOTH ARMS COLLECTED**

Identical scenario on both legs: `storm-25-2.5k`, seed 20260829, shape digest
`8b4f1943e5eda129`, target storm share 25.00 % / achieved 24.52 % (−1.9 %),
138,689 promoted / 81,957 unpromotable in the scenario plane, K3 unique 32,719
(76.4 % collapse), chunk peak/mean 4,789/2,451.62 (1.953×), burst
900,000/900,000 @ 1,000/s.

**L2 is a valid OFF reading of an overloaded system, not a clean baseline.** The
engine never finished: 78,663 signals still pending at the 2,700 s cap. Its
T1/T-last percentiles and its twin score are scoped to the subset that *did*
complete and are therefore optimistic. **The TTUR rows below are directional
only at this rung.** The decisive comparison here is not a percentile delta but
completion itself — INCOMPLETE → **PASS at 192 s** — and accuracy **81 % → 89 %**,
both of which move in the direction that an optimistic-by-construction OFF leg
makes *harder*, not easier, to achieve.

*Counter arithmetic:* every cell marked *(derived)* is this leg's capture minus
the previous leg's capture on the **same container** (L2 = its capture − L1's;
L4 = its capture − L3's), per the note in §1.

| metric | OFF (L2, INCOMPLETE) | ON (L4) | §6b projection | Δ |
|---|--:|--:|--:|--:|
| **signals reaching the engine** | **172,453** *(derived: `syslog_prefilter_passed` 271,089 − 98,636)* | **72,293** (Σ `corr_agg_forwarded_total{class}`; *derived*: 130,487 − 58,194) | 172,452 → 76,819 (−56 %) | **−100,160 = −58.1 %** |
| — `corr_agg_observed_total` | 0 (plane off) | 172,453 *(derived: 271,089 − 98,636)* | — | — |
| — `corr_agg_suppressed_total` | 0 | 100,160 *(derived)* = 58.1 % of observed | — | — |
| — forwarded `first` | 0 | 50,694 *(93,984 − 43,290)* | — | — |
| — forwarded `state_transition` | 0 | 5,989 *(10,923 − 4,934)* | — | — |
| — forwarded `recovery` | 0 | 11,622 *(20,424 − 8,802)* | — | — |
| — forwarded `count_threshold` | 0 | 3,919 *(5,048 − 1,129)* | — | — |
| — forwarded `repeat` | 0 | 69 *(108 − 39)* | — | — |
| — forwarded `contradiction` / `new_vantage` / `new_modality` | 0 | 0 / 0 / 0 | — | never fired |
| engine signals inside correlated incidents (`ttur.tsv sigs`) | 113,361 | 84,826 | — | −28,535 = **−25.2 %** |
| completion (s) | **INCOMPLETE** — pending 78,663 at the 2,700 s cap, oldest pending age 430 s, cohorts +38, versions persisted +19,767 | **192 s** PASS (budget 2,700; pending 0 on both replicas, cohorts +27, versions persisted +9,369) | — | **FAIL → PASS** |
| transport drain (s; peak lag) | **FAIL** — never reached baseline+eps in 2,700 s (peak 580,968, final 124,868) | **2,263 s** PASS (peak 493,697, final 12) | — | **FAIL → PASS**; peak lag −15.0 % |
| T1 p50 (s) *(L2 directional)* | 1,833 | 317 | — | −1,516 s (−82.7 %) |
| T1 p95 (s) *(L2 directional)* | 3,750 | 2,655 | — | −1,095 s (−29.2 %) |
| T1 p99 (s) *(L2 directional)* | 4,491 | 2,795 | — | −1,696 s (−37.8 %) |
| T1 max (s) *(L2 directional)* | 5,858 | 2,908 | — | −2,950 s (−50.4 %) |
| T-last p95 (s) *(L2 directional)* | 5,493 | 3,062 | — | −2,431 s (−44.3 %) |
| accuracy (stories pass) | 1,438/1,773 = **81.11 %** | 1,579/1,773 = **89.06 %** | — | **+7.95 pp** |
| positive-story pass / specificity | 81 % / 100 % *(empty negative set)* | 89 % / 100 % *(empty negative set)* | — | +7.95 pp / flat |
| `corr_agg_evicted_total` | 0 (plane off) | 57,526 *(derived)*: expired 57,270 + ident_expired 256; capacity / ident_capacity / tenant_capacity 0 | — | — |
| `corr_stream_time_evictions_total` | **124,803** *(derived: 165,815 − 41,012)* | **62,208** *(derived: 85,649 − 23,441)* | — | −62,595 = −50.2 % |
| `corr_open_objects_epoch_peak` | 4,097 | 1,869 | — | −2,228 (running max on each container) |
| `corr_engine_pending_peak` | **90,663** | **5,815** | — | −84,848 (running max) |
| incidents / versions / v-per-inc | 6,370 / 16,602 / 2.61 | 1,431 / 6,507 / 4.55 | — | −4,939 / −10,095 / +1.94 |
| merged / undetermined / confirmed | 313 / **949** / 0 | 113 / **1** / 0 | — | undetermined −948 |
| gate FAILs | **3** — drain, correlation_completion, memflat | **1** — memflat | — | **−2; no phase that PASSed on L2 FAILs on L4** |

Harness phase verdicts. **L2 — 6/9:** preflight PASS · onboard PASS (0.84) ·
burst PASS 900,000/900,000 · **drain FAIL** · **correlation_completion FAIL
(INCOMPLETE)** · accounting **PASS, balanced exactly** (900,001 == 900,001 + 0
DLQ + 0 rejections; 2,500/2,500 devices) · **memflat FAIL** —
`netops-correlation-4` *LEAK SLOPE UNKNOWN* because `corr_engine_pending` never
reached 0 on that replica (rss 968 MiB at input stop → 1,072 MiB end, 83.8 % of
the 1,280 MiB cap, **no pending-0 anchor**), replica-3 flat 112 → 134 MiB ·
stability **PASS** (0 CommitFailed, 0 UnknownMember, **0 restarts**, worst loop
stall 14,036 ms, 1,440 stalls, lifecycle 6,717 s) · cleanup PASS, **residue 0**.
**L4 — 8/9:** preflight PASS · onboard PASS (0.75) · burst PASS 900,000/900,000
@ 1,000/s · **drain PASS 2,263 s** · **correlation_completion PASS 192 s**
(`windows_rejected` +0, `profiler_errors` +0) · accounting **PASS, balanced
exactly** (900,001 == 900,001 + 0 DLQ + 0 rejections; 2,500/2,500 devices) ·
**memflat FAIL** — `netops-correlation-4` end 1,124 MiB = **87.8 % of its
1,280 MiB cap**, over the 85 % headroom gate, *while the curve itself is FLAT*:
1,087 MiB at input stop → 1,171 MiB at pending 0 → 1,124 MiB end, **×0.96 vs the
pending-0 anchor**, settle 123 s; replica-3 78 → 82 → 84 MiB (×1.026, FLAT,
6.5 % of cap); ClickHouse `MEMORY_LIMIT_EXCEEDED` +0, p99 MemoryTracking 28.0 %
of cap · stability **PASS** (0 CommitFailed, 0 UnknownMember, **0 restarts**,
worst loop stall 14,994 ms, 583 stalls, lifecycle 3,860 s) · cleanup PASS,
**residue 0**.

The two memflat FAILs are **different verdicts on the same underlying fact**.
L2's is *unmeasurable* (no pending-0 anchor, so no slope could be judged) on a
replica that was still climbing — 968 → 1,072 MiB with continuous 1–2.7 s loop
stalls and no relief. L4's is a *headroom* FAIL on a replica whose slope **was**
measurable and came out FLAT (×0.96): the engine finished, released, and settled;
what trips the gate is that it did so 87.8 % of the way up a 1,280 MiB cap.

Engine counters, storm replica `netops-correlation-4`, leg-attributable
(*derived*; the idle replica's engine counters are 0 on both legs): cohorts +55
(L2) → +27 (L4) · epochs +76 on L4 · `corr_versions{persisted}` +21,410 → +9,442,
`{damped}` +3,931 → +2,687, `{heartbeat_touch}` +1,596 → +121 ·
`corr_engine_windows_rejected_total` **0 → 0** ·
`corr_signals_dropped_total{reason="window_rejected"}` **0 → 0** ·
`corr_edge_cache_dropped_total` +307,179 → +344,106 ·
`corr_lifecycle_passes_total` +27 over 6,717 s → +75 over 3,860 s (on L2 the
lifecycle loop was *blocked*, not idle) · `corr_loop_lag_max_ms` 14,035.8 →
14,993.8 · restarts 0 on both. Plane-internal on L4 (*derived*):
`corr_agg_state_transitions_total` +17,611, `corr_agg_recoveries_total` +11,622,
`corr_agg_late_forwarded_total` +69, `corr_agg_beyond_lateness_total` 0; gauges
at capture `corr_agg_keys` 47,141, `corr_agg_identities` 40,623.

Per-template FAIL distribution (all 1,773 stories are `positive`; no negative
controls in either report, so specificity 100 % carries no information here):

| template | stories | FAIL OFF (L2) | FAIL ON (L4) |
|---|--:|--:|--:|
| `local_link_fault` | 771 | **0** | 6 |
| `bgp_peer_flap` | 514 | 172 | **39** |
| `ospf_adjacency_flap` | 308 | 0 | 0 |
| `upstream_link_failure` | 103 | 92 | 82 |
| `enterprise_outage` | 77 | 71 | 67 |
| **total** | **1773** | **335** | **194** |

Almost the whole +7.95 pp comes from `bgp_peer_flap` (172 → 39 FAIL), the
template whose signals are the most repeat-dense in this scenario. The two
chained templates still carry 163/335 and 149/194 of the failures — the same
`affected_includes` gap tracker 187 records, unchanged by the arm. The one
counter-movement is `local_link_fault` 0 → 6 FAIL; against 771 stories that is
0.8 pp and well inside the leg-to-leg accuracy floor, but it is recorded rather
than netted out.

**Measured vs projected — stated explicitly.** §6b projected the plane would
leave **76,819** of 172,452 promoted signals (−55.5 %, quoted as −56 %). The live
plane forwarded **72,293** of 172,453 (−58.1 %): **4,526 fewer signals than
projected, 2.6 pp more reduction than the projection's upper bound on removal.**
The direction matches the 10 % rung but the gap is **half the size** there
(5.3 pp at 10 % → 2.6 pp at 25 %), i.e. the projection tracks the classifier more
closely as the storm share rises — consistent with the extra removal coming from
within-bucket transition folding, whose share of the total shrinks as first-sight
signals dominate. Accounting inside the plane is exact (172,453 observed = 72,293
forwarded + 100,160 suppressed), and `corr_agg_state_transitions_total` +17,611
against forwarded `state_transition` 5,989 again locates the folding. For
corroboration, the harness's own in-run fleet-level projection for this rung
(`report.json` `…/shape/achieved/stream_projection`) is 172,113 → 77,520 =
−54.96 %, the same direction of gap.

**Replica coverage on L4 — reported honestly.** As on L1/L3, only
`netops-correlation-4` (`db5a31b7d5a0`) has non-zero `corr_agg_*` (observed
271,089 cumulative); `netops-correlation-3` (`1ce6206d8751`) reports observed
0.0. **Not** a mixed arm and the leg is **not** void: (a) `ab-leg.json` records
`env "1"` and `corr_agg_enabled 1.0` for **both** replicas; (b) replica-3
received no storm traffic at all — `corr_ingest_events{counter="syslog_received"}
0`, `syslog_signals` 0, `syslog_prefilter_passed` 0, cohorts 0, versions 0,
`open_objects_epoch_peak` 0, `stream_time_evictions` 0 — so there was nothing for
its plane to observe; (c) the identical asymmetry holds on the OFF leg L2, where
replica-3 saw `syslog_received` 30 / `syslog_signals` 0 against replica-4's
1,826,272 / 271,089. The 25 % A/B is therefore a **same-replica** comparison,
carried by replica-4 on both arms.

*Sources: `/var/tmp/scale-runs/agg-25-off-08300014/{ab-leg.json, ttur.tsv,
metrics-final.txt, report.md, report.json, accuracy-report.md,
accuracy-report.json, twin-score.log, launcher.log}` and the same file set under
`/var/tmp/scale-runs/agg-25-on-08300356/` (plus `ttur-scope.json`); subtraction
baselines from `/var/tmp/scale-runs/agg-10-on-08300221/metrics-final.txt` (L3)
and `/var/tmp/scale-runs/agg-10-off-08292249/metrics-final.txt` (L1);
`docs/scale/RUN_PLAN_P3_AB_2026-08-29.md` §1 rows L2/L4 and §6.2; projection from
`docs/design/AGGREGATION_PLANE_P3_2026-08-29.md` §6b.*

---

### 2.3 2 % rung — `t-storm-2.5k` — L0a / L0b (OFF) vs L5 (ON) — the neutrality guard — **BOTH ARMS COLLECTED**

By §6b this rung was projected to have **no aggregation opportunity by
construction** (54,766 → 54,766, 0 %). Any movement L5 shows here was therefore
expected to be cost, not benefit. Two OFF legs are carried because the
leg-to-leg noise floor of this benchmark is ±10 % on TTUR and one baseline
cannot show it.

Identical scenario plane on all three legs: `storm-2.5k`, seed 20260829, 345
incidents, 11,071 promoted / 4,989 unpromotable scenario events, K3 unique 5,677
(48.7 % collapse), class shares first 24.0 % / transition 2.4 % / recovery
15.9 % / repeat 57.7 %, burst 900,000/900,000 @ 1,000/s, and a byte-identical
in-run `stream_projection` (54,561 → 51,191 = −6.18 %). The ground-truth
`digest` differs across the three only because it hashes the run-scoped device
names.

**TTUR provenance.** All three rows were re-queried **in one session**
(2026-08-30 06:2xZ) with the exact §5.3 clean-scope SQL, each leg's scope taken
from its own `report.json` phase stamps (`phases[burst].at − 900 s` →
`phases[burst].at`, cutoff `phases[correlation_completion].at`), the
tenant-constant storm-aggregate cid `bb1e46d6-5462-54dc-8465-777c707b9329`
excluded, tenant `global` confirmed on all three from their burst evidence.

- **L5 reproduces its on-disk `ttur.tsv` digit-for-digit** (2,236 / 10,630 /
  4.75 / 81,052 / 164 / 1,360 / 1,466 / 1,865 / 2,055 / 184 / 0 / 0).
- **L0a reproduces partially.** T1 p99 (1,229), T1 max (1,622) and merged (162)
  are exact; T1 p95 is 1,055 against the 1,054 in
  `STORM_S02_2P5K_VERDICT_2026-08-29.md` §3. But the re-query returns **inc
  2,762 / versions 12,735 / vpi 4.61 / sigs 91,441 / T1 p50 460 / T-last p95
  1,880** where the S02 verdict recorded 2,754 / 13,317 / 4.84 / 91,460 / 453 /
  2,203. The S02 verdict used a **later `created_at` cutoff**, which admits
  post-convergence close-out versions and inflates `versions` and, sharply,
  `T-last p95`. This is the same effect §5.3's own validation note records for
  leg p2-s06. **The re-queried values are used throughout §2.3**, because they,
  L0b's and L5's came from one query in one session — which is precisely what
  §5.3 requires and what the P2 wave learned the hard way.
- **L0b had no `ttur.tsv` and no twin score on disk at all.** Both were computed
  for the first time here. Its 13,749 `corr_objects` rows (3,216 correlation
  ids, 21:51:47 → 22:59:41) survive in ClickHouse, which is what made the
  recovery possible. The twin scorer was re-run against those surviving rows
  after its `mlx-` devices had been purged; **it succeeded, not degraded** —
  321/345, 21 ClickHouse queries, read bounds 21:34:20 → 23:42:44, all 24 FAILs
  on the two chained templates, the same shape as L0a's 23.

*Counter arithmetic:* every cell marked *(derived)* is L5's capture minus L4's
capture on the **same container**, per §1. Replica-3 ran no prior-leg storm
traffic on these containers, so its counters are already L5-only.

| metric | OFF (L0a) | OFF (L0b) | **OFF-vs-OFF spread** | ON (L5) | §6b projection | Δ vs L0a | Δ vs L0b |
|---|--:|--:|--:|--:|--:|--:|--:|
| **signals reaching the engine** | 47,012 (from the S02 verdict; **no fleet total on disk**) | **n/a** (no `metrics-final.txt`) | **not computable** | **49,800** (Σ `corr_agg_forwarded_total{class}`; *derived*: 177,898 + 2,389 − 130,487) | 54,766 → 54,766 (0 %) | **not comparable** | not comparable |
| — `corr_agg_observed_total` | 0 (plane off) | 0 (plane off) | — | **54,767** *(derived: 323,467 − 271,089, + 2,389)* | — | — | — |
| — `corr_agg_suppressed_total` | 0 | 0 | — | **4,967 = 9.07 % of observed** *(derived: 145,569 − 140,602)* | — | — | — |
| — forwarded `first` | 0 | 0 | — | 41,978 *(39,589 derived + 2,389)* | — | — | — |
| — forwarded `state_transition` | 0 | 0 | — | 3,144 *(14,067 − 10,923)* | — | — | — |
| — forwarded `recovery` | 0 | 0 | — | 4,627 *(25,051 − 20,424)* | — | — | — |
| — forwarded `count_threshold` | 0 | 0 | — | 21 *(5,069 − 5,048)* | — | — | — |
| — forwarded `repeat` | 0 | 0 | — | 30 *(138 − 108)* | — | — | — |
| — forwarded `contradiction` / `new_vantage` / `new_modality` | 0 | 0 | — | 0 / 0 / 0 | — | never fired | never fired |
| engine signals inside correlated incidents (`ttur.tsv sigs`) | 91,441 | 89,378 | **2.28 %** | 81,052 | — | **−11.36 %** | **−9.32 %** |
| completion (s) | 118 | 104 | **12.61 %** | **211** | — | **+78.8 %** | **+102.9 %** |
| transport drain (s; peak lag) | 1,026 (403,844) | 1,155 (403,074) | **11.83 %** (lag 0.19 %) | **1,344** (416,669) | — | **+31.0 %** (lag +3.2 %) | **+16.4 %** (lag +3.4 %) |
| **T1 p50 (s)** | 460 | 383 | **18.27 %** | **164** | — | **−64.4 %** (better) | **−57.2 %** (better) |
| **T1 p95 (s)** | **1,055** | **1,203** | **13.11 %** | **1,360** | — | **+28.9 %** (worse) | **+13.1 %** (worse) |
| T1 p99 (s) | 1,229 | 1,237 | **0.65 %** | 1,466 | — | **+19.3 %** (worse) | **+18.5 %** (worse) |
| T1 max (s) | 1,622 | 1,684 | **3.75 %** | 1,865 | — | +15.0 % | +10.8 % |
| **T-last p95 (s)** | 1,880 | 1,834 | **2.48 %** | **2,055** | — | **+9.3 %** (inside ±10 %) | **+12.1 %** (worse) |
| **accuracy (stories pass)** | 322/345 = **93.33 %** | 321/345 = **93.04 %** | **0.29 pp** | **327/345 = 94.78 %** | — | **+1.45 pp** (better) | **+1.74 pp** (better) |
| positive / specificity | 93 % / 100 % *(empty neg. set)* | 93 % / 100 % *(empty neg. set)* | — | 95 % / 100 % *(empty neg. set)* | — | +1.45 pp / flat | +1.74 pp / flat |
| incidents / versions / v-per-inc | 2,762 / 12,735 / 4.61 | 2,685 / 11,198 / 4.17 | 2.83 % / **12.84 %** / **10.02 %** | 2,236 / 10,630 / 4.75 | — | −19.0 % / −16.5 % / +3.0 % | −16.7 % / −5.1 % / +13.9 % |
| merged / undetermined / confirmed | 162 / **0** / 0 | 199 / **0** / 0 | 20.50 % (merged) | 184 / **0** / 0 | — | +13.6 % merged | −7.5 % merged |
| `corr_agg_evicted_total` | 0 (plane off) | 0 (plane off) | — | 64,751 *(derived)*: expired 64,495 + ident_expired 256; capacity / ident_capacity / tenant_capacity **0** | — | — | — |
| `corr_stream_time_evictions_total` | not on disk | not on disk | — | 65,582 *(derived: 151,231 − 85,649)* | — | — | — |
| storm-replica end rss (% of 1,280 MiB cap) | 838 MiB (**65.5 %**) | 1,046 MiB (**81.7 %**) | **22.1 %** | **1,231 MiB (96.2 %)** | — | +46.9 % | +17.7 % |
| **gate FAILs** | **1** — `stability` | **2** — `accounting` + `stability` | — | **4** — `onboard`, `accounting`, **`memflat`**, `stability` | — | see §3.3 | see §3.3 |

Harness phase verdicts. **L0a — 8/9:** preflight PASS · onboard PASS (0.63) ·
burst PASS 900,000/900,000 · drain PASS 1,026 s · completion PASS 118 s ·
accounting PASS (balanced exactly) · **memflat PASS** (9/9; carrier corr-4
527 → 875 → 838 MiB, ×0.958 FLAT, 65.5 % of cap) · **stability FAIL** (2
CommitFailed, 106 UnknownMemberId, 2 consumer restarts, worst stall
**35,690 ms** > the 30 s session timeout) · cleanup PASS, residue 0.
**L0b — 7/9:** preflight PASS · onboard PASS (0.85) · burst PASS · drain PASS
1,155 s · completion PASS 104 s · **accounting FAIL** (1 `netops.findings` row
lost to a transport ReadError, tracker 188) · **memflat PASS** (9/9; carrier
corr-3 544 → 959 → 1,046 MiB, ×1.09 FLAT, **81.7 % of cap** — 3.3 pp from
failing the same gate L5 failed) · **stability FAIL** (1 CommitFailed, 53
UnknownMemberId, 1 restart, worst stall 26.8 s — *under* the gate, ejected by
broker heartbeat timeout anyway) · cleanup PASS, residue 0.
**L5 — 5/9:** preflight PASS · **onboard FAIL** (40.7 → 20.0/s, ratio **0.49**
vs the 0.6 floor, super-linear; 2,500/2,500 devices created and attributable, 0
absorbed by dedupe, `stop=none` — the workload still ran) · burst PASS
900,000/900,000 @ 1,000/s · **drain PASS 1,344 s** (budget 2,700, peak 416,669,
final 1) · **correlation_completion PASS 211 s** (budget 2,700; pending 0 on
both replicas, cohorts +20, versions persisted +11,168, `windows_rejected` +0,
`profiler_errors` +0) · **accounting FAIL** (2 `netops.findings` insert
failures; everything else exact — 900,001 injected == 900,001 OpenSearch docs,
0 DLQ lines, 0 vector discards, 2,500/2,500 devices covered,
`unexplained_missing` 0) · **memflat FAIL** (carrier corr-4 **1,231 MiB =
96.2 % of its 1,280 MiB cap**, over the 85 % headroom gate, *curve FLAT* ×1.039
vs a measurable pending-0 anchor, 1,151 → 1,185 → 1,231 MiB, settle 123 s;
corr-3 87 → 165 → 175 MiB ×1.061 FLAT, 13.7 %; ClickHouse
`MEMORY_LIMIT_EXCEEDED` +0, p99 MemoryTracking 34.0 % of cap) · **stability
FAIL** (2 CommitFailed, 106 UnknownMemberId, 2 consumer restarts, 11
rebalances, 270 loop stalls, worst stall **32,331 ms** > the 30 s session
timeout) · cleanup PASS, **residue 0**.

Engine counters, storm replica `netops-correlation-4`, **L5-attributable**
(*derived*, capture − L4's capture on the same container): cohorts +18 ·
epochs +43 · `corr_versions{persisted}` +11,101, `{damped}` +1,018,
`{heartbeat_touch}` +163 · `corr_engine_windows_rejected_total` **0** ·
`corr_signals_dropped_total{reason="window_rejected"}` **0** ·
`corr_edge_cache_dropped_total` +315,451 · `corr_lifecycle_passes_total` +43 ·
`corr_loop_lag_stalls_total` +332. Reported **as-is with the label**, not
subtracted: `corr_open_objects_epoch_peak` **1,869 (running max, unchanged from
L4 — L5's own peak is at or below it)**, `corr_engine_pending_peak` **5,815
(running max, unchanged)**, `corr_loop_lag_max_ms` **32,331.1 (running max —
this one *did* advance from L4's 14,993.8, so 32,331 ms is L5's own worst
stall)**. Idle replica `netops-correlation-3` was **not** idle on this leg:
cohorts +2, versions persisted +827, epochs +123, `open_objects_epoch_peak` 592,
`engine_pending_peak` 1,575 — the first ON leg where the second replica did any
engine work at all. Plane-internal on L5 (*derived*):
`corr_agg_state_transitions_total` +7,771, `corr_agg_recoveries_total` +4,627,
`corr_agg_late_forwarded_total` +30, `corr_agg_beyond_lateness_total` **0**;
gauges **at capture** (as-is) `corr_agg_keys` **29,855**,
`corr_agg_identities` **66,529** on the carrier, 2,389 / 2,143 on replica-3.

Per-template FAIL distribution (all 345 stories are `positive`; no negative
controls in any of the three reports, so "specificity 100 %" carries no
information at this rung):

| template | stories | FAIL L0a | FAIL L0b | FAIL L5 |
|---|--:|--:|--:|--:|
| `local_link_fault` | 150 | 0 | 0 | 0 |
| `bgp_peer_flap` | 100 | 0 | 0 | 0 |
| `ospf_adjacency_flap` | 60 | 0 | 0 | 0 |
| `upstream_link_failure` | 20 | 8 | 9 | **5** |
| `enterprise_outage` | 15 | 15 | 15 | **13** |
| **total** | **345** | **23** | **24** | **18** |

Every failure on every leg is on the two chained templates — the tracker-187
`affected_includes` gap, unchanged by the arm. L5 is better on both, and the
improvement (+1.45 / +1.74 pp) is outside the 0.29 pp OFF-vs-OFF accuracy
spread. **Accuracy is the one clause of the neutrality guard that L5 passes with
room.**

**Measured vs projected at 2 % — stated explicitly.** §6b projected **zero**
removal (54,766 → 54,766). The live plane removed **9.07 %** (54,767 observed →
49,800 forwarded). Two facts, separately:

1. §6b's *baseline* is essentially exact — 54,766 projected against **54,767
   measured observed**, a one-signal match. It is L0a's 47,012 that fails to
   line up with the projection, not the projection with the plane.
2. §6b's *removal* figure of 0 % is wrong in the **same direction as at both
   other rungs**. The harness's own in-run fleet-level projection
   (`report.json` `…/shape/achieved/stream_projection`) is 54,561 → 51,191 =
   **−6.18 %**, so the live −9.07 % overshoots that by **2.9 pp** — the same
   size of gap as at 25 % (2.6 pp) and about half the 10 % gap (5.3 pp). The
   mechanism is the one §2.1/§2.2 located: `corr_agg_state_transitions_total`
   +7,771 against forwarded `state_transition` 3,144 — transitions folding
   inside a 60 s bucket instead of forwarding synchronously. Plane accounting is
   exact (54,767 = 49,800 + 4,967).

**Why "signals reaching the engine" is not comparable at this rung — reported,
not netted out.** L0a's 47,012 is quoted from
`STORM_S02_2P5K_VERDICT_2026-08-29.md` §2; **neither L0a nor L0b kept a
`metrics-final.txt`**, so nothing on disk establishes whether that figure is a
fleet total or one replica's — and L0a's traffic was *split* across both
replicas (window signals 22,917 / 7,822), unlike L1/L3/L4 where the idle replica
saw literally zero. L5's derived fleet observed is **54,767**, +16.5 % above
47,012 on an identical scenario plane. That is either a real leg-to-leg swing in
noise-pool promotion or a denominator mismatch, and **this evidence cannot tell
them apart.** The row is therefore excluded from the neutrality judgement; §3.1
judges criterion 1 on TTUR and accuracy, which is what §7 asks for.

**The plane's cost/benefit at 2 %, honestly.** 9.07 % suppression is not the
"no opportunity" §6b predicted, but it is small, and it is the only throughput
credit the plane earns here. Set against it: T1 p95 **+28.9 % / +13.1 %** worse,
T1 p99 **+19.3 % / +18.5 %** worse, completion +79 % / +103 % worse, drain
+31 % / +16 % worse, and a `memflat` FAIL neither OFF leg had. The unambiguous
credits are accuracy (+1.45 / +1.74 pp) and **T1 p50 (−64 % / −57 %)**. That
split — median far better, tail worse — is itself the finding: suppression
clears the cheap repeat work early and leaves a residue that lands in the tail.

**One observation that bears on how much of the tail is the plane's.** T1 p95
tracks the Kafka **transport drain time** almost exactly on all three legs:

| leg | drain (s) | T1 p95 (s) | ratio |
|---|--:|--:|--:|
| L0a | 1,026 | 1,055 | 1.028 |
| L0b | 1,155 | 1,203 | 1.041 |
| **L5** | **1,344** | **1,360** | **1.012** |

At this rung the 95th-percentile incident's first version lands within ~1–4 % of
when transport finished handing the events over. On this evidence T1 p95 here is
**transport-bound, not engine-bound**, and the plane sits *downstream* of
transport. This is an observation, **not a proof of neutrality**: it does not
explain why L5's drain was 16–31 % slower in the first place, and a slower drain
on a box carrying three legs' worth of resident state is exactly the confound
§3.5 asks to remove. T1 p99 does not hold the same ratio (1.198 / 1.071 / 1.091),
so the deep tail is not fully explained by it either.

**Replica coverage on L5 — reported honestly, and it differs from L3/L4.** Both
replicas report `env "1"` and `corr_agg_enabled 1.0` (`ab-leg.json`), and unlike
every other ON leg **both have non-zero `corr_agg_*`**: replica-4 observed
323,467 cumulative, replica-3 observed **2,389** (all forwarded as `first`,
0 suppressed). Replica-3 also did real engine work for the first time in the ON
arm (cohorts +2, versions +827). The asymmetry is therefore softer here than at
10 %/25 % but still dominant — 96 % of the storm on replica-4. Both OFF legs at
this rung were also split (L0a 22,917/7,822 with replica-**4** carrying, L0b
31,167/3,503 with replica-**3** carrying), so **the 2 % rung is *not* a
same-replica A/B the way the 10 % and 25 % rungs are**: L5 and L0a share
replica-4 as carrier, L0b's carrier is replica-3. Carried as caveat 12.

*Sources: `/var/tmp/scale-runs/agg-2p5k-on-08300516/{ab-leg.json, ttur.tsv,
ttur-scope.json, metrics-final.txt, report.md, report.json, accuracy-report.md,
accuracy-report.json, twin-score.log, launcher.log}` ·
`/var/tmp/scale-runs/storm-s02-08291929/{report.md, report.json,
accuracy-report.md, accuracy-report.json}` ·
`/var/tmp/scale-runs/storm-s03-08292148/{report.md, report.json,
accuracy-report.md, accuracy-report.json, twin-score.log}` (the last two written
2026-08-30 06:23Z by the recovery re-score) · L4 subtraction baselines from
`/var/tmp/scale-runs/agg-25-on-08300356/metrics-final.txt` · TTUR rows from the
in-session re-query of `netops.corr_objects` documented above ·
`docs/scale/STORM_S02_2P5K_VERDICT_2026-08-29.md`,
`docs/scale/STORM_S02_ACCURACY_2026-08-29.md`,
`docs/scale/STORM_S03_2P5K_VERDICT_2026-08-29.md`,
`docs/scale/RUN_PLAN_P3_AB_2026-08-29.md` §1 rows L0a/L0b/L5 and §6.3/§6.3a;
projection from `docs/design/AGGREGATION_PLANE_P3_2026-08-29.md` §6b.*

---

## 3. Decision-rule checklist (`RUN_PLAN_P3_AB_2026-08-29.md` §7)

`CORR_AGGREGATION_PLANE` becomes default ON **if and only if all three hold.**

### 3.1 Criterion 1 — Neutrality guard (2 % rung, L5 vs L0a **and** L0b) — **FAILS**

§7 requires, on `t-storm-2.5k`, that TTUR be within **±10 %** (T1 p95,
cross-checked against T1 p50 and T-last p95) and accuracy **≥ OFF − 1 pp**.
Deltas below are `(ON − OFF)/OFF`; the spread column is `|L0a − L0b| / mean`.

| clause | threshold | vs L0a | vs L0b | OFF-vs-OFF spread | verdict |
|---|---|--:|--:|--:|---|
| **T1 p95 within ±10 %** | ±10 % | 1,055 → 1,360 = **+28.9 %** | 1,203 → 1,360 = **+13.1 %** | **13.11 %** | **FAIL — outside ±10 % against BOTH baselines** |
| T1 p50 (cross-check) | ±10 % | 460 → 164 = **−64.4 %** | 383 → 164 = **−57.2 %** | 18.27 % | outside, in the **better** direction, against both |
| T-last p95 (cross-check) | ±10 % | 1,880 → 2,055 = **+9.3 %** | 1,834 → 2,055 = **+12.1 %** | 2.48 % | **split** — inside vs L0a, outside vs L0b |
| T1 p99 (further cross-check) | — | 1,229 → 1,466 = **+19.3 %** | 1,237 → 1,466 = **+18.5 %** | **0.65 %** | worse by **~29× the spread** — the cleanest signal in the table |
| accuracy ≥ OFF − 1 pp | ≥ −1.00 pp | 93.33 % → 94.78 % = **+1.45 pp** | 93.04 % → 94.78 % = **+1.74 pp** | 0.29 pp | **PASS** — better than both, outside the spread |

**Criterion 1 FAILS on its primary clause.** T1 p95 is worse than *both* OFF
baselines by more than 10 %. Accuracy passes with room. The cross-checks do not
rescue it: T-last p95 is outside the floor against one baseline, and T1 p99 is
worse than both by ~19 % against an OFF-vs-OFF spread of 0.65 %.

**The spread caveat §7 asks for, applied.** The OFF-vs-OFF spread on **T1 p95 is
itself 13.11 %** — the metric the decision hinges on is noisier at this rung
than the ±10 % threshold being applied to it. Two consequences, both stated:

- **Against L0b the ON delta (+13.1 %) is indistinguishable from the OFF-vs-OFF
  spread (13.11 %) — a ratio of 1.00.** On that pair alone, L5's p95 movement is
  *exactly* the size of the noise and must be reported as noise.
- **Against L0a the ON delta (+28.9 %) is 2.2× the spread.** On that pair it is
  a real move.

So the p95 clause fails the *letter* of the rule against both baselines, but the
*strength* of the evidence is asymmetric: one baseline says "regression", the
other says "noise". This is exactly the situation two OFF legs were carried to
expose, and it is why §3.5 recommends one more measurement rather than treating
+28.9 % as an established fact.

**What is NOT ambiguous.** T1 p99 (+19 % against a 0.65 % spread), completion
(211 s vs 118/104 — +79 %/+103 % against a 12.6 % spread) and transport drain
(1,344 s vs 1,026/1,155 — +31 %/+16 % against an 11.8 % spread) all move the
same way, all beyond their own spreads, on a rung where §6b said there was
nothing to gain. And **T1 p50 moves hard the other way** (−64 %/−57 % against an
18.3 % spread). The plane made the median incident much faster and the tail
slower. That is a real, reproducible-looking shape, not a wash — and §2.3's
drain/p95 ratio table (1.028 / 1.041 / 1.012) says the tail half of it may be
transport-bound rather than engine-bound, which the current evidence cannot
settle.

### 3.2 Criterion 2 — The 10 % rung earns it (L3 vs L1) — **MET**

| §7 clause | threshold | measured | verdict |
|---|---|---|---|
| ≥20 % fewer signals reaching the engine | ≥ 20 % | **98,636 → 58,194 = −41.0 %** (OFF promoted count vs Σ `corr_agg_forwarded_total{class}`, the §6-defined measure) | **PASS**, by 21 pp of margin |
| TTUR not worse (beyond the ±10 % noise floor) | ≥ −10 % | T1 p95 2,763 → 1,985 s = **−28.2 %** (better); T1 p50 434 → 282 s = −35.0 %; T-last p95 3,273 → 2,426 s = −25.9 %; T1 p99 3,063 → 2,224 s = −27.4 % | **PASS** — better on all four, each beyond the noise floor and all in the same direction |
| accuracy not worse (beyond 1 pp) | ≥ −1.00 pp | 89.85 % → 89.45 % = **−0.40 pp** (903/1005 → 899/1005; specificity 100 % on both) | **PASS** — inside the 1 pp floor |

**Honest qualification on the first clause.** The −41.0 % figure is the measure
§6 of the run plan defines. A *second*, engine-side measure — Σ signals attached
to correlated incidents, the `sigs` column of `ttur.tsv` — moves 94,942 → 76,680
= **−19.2 %**, which is **just under** the 20 % bar. The two numbers differ
because the plane's suppression removes repeats that would otherwise have been
folded into an existing correlation object rather than creating new engine work
one-for-one. Criterion 2 is judged on the run plan's stated measure and passes;
the −19.2 % secondary figure is recorded here so the margin is not overstated.

### 3.3 Criterion 3 — No new gate FAIL — **FAILS** (at the 2 % rung; the 10 % and 25 % rungs are clean)

The clause: *"No phase that PASSed on the corresponding OFF leg FAILs on the ON
leg. A pre-existing FAIL that persists unchanged is not a new FAIL, but must be
named."*

**10 % rung — clean.** Every phase that PASSed on L1 PASSed on L3 (9/9 both),
accounting exactly lossless on both, `corr_engine_windows_rejected_total` 0 on
both, restarts 0 on both, residue 0 on both.

**25 % rung — clean, and strictly better.** Unchanged from §3.3's earlier
evaluation, reproduced here in full because the conclusion depends on it:

| §7 clause | L2 (OFF) | L4 (ON) | verdict |
|---|---|---|---|
| memflat | **FAIL** — corr-4 LEAK SLOPE UNKNOWN, rss 968 → 1,072 MiB (83.8 % of cap) still climbing, no pending-0 anchor | **FAIL** — same replica 1,124 MiB = 87.8 % of cap (> 85 % gate), curve **FLAT ×0.96** vs a *measurable* anchor | **pre-existing FAIL, persisting — NOT new**, and strictly less bad |
| drain | **FAIL** — never drained in 2,700 s, final lag 124,868 | **PASS 2,263 s**, final lag 12 | **FAIL → PASS** |
| correlation_completion | **FAIL — INCOMPLETE**, pending 78,663 | **PASS 192 s**, pending 0 | **FAIL → PASS** |
| accounting exactly lossless | PASS | PASS | holds on both |
| `windows_rejected` 0 / restarts 0 / residue 0 | 0 / 0 / 0 | 0 / 0 / 0 | holds on both |

**2 % rung — this is where criterion 3 fails.** Phase by phase, L5 against
*both* corresponding OFF legs:

| phase | L0a (OFF) | L0b (OFF) | L5 (ON) | verdict under §7 |
|---|---|---|---|---|
| preflight | PASS | PASS | PASS | holds |
| **onboard** | **PASS** (0.63) | **PASS** (0.85) | **FAIL** (0.49) | **NEW FAIL — a phase that PASSed on BOTH OFF legs** |
| burst | PASS 900,000/900,000 | PASS | PASS 900,000/900,000 | holds |
| drain | PASS 1,026 s | PASS 1,155 s | PASS 1,344 s | holds (slower, but PASS) |
| correlation_completion | PASS 118 s | PASS 104 s | PASS 211 s | holds (slower, but PASS) |
| **accounting** | **PASS** (exact) | **FAIL** (1 `netops.findings` row) | **FAIL** (2 `netops.findings` rows) | **pre-existing failure mode** (tracker 188) — but a PASS→FAIL against L0a |
| **memflat** | **PASS** (65.5 % of cap, FLAT) | **PASS** (81.7 % of cap, FLAT) | **FAIL** (96.2 % of cap, FLAT ×1.039) | **NEW FAIL — a phase that PASSed on BOTH OFF legs** |
| **stability** | **FAIL** (2 / 106 / 2, worst stall 35,690 ms) | **FAIL** (1 / 53 / 1, worst stall 26,824 ms) | **FAIL** (2 / 106 / 2, worst stall 32,331 ms) | **pre-existing FAIL, persisting — NOT new. L5's signature is L0a's exactly** (identical 2 CommitFailed / 106 UnknownMemberId / 2 restarts) |
| cleanup / residue | PASS, 0 | PASS, 0 | PASS, 0 | holds |
| `windows_rejected` | 0 | 0 | **0** | holds |

Named explicitly, as §7 requires:

- **`stability` is pre-existing and must NOT be counted against L5.** Both OFF
  legs failed it. L5's counts are *identical* to L0a's (2 CommitFailedError, 106
  UnknownMemberIdError, 2 consumer restarts) and its worst stall (32,331 ms) sits
  between L0b's 26,824 ms and L0a's 35,690 ms. Fix `2852ad6f` (tracker 185
  part 3) is committed and deliberately not deployed in this wave's image.
- **`accounting` is the tracker-188 failure mode**, present on L0b (1 row) and
  on L5 (2 rows), absent on L0a. Fix `2852ad6f` (findings retry-safety) is
  likewise committed and undeployed on purpose. Against L0b it is pre-existing;
  **against L0a it is a PASS→FAIL**, and a literal reading of §7 ("the
  corresponding OFF leg", with two of them) cannot dismiss it. It is recorded
  as pre-existing-in-mechanism but **not** claimed to be exonerated by evidence.
- **`onboard` is a NEW FAIL and is not the engine.** It measures device-creation
  rate through the device API *before a single event is injected*: 40.7 → 20.0
  devices/s, ratio 0.49 against a 0.6 floor, super-linear (O(N²) class) — the
  tracker-175 onboarding debt. **Neither OFF leg failed it** (0.63, 0.85). All
  2,500 devices were created and attributable, 0 absorbed by dedupe,
  `stop=none`, so the workload ran in full. The aggregation plane is not on the
  device-onboard path at all; what this most plausibly reflects is the state of
  the host and the API's device store on the wave's sixth consecutive leg (the
  API's tombstone file already held 57,927 suppressed entries by cleanup). **It
  is nonetheless a phase that PASSed on both OFF legs and FAILed on the ON leg,
  and §7 counts it.**
- **`memflat` is the NEW FAIL that matters**, and it is evaluated in §3.4.

**Criterion 3 therefore FAILS**: `memflat` and `onboard` both PASSed on both
corresponding OFF legs and FAIL on L5 (and `accounting` PASSed on one of them).

### 3.4 The `memflat` FAIL on L5 — how far the evidence goes, and where it stops

Storm-carrying replica per leg (cap 1,280 MiB on every container; `cold` is the
preflight baseline, `end` the memflat end sample):

| leg | arm | rung | carrier | leg # on that container | cold | end | in-leg growth | end % of cap | memflat |
|---|---|---|---|--:|--:|--:|--:|--:|---|
| L0a | OFF | 2 % | `143e8533f1ee` corr-4 | **1** | 60 MiB | 838 MiB | **+778** | 65.5 % | PASS (FLAT ×0.958) |
| L0b | OFF | 2 % | `cb969ae44891` corr-3 | **1** | 62 MiB | **1,046 MiB** | **+984** | **81.7 %** | PASS (FLAT ×1.09) |
| L1 | OFF | 10 % | `cd8ce6063716` corr-4 | **1** | 62 MiB | 935 MiB | +873 | 73.0 % | PASS (FLAT ×0.986) |
| L2 | OFF | 25 % | `cd8ce6063716` corr-4 | **2** | **937 MiB** | 1,072 MiB | +135 | 83.8 % | FAIL (slope UNKNOWN) |
| L3 | ON | 10 % | `db5a31b7d5a0` corr-4 | **1** | 69 MiB | 1,015 MiB | +946 | 79.3 % | PASS (FLAT ×0.964) |
| L4 | ON | 25 % | `db5a31b7d5a0` corr-4 | **2** | **934 MiB** | 1,124 MiB | +190 | 87.8 % | FAIL (headroom; FLAT ×0.96) |
| **L5** | **ON** | **2 %** | `db5a31b7d5a0` corr-4 | **3** | **1,065 MiB** | **1,231 MiB** | **+166** | **96.2 %** | **FAIL (headroom; FLAT ×1.039)** |

Idle-replica end rss: L0a 330 · L0b 182 · L1 111 · L2 134 · L3 69 · L4 84 ·
L5 175 MiB. Plane gauges **at capture, as-is** on the ON carrier:

| capture | `corr_agg_keys` | `corr_agg_identities` | cumulative `evicted{ident_expired}` | cumulative `evicted{ident_capacity}` |
|---|--:|--:|--:|--:|
| L3 | 37,766 | 18,714 | 97 | 0 |
| L4 | 47,141 | 40,623 | 353 | 0 |
| **L5** | **29,855** | **66,529** | **609** | **0** |

**What the evidence supports.**

1. **L5's FAIL is a headroom verdict driven by carry-in, not by in-leg growth.**
   L5's in-leg growth is **+166 MiB — the smallest of any 2 % leg**, about a
   fifth of L0a's +778 and a sixth of L0b's +984, and its slope is FLAT
   (×1.039) against a *measurable* pending-0 anchor. What put it at 96.2 % of
   cap is that it **started** at 1,065 MiB — 83.2 % of cap, above where L0a
   *ended*.
2. **Leg-over-leg carry-over exists on the OFF arm too, at the same magnitude.**
   The one arm-matched carry-in comparison available is leg 2: OFF cold
   **937 MiB** (L2, after L1) vs ON cold **934 MiB** (L4, after L3) — 3 MiB
   apart. On this evidence the plane adds **nothing measurable** to the first
   carry-over.
3. **The OFF arm's own first-leg spread at this rung exceeds the gap the plane
   is being blamed for.** Two OFF legs, same rung, same scenario, both on fresh
   containers: **838 vs 1,046 MiB** — 208 MiB, **22.1 %**, with L0b landing
   **3.3 pp** from failing the very gate L5 failed. Storm-carrier end rss at 2 %
   is high-variance with no plane at all.
4. **One plane-specific quantity does grow monotonically across the wave**:
   `corr_agg_identities` **18,714 → 40,623 → 66,529**, while cumulative
   `ident_expired` evictions total only 609 and `ident_capacity` evictions are
   **0**. `corr_agg_keys` is *not* monotone (37,766 → 47,141 → 29,855), so the
   key table is being reclaimed and the identity table is not, over the ~4 h
   lifetime of these containers. That is resident plane state that grew by ~48k
   entries across three legs.

**What the evidence does NOT support, and is not claimed.**

- **There is no OFF leg 3.** The ON arm's leg-2 → leg-3 carry-in increment
  (934 → 1,065 MiB, **+131 MiB**) has no OFF counterpart, so it cannot be
  attributed to the plane rather than to the engine's own third-leg carry-over.
- The identity-table growth is **consistent with** contributing to that
  +131 MiB, but nothing instruments bytes per identity entry and the plane's
  resident footprint is not separately measured. Correlating a monotone counter
  with a monotone rss is not attribution.
- L2's memflat FAIL is *slope-unknown*, so the OFF arm offers no measurable
  leg-2 slope to compare L4's and L5's FLAT verdicts against.

**Conclusion, at exactly the strength the evidence carries: the `memflat` FAIL
on L5 CANNOT be separated into "the plane's resident state" versus "three
consecutive legs on one container" with this data.** Two facts point away from
the plane (the plane adds ~0 MiB to the arm-matched leg-2 carry-in; L5's in-leg
behaviour is the best of any 2 % leg). Two facts point toward it
(`corr_agg_identities` grows monotonically and is not reclaimed; no OFF leg ever
reached 96.2 % of cap). **Under §7 the FAIL stands regardless** — the rule asks
whether a phase that PASSed on the OFF leg FAILed on the ON leg, not whether the
plane caused it.

### 3.5 The rule applied literally — outcome

| criterion | requirement | result |
|---|---|---|
| **1 — neutrality guard** | TTUR within ±10 % of the OFF legs (T1 p95, cross-checked p50 / T-last p95) **and** accuracy ≥ OFF − 1 pp, on the 2 % rung | **FAIL** — T1 p95 +28.9 % vs L0a and +13.1 % vs L0b, outside ±10 % against both (accuracy clause **passes**: +1.45 / +1.74 pp) |
| **2 — the 10 % rung earns it** | ≥20 % fewer signals reaching the engine, TTUR not worse, accuracy not worse | **MET** — −41.0 % signals, TTUR better on all four percentiles, accuracy −0.40 pp (inside the 1 pp floor) |
| **3 — no new gate FAIL** | no phase that PASSed on the corresponding OFF leg FAILs on the ON leg | **FAIL** — `memflat` and `onboard` PASSed on **both** 2 % OFF legs and FAIL on L5; `accounting` PASSed on L0a and FAILs on L5 |

§7's disposition text, applied word for word:

> *"If 1 fails → the plane costs something where it can gain nothing: do not
> default ON; investigate the cost first."*
> *"If 3 fails → stop; the failure is the result, and no reduction number buys
> past it."*

**Outcome: `CORR_AGGREGATION_PLANE` does NOT become default ON.** Two of the
three criteria fail. The flag stays **OFF by default** and the plane stays
opt-in behind `deployment/docker/compose.agg.yml`. The −41.0 % / −58.1 % signal
reductions and the 25 % rung's INCOMPLETE→PASS result are real and are recorded
as the wave's finding — **they do not buy past criterion 3**, which §7 states
explicitly.

**This is not a verdict that the plane is harmful.** It is a verdict that the
2 % neutrality guard, as run, did not clear the bar — and §3.1 and §3.4 both
show the evidence at that rung is contaminated: the p95 delta is 1.00× the
OFF-vs-OFF spread against one of the two baselines, T1 p95 tracks transport
drain to within 1–4 % on all three legs, and the `memflat` FAIL is inseparable
from a three-legs-on-one-container carry-in that the OFF arm never had a
matching third leg for.

### 3.6 Recommended follow-up — the ONE measurement that would settle it

**Recommendation only. Nothing was run for this, and nothing should be run from
this document without the owner's go-ahead.**

Deploy `2852ad6f` (tracker 188 findings retry-safety + 185 part 3 lifecycle
yields), then run **a single matched pair at `t-storm-2.5k`, each leg on freshly
`--force-recreate`d correlation containers, back to back in one session**:

1. one **OFF** leg on fresh containers (the new post-deploy baseline), then
2. one **ON** leg on fresh containers,

with TTUR re-queried for both in that same session per §5.3 and both twin-scored.

That one pair removes every confound this wave could not:

| confound in this wave | what the paired fresh-container run resolves |
|---|---|
| L5 was leg 3 on a container carrying 1,065 MiB of prior state; no OFF leg 3 exists | both legs start cold, so `memflat` measures the leg, and `corr_agg_identities` growth is measured over **one** leg |
| `stability` FAIL (32.3 s stall, 2 consumer ejections) is pre-existing and undeployed-fix-bound; consumer ejection and re-delivery inflate the tail | `2852ad6f` is in the image, so if T1 p95/p99 regression survives it, it is the plane's |
| `accounting` FAIL (2 `netops.findings` rows) is tracker 188 | `2852ad6f` fixes it; accounting returns to exactly lossless or it does not |
| T1 p95 tracks transport drain to within 1–4 %; drain itself was 16–31 % slower on L5 | same-session, same-day, fresh-container pair makes drain comparable |
| OFF-vs-OFF T1 p95 spread is 13.11 %, wider than the ±10 % threshold | a third 2 % OFF point tightens (or confirms) the noise floor the rule is judged against |
| the 2 % rung is not a same-replica A/B (L5+L0a on replica-4, L0b on replica-3) | record the carrier on both legs and re-run if they differ |

If that pair shows T1 p95 within ±10 %, accuracy ≥ OFF − 1 pp, and no new gate
FAIL, criteria 1 and 3 are met and — with criterion 2 already MET — the rule
would then say default ON. **Until it is run, the answer is the one above: not
default ON.**

---

## 4. Caveats (all of them)

1. **Loaded 4-core box.** Every leg ran on the single shared lab host with the
   full 26-service stack live. Absolute latencies are host-bound; only
   leg-to-leg deltas on the same host are meaningful.
2. **±10 % leg-to-leg noise floor on TTUR**, established in
   `docs/scale/P2_STEP6_2P5K_VERDICT_2026-08-29.md` §3. Every TTUR delta in this
   document must be read against it. The 10 % rung's T1 p95 move (−28.2 %) is
   ~2.8× the floor; the accuracy move (−0.40 pp) is *inside* the 1 pp floor and
   is therefore reported as flat, not as a regression.
3. **Replica identity.** One replica carries the tenant on this deployment. On
   the 10 % and 25 % rungs `netops-correlation-4` carried it on **all four** legs
   (L1/L3 and L2/L4), so both of those A/Bs are same-replica and the other
   replica contributes only zeros. **The 2 % rung is different and weaker**: the
   traffic was *split* on all three legs, and the carrier is not the same across
   them — L0a's carrier was **replica-4** (window signals 22,917 vs 7,822;
   `STORM_S02_2P5K_VERDICT_2026-08-29.md` says so explicitly, and the draft of
   this document previously recorded it wrongly as replica-3), L0b's was
   **replica-3** (31,167 vs 3,503), L5's was **replica-4** (26,616 vs 2,389).
   L5 vs L0a is therefore same-replica; **L5 vs L0b is not**. Cross-rung
   comparisons inherit the asymmetry.
4. **Cron overlap: none.** The 03:17 UTC 1K canary was removed from the crontab
   on 2026-08-29 (owner-approved), so no leg in this wave overlapped it. The
   remaining crontab entries are the watchdog, a need-based TLS rotate at 05:07
   that defers restarts under a live run, and hygiene. The one cron-shaped
   incident in this wave was the *driver's own* stale 03:10–04:40 UTC canary
   guard, which stopped the driver at 03:32Z **after L3 completed and before L4
   started** — it cost a relaunch, not a leg.
   (`docs/scale/RUN_PLAN_P3_AB_2026-08-29.md` §1 row L4;
   `docs/scale/RESUME_BRIEF_2026-08-28.md` UPDATE 2026-08-30 03:45Z.)
5. **L2 (25 % OFF) is INCOMPLETE.** Single-partition overload: replica-4 alone
   held the storm partition, pending stuck at 78,663 at the 2,700 s cap with
   final lag 124,868, **no rebalance and no consumer ejection** (0 UnknownMember,
   0 restarts) — the system absorbed the overload as unbounded backlog instead
   of failing loudly. Its T1 numbers are scoped only to the incidents that did
   complete and are therefore optimistic; its memflat FAIL is an *unmeasurable*
   verdict (no pending-0 anchor), not a proven leak. It is a valid OFF reading of
   an overloaded system and nothing more. **Every TTUR delta at the 25 % rung is
   therefore directional only** — the decisive comparison at that rung is
   completion (INCOMPLETE → PASS 192 s) and accuracy (81 % → 89 %), not a
   percentile.
6. **No mixed-arm leg was discarded** — none occurred. L3's zero-`corr_agg_*`
   replica is an idle replica, evidenced in §2.1, not a misflagged one.
7. **Post-wave fixes are undeployed on purpose.** `2852ad6f` (tracker 188
   findings retry-safety + 185 part 3 lifecycle yields) is committed but not in
   the wave's image, so L0b's accounting FAIL and the residual loop stalls are
   expected to persist across all five legs. **They did**: L5 carries the same
   `netops.findings` loss (2 rows) and the same stall-driven consumer ejection
   signature as L0a (2 CommitFailed / 106 UnknownMemberId / 2 restarts). Both
   of L5's `accounting` and `stability` FAILs are therefore expected artefacts
   of the frozen image, not results — and both are the first thing §3.6's
   recommended follow-up removes.
8. **The measured-vs-projected gap at 10 % is unexplained in full.** The plane
   removed 5.3 pp *more* than the §6b upper bound predicted, traced in §2.1 to
   within-bucket transition folding. Until the equivalence suite confirms that
   folding is lossless with respect to what the engine would have concluded,
   this is an open question, not a bonus.
9. **Specificity is reported over an empty negative set.** Both 10 % accuracy
   reports contain 1,005 `positive` stories and no negative controls, so the
   "specificity 100 %" line carries no information for this rung.

10. **Single-replica storm concentration is a live capacity risk, independent of
   the arm — and it is now the limiting factor.** The storm partition lands on
   one replica in every leg of this wave. At the 25 % rung
   `netops-correlation-4` ends at **87.8 % of its 1,280 MiB cap on L4** (83.8 %
   on L2) while `netops-correlation-3` sits at 6.5 % / 10.5 %. **At the 2 % rung
   on L5 the same replica ends at 1,231 MiB = 96.2 % of its cap** — one burst
   from an OOM kill, in the harness's own words — while replica-3 sits at
   175 MiB (13.7 %), and there was **no rebalance and no ejection driven by the
   imbalance** (L5's 11 rebalances and 2 consumer restarts are the tracker-185
   loop-stall ejections, not load shedding). The OFF arm shows the same shape
   with no plane at all: **L0b's carrier ended at 1,046 MiB = 81.7 % of cap on a
   fresh container, 3.3 pp from failing the gate**, while its peer sat at
   182 MiB. What the memflat FAILs on L2, L4 and L5 all report is the same
   structural fact — the memory *curve* is FLAT wherever it could be measured
   (L4 ×0.96, L5 ×1.039, L0b ×1.09), the *headroom* is not. The aggregation
   plane changes how much work that replica must do (which is why L4 finished
   where L2 could not) but **it does not and cannot change which replica does
   it.** With 24 partitions owned per replica, `corr_consumer_zero_assignments`
   0 and `corr_consumer_cold_partitions` 0, assignment is even and the *keys*
   are not: a single tenant's storm keys hash to one replica's partitions.
   **Tracker candidate; deliberately not filed from this document.**

11. **L5 is the third consecutive leg on one container; no OFF leg 3 exists.**
   L3, L4 and L5 all ran on `db5a31b7d5a0` / `1ce6206d8751` (started 02:21Z).
   L5's storm replica entered the leg at a preflight-cold rss of **1,065 MiB =
   83.2 % of cap**, above where L0a *ended*. The OFF arm reached leg 2 (L1→L2)
   and stopped. §3.4 shows the arm-matched leg-2 carry-in is 937 MiB (OFF) vs
   934 MiB (ON) — the plane adds ~0 — but the leg-2→leg-3 increment (+131 MiB)
   has no OFF counterpart, so **the `memflat` FAIL cannot be attributed to the
   plane or exonerated from it with this data.** Every absolute number on L5
   must be read with this confound present; §3.6 names the one measurement that
   removes it.

12. **The 2 % rung's OFF-vs-OFF spread is wider than the threshold applied to
   it.** `|L0a − L0b| / mean` on T1 p95 is **13.11 %**, against a ±10 %
   decision threshold. On T1 p50 it is 18.27 %, on versions 12.84 %, on
   completion 12.61 %, on drain 11.83 % — and on the carrier's end rss, **22.1 %
   (838 vs 1,046 MiB)**. Only T1 p99 (0.65 %), T-last p95 (2.48 %), sigs
   (2.28 %) and accuracy (0.29 pp) are tight. The ±10 % floor quoted from
   `P2_STEP6_2P5K_VERDICT_2026-08-29.md` §3 is **optimistic for this rung**;
   §3.1 reports L5's p95 delta both absolutely and as a multiple of the measured
   spread (1.00× against L0b, 2.2× against L0a) rather than against the nominal
   floor alone.

13. **L0a's TTUR row in `STORM_S02_2P5K_VERDICT_2026-08-29.md` §3 does not fully
   reproduce.** The in-session re-query (§2.3) reproduces T1 p99, T1 max and
   merged exactly and T1 p95 to 1 s, but returns inc 2,762 / versions 12,735 /
   vpi 4.61 / T1 p50 460 / **T-last p95 1,880** where that verdict recorded
   2,754 / 13,317 / 4.84 / 453 / **2,203**. The S02 verdict used a later
   `created_at` cutoff, admitting post-convergence close-out versions. **This
   document uses the re-queried values throughout**, per §5.3's one-session
   rule. The older numbers are not wrong for their own cutoff; they are not
   comparable to L5's.

14. **`signals reaching the engine` is not comparable at the 2 % rung.** Neither
   L0a nor L0b kept a `metrics-final.txt`, so the only OFF figure is L0a's
   47,012 quoted from the S02 verdict, and nothing on disk establishes whether
   it is a fleet total or one replica's — on a leg whose traffic was split
   across both replicas. L5's derived fleet observed is 54,767 (+16.5 %) on an
   identical scenario plane. §3.1 judges criterion 1 on TTUR and accuracy only.

15. **L0b's twin score and TTUR row were reconstructed after the fact.** Both
   were computed on 2026-08-30 from surviving ClickHouse evidence (13,749
   `corr_objects` rows), not captured at run time, and the twin re-score ran
   after its `mlx-` devices had been purged. **It succeeded rather than
   degrading** — 321/345, 21 queries, all 24 FAILs on the two chained templates,
   the same shape as L0a's — because the scorer reads `corr_objects` and the
   ground-truth file, not the device registry. Its read bounds (21:34:20 →
   23:42:44) extend past L0b's own cleanup and overlap the start of L1; stories
   are matched to L0b's own run-scoped `mlx-08292148kdz4-*` devices, so
   cross-run contamination is not expected, but the wide window is recorded
   rather than hidden.

---

## 5. Wave closed — what was completed, and what deliberately was not

1. ~~Run **L4**~~ — **DONE**, `agg-25-on-08300356` / `08300356hdmy`, 8/9.
2. ~~Land **L5** and recover L0b's TTUR + twin score~~ — **DONE**.
   `agg-2p5k-on-08300516` / `08300516wqrl` collected 2026-08-30 06:20Z (5/9);
   L0b's TTUR row computed from surviving `corr_objects` and its twin re-scored
   at 321/345 (§2.3, caveat 15). The guard has its two OFF baselines.
3. ~~Re-query all legs' TTUR **in one session** per §5.3~~ — **DONE** for the
   2 % rung's three legs (L0a, L0b, L5) on 2026-08-30 06:2xZ. L5 reproduces its
   on-disk row exactly; L0a reproduces partially and the discrepancy is recorded
   as caveat 13.
4. **Not done, on purpose:** the OFF arm has **not** been restored (run plan
   §3.4). The correlation service is being rebuilt/redeployed concurrently by
   another agent; this document's author held to docs and read-only ClickHouse
   queries and touched no container. **Whoever next owns the stack must confirm
   the arm before the next leg** (§3.3 of the run plan).
5. **The follow-up in §3.6 is a recommendation, not a plan of record.** Nothing
   was run for it. It needs the owner's go-ahead and a `2852ad6f` deploy first.
