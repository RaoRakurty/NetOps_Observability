# Programme close-out — `storm-s05` (OFF) / `storm-s06` (ON), and the aggregation plane's default flip (2026-08-30)

**Verdict: both legs PASS 9 of 9, and `CORR_AGGREGATION_PLANE` is now ON by
default in the shipped compose file.** This document is the close-out of the P4
storm-time optimisation programme: it records the matched OFF/ON confirmation
pair that followed the two engine/instrument fixes, the evidence that closes
tracker 185, the live confirmation of twin scorer v2, the decision trail that
took the plane from "stays OFF" to "default ON", and the two residuals that
remain open.

**Runs.**
`storm-s05` = `/var/tmp/scale-runs/storm-s05-08301919` (runid `08301919od1w`,
arm **OFF**) · `storm-s06` = `/var/tmp/scale-runs/storm-s06-08302033` (runid
`08302033yg32`, arm **ON**). Profile `t-storm-2.5k` on both, scenario seed
`20260829`, digest `bfe611226220fff3`, 345 labelled incidents
(`launcher.log` of each run).

**Image, both legs:** `netops-correlation` **`c3f627581082`**, code
**`0bfdce1c`** (tracker 185 residual fix: `reconcile.find_continuation` bound).
Both correlation replicas were `--force-recreate`d before s05, so every
`*_total` in each leg's `metrics-final.txt` is **LEG-SCOPED** — no subtraction
appears anywhere below. The arm was verified from BOTH replicas' environment and
from `corr_agg_enabled` on each leg: s05 `corr_agg_enabled 0` on both,
s06 `corr_agg_enabled 1` on both (`metrics-final.txt` of each run).

---

## 1. Phase-by-phase comparison — s05 (OFF) vs s06 (ON)

Source: `report.json` / `report.md` of each run (`phases[*].status`,
`phases[*].notes`, `phases[*].evidence`).

| phase | **s05 (OFF)** | **s06 (ON)** |
|---|---|---|
| preflight | PASS — 26 services running/healthy, consumers live, residue 0 | PASS — 26 services running/healthy, consumers live, residue 0 |
| onboard | PASS — 39.53 → 30.48 /s, ratio **0.771** (floor 0.60), 2,500/2,500, 0 absorbed | PASS — 28.5 → 28.6 /s, ratio **1.00**, 2,500/2,500, 0 absorbed |
| burst | PASS — **900,000 / 900,000** in 900 s @ 1,000/s | PASS — **900,000 / 900,000** in 900 s @ 1,000/s |
| drain | PASS — **1,244.3 s** (budget 2,700), peak lag 440,583, final 33, baseline 9 | PASS — **1,244.6 s**, peak lag 415,749, final 35, baseline 0 |
| correlation_completion | PASS — **95.0 s** (budget 2,700), pending 0 on both replicas, cohorts +23, versions +10,460, `windows_rejected` +0, `profiler_errors` +0 | PASS — **124.3 s**, pending 0 on both replicas, cohorts +23, versions +10,202, `windows_rejected` +0, `profiler_errors` +0 |
| accounting | **PASS — exact**: 900,001 == 900,001 + 0 DLQ + 0 counted rejections; 2,500/2,500 devices; `corr_signals` **54,000** rows; `unexplained_missing` 0 | **PASS — exact**: 900,001 == 900,001 + 0 DLQ + 0 counted rejections; 2,500/2,500 devices; `corr_signals` **54,021** rows; `unexplained_missing` 0 |
| memflat | PASS — carrier **corr-3** 518 → 1,041 → **1,065 MiB** end = **83.2 %** of its 1,280 MiB cap, ×1.023 **FLAT**, settle 123 s; idle corr-4 66 → 70 → 75 MiB (5.9 %) | PASS — carrier **corr-3** 579 → 1,037 → **1,059 MiB** end = **82.7 %** of cap, ×1.021 **FLAT**, settle 123 s; idle corr-4 76 → 80 → 102 MiB (8.0 %) |
| stability | PASS — **0** CommitFailed, **0** UnknownMember, **0** restarts, **0** rebalances over a 2,702 s lifecycle; 167 in-window stalls, **worst 4,122 ms** | PASS — **0 / 0 / 0 / 0** over a 2,753 s lifecycle; 174 in-window stalls, **worst 4,450 ms** |
| cleanup | PASS — 2,500 devices deleted+verified, 0 `mlx-` devices of ANY runid remain, telemetry purged (CH+OS) | PASS — 2,500 devices deleted+verified, 0 `mlx-` devices of ANY runid remain, telemetry purged (CH+OS) |
| **totals** | **9 / 9** | **9 / 9** |

## 2. Measured comparison — every number, with its source file

TTUR rows are each leg's own `ttur.tsv`, produced by the §5.3 query of
`RUN_PLAN_P3_AB_2026-08-29.md` with the storm-aggregate cid
`bb1e46d6-5462-54dc-8465-777c707b9329` excluded and the scope derived per leg
from its own `report.json` (the exact SQL and the scope bounds are recorded in
each run's `ttur-scope.json`). Δ is `(s06 − s05)/s05`.

| metric | **s05 OFF** | **s06 ON** | **Δ ON vs OFF** | source |
|---|--:|--:|--:|---|
| onboard ratio (last/first) | 0.771 | **1.00** | +29.7 % | `report.json` `phases[onboard]` |
| transport drain (s) | 1,244.3 | 1,244.6 | +0.02 % | `report.json` `phases[drain]` |
| correlation completion (s) | **95.0** | **124.3** | **+30.8 % (+29.3 s)** | `report.json` `phases[correlation_completion]` |
| injected == persisted | 900,001 == 900,001 | 900,001 == 900,001 | exact both | `report.json` `phases[accounting]` |
| DLQ lines / counted rejections | 0 / 0 | 0 / 0 | — | `report.json` `phases[accounting]` |
| `corr_signals` rows (run) | 54,000 | 54,021 | +0.04 % | `report.json` `phases[accounting]` |
| devices covered | 2,500 / 2,500 | 2,500 / 2,500 | — | `report.json` `phases[accounting]` |
| incidents (`inc`) | 1,637 | 1,632 | −0.31 % | `ttur.tsv` |
| versions | 10,449 | 10,191 | −2.47 % | `ttur.tsv` |
| versions per incident | 6.38 | 6.24 | −2.19 % | `ttur.tsv` |
| engine signals inside correlated incidents (`sigs`) | 85,837 | **82,359** | **−4.05 %** | `ttur.tsv` |
| **T1 p50 (s)** | 85 | **80** | **−5.88 %** | `ttur.tsv` |
| **T1 p95 (s)** | 866 | **816** | **−5.77 %** | `ttur.tsv` |
| **T1 p99 (s)** | 1,337 | **1,271** | **−4.94 %** | `ttur.tsv` |
| T1 max (s) | 1,766 | 1,717 | −2.77 % | `ttur.tsv` |
| **T-last p95 (s)** | 2,196 | **2,001** | **−8.88 %** | `ttur.tsv` |
| merged / undetermined / confirmed | 186 / 0 / 0 | 162 / 0 / 0 | −12.90 % / — / — | `ttur.tsv` |
| **accuracy (twin scorer v2)** | **345 / 345 = 100.00 %** | **345 / 345 = 100.00 %** | **0.00 pp** | `accuracy-report.json` |
| detection rate / specificity | 1.00 / 1.00 | 1.00 / 1.00 | — | `accuracy-report.json` |
| carrier replica / end rss / % of 1,280 MiB cap | corr-3 / 1,065 MiB / **83.2 %** | corr-3 / 1,059 MiB / **82.7 %** | −0.56 % rss | `report.json` `phases[memflat]` |
| memflat slope vs pending-0 anchor | ×1.023 FLAT | ×1.021 FLAT | — | `report.json` `phases[memflat]` |
| idle replica end rss | corr-4 75 MiB | corr-4 102 MiB | — | `report.json` `phases[memflat]` |
| CommitFailed / UnknownMember / restarts / rebalances | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 | — | `report.json` `phases[stability]` |
| worst in-window loop stall (ms) / in-window stalls | **4,122** / 167 | **4,450** / 174 | +7.96 % / +4.19 % | `report.json` `phases[stability]` |
| `corr_sync_stretch_max_ms` (carrier) | **443.5** | **401.1** | **−9.56 %** | `metrics-final.txt` |
| `corr_sync_overruns_total` | **0** | **0** | — | `metrics-final.txt` |
| `corr_loop_lag_stalls_total` (process lifetime) | 238 | 240 | +0.84 % | `metrics-final.txt` |
| `corr_loop_lag_max_ms` (process lifetime) | 9,134.9 | 13,881.1 | +52.0 % | `metrics-final.txt` |
| syslog prefilter passed / rejected | 54,767 / 845,234 | 54,767 / 845,234 | **digit-identical** | `metrics-final.txt` |
| residue after cleanup | 0 devices, CH+OS purged | 0 devices, CH+OS purged | — | `report.json` `phases[cleanup]` |

**The prefilter stream is digit-identical across the two legs** — 54,767 passed
and 845,234 rejected on both — which is the strongest available statement that
the two arms saw the same workload and that every difference below the prefilter
is the plane's.

### 2.1 The plane's own accounting (s06 only, carrier `netops-correlation-3`, leg-scoped)

Source: `storm-s06-08302033/metrics-final.txt`. All values are from the carrier
replica; the idle replica reports 0 for every plane counter.

| counter | value |
|---|--:|
| `corr_agg_observed_total` | **54,767** |
| `corr_agg_forwarded_total{class="first"}` | 41,928 |
| `corr_agg_forwarded_total{class="state_transition"}` | 3,223 |
| `corr_agg_forwarded_total{class="recovery"}` | 4,708 |
| `corr_agg_forwarded_total{class="contradiction"}` | **0** |
| `corr_agg_forwarded_total{class="new_vantage"}` | **0** |
| `corr_agg_forwarded_total{class="new_modality"}` | **0** |
| `corr_agg_forwarded_total{class="count_threshold"}` | 22 |
| `corr_agg_forwarded_total{class="repeat"}` (late) | 32 |
| **forwarded, total** | **49,913** |
| `corr_agg_suppressed_total` | **4,854** (**8.86 %** of observed) |
| `corr_agg_keys` / `corr_agg_identities` at capture | 32,243 / 27,280 |
| `corr_agg_evicted_total{expired}` / `{ident_expired}` | 17,467 / 96 |
| `corr_agg_evicted_total{capacity}` / `{ident_capacity}` / `{tenant_capacity}` | 0 / 0 / 0 |
| `corr_agg_state_transitions_total` / `corr_agg_recoveries_total` | 7,931 / 4,708 |
| `corr_agg_late_forwarded_total` / `corr_agg_beyond_lateness_total` | 32 / **0** |

**Accounting is exact:** 41,928 + 3,223 + 4,708 + 0 + 0 + 0 + 22 + 32 =
**49,913** forwarded, + **4,854** suppressed = **54,767** = `observed` = the
prefilter's `passed` count on both legs. Zero capacity evictions of any kind and
zero `beyond_lateness` — the plane ran inside its bounds throughout.

**Still unexercised, and stated:** `contradiction`, `new_vantage` and
`new_modality` forwarded **0** on this leg, as on every previous ON leg. The
harness gives each entity exactly one observer and one modality, so those three
classes cannot fire; the plane's behaviour under multi-vantage or multi-modality
telemetry remains **unmeasured**. Closing that needs a workload with a second
independent vantage per entity (harness work, adjacent to tracker 183).

---

## 3. Tracker 185 — closed, with the evidence

Tracker 185's residual was: `reconcile.find_continuation` blocked the event loop
for **27,844 ms** on `storm-s04` — 92.9 % of that run's 29,974 ms worst stall,
with **16 overruns** of the 500 ms sync budget — and passed `stability` only
because `2852ad6f` had widened the Kafka session timeout 30 s → 60 s. The block
was widened around, not bounded (`STORM_S04_2P5K_VERDICT_2026-08-30.md` §4).

**Fix:** `0bfdce1c` — the seam bridge re-derived per candidate PAIR
(`_snap_touches_seam` calling `Node.identity_refs()`, itself O(|node.signals|);
the seam_id → view map rebuilt by scanning the whole tenant inventory per pair;
a `ce | se` union set built and discarded per candidate). It was replaced by
cached `ObjectSnapshot.identity_refs()` / `.grounded_seam_ids()`, a
`_seam_view_index(seams, tenant)` built once per inventory and hard-bounded at
4 entries, cached `SeamView.membership_values()`, and Jaccard computed as
|A∪B| = |A|+|B|−|A∩B| with no union set. Semantics-preserving by construction;
a-before-b view precedence preserved exactly.

**Acceptance evidence, all three tiers:**

| tier | measurement | result | source |
|---|---|---|---|
| Fixture (deterministic) | live-shaped probe: 900-node / 94,500-signal aggregate, 0 edges, tenant-constant seam inventory, 2,500 open objects, 900 candidates all reaching the admission test | sync span **13,787 ms → 46.8 ms (294×)**; signal touches **42,573,150 → 94,500 (451×)**; probe cost now O(1) in the candidate count | commit `0bfdce1c`; `src/correlation/tests/test_find_continuation_bound_185.py` (24 tests, pre-fix algorithm reproduced as the oracle, bound stated as operation counts, mutation-verified) |
| Live, OFF arm | `corr_sync_stretch_max_ms` on the carrier replica | **443.5 ms**, `corr_sync_overruns_total` **0** | `storm-s05-08301919/metrics-final.txt` |
| Live, ON arm | `corr_sync_stretch_max_ms` on the carrier replica | **401.1 ms**, `corr_sync_overruns_total` **0** | `storm-s06-08302033/metrics-final.txt` |

**The worst site moved.** On `storm-s04` the worst sync stretch was **27,844 ms
at `reconcile.find_continuation`**, with 14 of that run's 16 overruns at that
site. On s05 the worst stretch is **443.5 ms at `lifecycle.merge_index`** —
a different site, inside the 500 ms budget, with **0 overruns**. The site that
tracker 185 named is no longer the worst site, and the new worst site does not
breach the budget on either arm. In-window worst loop stalls fell from
29,974 ms (s04) to **4,122 ms** (s05) and **4,450 ms** (s06), a **~7×**
reduction, with 0 CommitFailed / 0 UnknownMember / 0 restarts / 0 rebalances on
both legs.

**Tracker 185 is closed** (row deleted from `docs/TRACKER.md`; this section is
the closure record). What remains from the loop-stall family is *not* 185 — see
§6.1.

---

## 4. Twin scorer v2 — confirmed on live runs

Tracker 191 fixed `scripts/lab/twin/scorer.py` (`06450430`): `affected_includes`
is evaluated over the **union** of the objects touching the story
(`_affected_anywhere`) rather than against one `max()`-selected object, `best`
became `_best_object()` — deterministic on `(tier, node_count, confidence,
correlation_id)` — and reports carry `scorer_version`. Before the fix, 35 of the
345 stories in this corpus were decided by a coin flip on correlation-UUID sort
order, giving an expected score of 93.04 % with 1σ = 0.71 pp
(`P3_PAIR_2P5K_VERDICT_2026-08-30.md` §3).

Until s05/s06 the fixed scorer had only been exercised **offline**, re-scoring
`corr_objects` rows that were still resident from earlier runs. That was the
open clause on tracker 191: *confirm on a live run.*

| leg | `scorer_version` | stories | passed | accuracy | detection | specificity | source |
|---|--:|--:|--:|--:|--:|--:|---|
| s05 (OFF) | **2** | 345 | **345** | **100.00 %** | 1.00 | 1.00 | `storm-s05-08301919/accuracy-report.json` |
| s06 (ON) | **2** | 345 | **345** | **100.00 %** | 1.00 | 1.00 | `storm-s06-08302033/accuracy-report.json` |

**Both legs scored in-line by the deployed harness, both `scorer_version: 2`,
both 345/345, zero template FAILs, spread 0.00 pp.** The instrument that
produced 93.04 % ± 0.71 pp of pure chance now returns the same number twice on
two different arms. Tracker 191's open clause is discharged (row deleted from
`docs/TRACKER.md`).

**What v2 does NOT claim.** 100.00 % is the score of the *corrected* clause on
the 345-story `t-storm-2.5k` corpus. It is not a claim that RCA attribution is
perfect: the remaining known attribution defect is tracker 187 (§6.3) — an
object's final `affected` shrinking below its own version history at CLOSE —
which this corpus's clause, read as a union over objects, does not catch.

---

## 5. The default-ON decision trail

The decision rule is `RUN_PLAN_P3_AB_2026-08-29.md` §7, unchanged throughout the
programme. Its three criteria, each with the numbers that satisfy it and the
document those numbers come from:

| criterion | requirement | **result** | numbers | source doc |
|---|---|---|---|---|
| **1 — neutrality guard** (2 % rung) | TTUR within ±10 % (T1 p95, cross-checked p50 / p99 / T-last p95) **and** accuracy ≥ OFF − 1 pp | **PASS** | Matched fresh-container pair P1 OFF / P2 ON, re-scored on scorer v2: **all TTUR clauses within ±10 %** (T1 p95 −7.98 % vs P1, −0.24 % vs s04; p50 0.00 %; p99 −1.30 %; T-last p95 −4.59 %) and **accuracy 100.00 % / 100.00 %, Δ 0.00 pp** | `P3_PAIR_2P5K_VERDICT_2026-08-30.md` §2/§4.1 + §7 re-grade; scorer fix `06450430` (tracker 191) |
| **2 — the 10 % rung earns it** | ≥20 % fewer signals reaching the engine, TTUR not worse, accuracy not worse | **MET** | L3 vs L1 at `t-storm-10-2.5k`: **−41.0 %** signals (98,636 → 58,194), T1 p95 2,763 → 1,985 s = **−28.2 %**, p50 −35.0 %, p99 −27.4 %, T-last p95 −25.9 %; re-scored accuracy **Δ −0.20 pp** (L1 1002/1005, L3 1000/1005). Honest qualification retained: the engine-side secondary measure was **−19.2 %**, just under the 20 % bar | `P3_AB_2P5K_VERDICT_2026-08-29.md` §3.2; re-score in tracker 191's record |
| **3 — no new gate FAIL** | no phase that PASSed on the corresponding OFF leg FAILs on the ON leg | **PASS** | On the pair: 0 phases PASS→FAIL; `memflat` and `cleanup` both FAIL→PASS; `stability` pre-existing on both (tracker 190's stale gate), 0 ejections either side. On the s05/s06 confirmation pair: **9/9 on both arms, no FAIL of any kind on either** | `P3_PAIR_2P5K_VERDICT_2026-08-30.md` §4.3; this document §1 |

§7's disposition text for that outcome: *"If both hold, criteria 1+2+3 hold and
the rule says default ON."*

**Executed.** `CORR_AGGREGATION_PLANE` was flipped to default ON at **20:31Z on
2026-08-30** and committed as **`a9d9a10c`**:

- `deployment/docker/docker-compose.yml:1201` — `CORR_AGGREGATION_PLANE: ${CORR_AGGREGATION_PLANE:-1}`.
- The **image default stays OFF** (`src/correlation/main.py`) so the A/B overlay
  contract still holds and a bare container is unchanged; the compose file is
  what carries the shipped default.
- Fallback is `CORR_AGGREGATION_PLANE=0` in `deployment/docker/.env`.
- Both replicas verified at deploy: environment `CORR_AGGREGATION_PLANE=1` and
  `corr_agg_enabled 1` on each.

**Confirmed by `storm-s06`:** the first `t-storm-2.5k` run on the shipped
default configuration — **9/9**, accounting exact, memflat 82.7 % of cap FLAT,
accuracy 345/345, stability 0/0/0/0. The decision was taken on the re-scored
pair, and it was then verified on a live run of the configuration it produced.

**Chain of documents**, in the order the decision was actually built:

1. `P3_AB_2P5K_VERDICT_2026-08-29.md` — the five-leg ladder wave; criterion 2 met at the 10 % rung, criteria 1 and 3 failed at the 2 % neutrality rung on a leg confounded by container reuse and a pre-`2852ad6f` image.
2. `STORM_S04_2P5K_VERDICT_2026-08-30.md` — the fresh-container OFF baseline, 9/9, and the measurement that turned tracker 185 into a named residual.
3. `P3_PAIR_2P5K_VERDICT_2026-08-30.md` — the matched fresh-container pair; TTUR half of criterion 1 passed for the first time, criterion 3 passed, accuracy clause failed **on the instrument**, diagnosed to `scorer.py` and filed as tracker 191.
4. `06450430` (tracker 191) — the scorer fix, plus a re-score of all 10 surviving legs from resident `corr_objects` at zero rig cost.
5. `0bfdce1c` (tracker 185) — the `find_continuation` bound.
6. `P3_PAIR_2P5K_VERDICT_2026-08-30.md` **§7 re-grade** — criterion 1 re-applied on the v2 numbers: **PASS**.
7. `a9d9a10c` — the flip, deployed 20:31Z.
8. This document + `storm-s06` — the confirmation on the shipped default.

---

## 6. Residuals — the two things this close-out does NOT close

### 6.1 An un-instrumented ~9–14 s loop block on the cleanup / re-key path

Both legs recorded a **process-lifetime** `corr_loop_lag_max_ms` far larger than
anything inside the stability window:

| leg | in-window worst stall | process-lifetime `corr_loop_lag_max_ms` | source |
|---|--:|--:|---|
| s05 (OFF) | 4,122 ms | **9,134.9 ms** | `report.json` `phases[stability]` · `metrics-final.txt` |
| s06 (ON) | 4,450 ms | **13,881.1 ms** | `report.json` `phases[stability]` · `metrics-final.txt` |

On s05 the block is locatable in time: a **9,135 ms** loop block at
**20:11:54Z**, during cleanup — i.e. **outside** the stability observation
window, which is why neither leg's `stability` phase saw it. Its signature is a
period of silence followed by a burst of *"continued under re-keyed window
(identity adopted, no tombstone)"*, and **no `sync_span` site is attributed to
it** — `corr_sync_stretch_max_ms` stayed at 443.5 ms with 0 overruns, so the
block happened somewhere the 185 instrumentation does not cover. Both legs also
showed continuing 1–3 s stalls after the run had finished.

s06's lifetime maximum is larger (13,881 ms) but has the same shape and the same
cleanup-path timing. **The plane is not implicated:** the two legs differ by a
factor the in-window numbers do not reproduce (4,122 vs 4,450 ms), and both
values sit outside the measured window.

This is **not** tracker 185 — 185's site is bounded and proven bounded (§3). It
is a distinct, un-instrumented path. Filed as a **new tracker row (192)**: it
needs a `sync_span` around the re-key/cleanup path and a bound in the same style
as `0bfdce1c` (algebraic where possible, chunk-and-yield otherwise).

### 6.2 No `.dockerignore` at the repository root

`deployment/docker/docker-compose.yml:1161` (and seven other services) builds
with `context: ../..`, i.e. the whole repository root. There is **no
`.dockerignore` anywhere in the tree** (verified: `find … -name .dockerignore`
returns nothing), and the root currently measures **16 GB** — dominated by
gitignored-but-not-dockerignored `data/`.

It is **benign today**: `Dockerfile.correlation` copies only
`src/correlation/requirements.txt` and `src/correlation/`, so nothing unwanted
reaches the image. What it costs is a 16 GB context transfer to the daemon on
every build, cache invalidation on any unrelated file change under the root, and
a latent leak the moment any Dockerfile gains a broader `COPY`. Filed as a
**new tracker row (193)**, Low.

### 6.3 Known and already tracked (not new here)

- **Tracker 187** — an object's final `affected` shrinks below its own version
  history at CLOSE (3–5 `bgp_peer_flap` stories per 1,005-story leg,
  arm-independent, same story ids on both arms). This is the honest remaining
  **accuracy** defect; scorer v2's union-over-objects reading does not catch it
  because the union is over objects, not versions.
- **Tracker 190** — the harness `stability` gate is still derived from a
  hard-coded 30,000 ms (`session_timeout_ms: 30000` appears in both legs'
  `phases[stability]` evidence) while the engine runs a 60 s session timeout.
  With worst in-window stalls now ~4 s it no longer bites; it is still wrong.

---

## 7. Caveats

1. **Two legs, one session, one day.** s05 and s06 are a matched pair on one
   image with a fresh-container reset before s05, but they are a single pair.
   No distribution is characterised. Where a spread is needed, use the
   OFF-vs-OFF spread measured on the earlier pair (8.07 % on T1 p95,
   `P3_PAIR_2P5K_VERDICT_2026-08-30.md` §4.1).
2. **Replica idle asymmetry persists.** On both legs `netops-correlation-3`
   carried essentially the whole tenant partition (1,065 / 1,059 MiB) and
   `netops-correlation-4` was nearly idle (75 / 102 MiB, all plane counters 0).
   This is the harness's `producer_key=tenant` single-key partitioning, not a
   rebalance failure — but the pair measures **one replica's** behaviour and
   says nothing about the plane under a balanced two-partition load.
3. **Completion moved the wrong way** — 95.0 s → 124.3 s, +29.3 s. It is 4.6 %
   of a 2,700 s budget and every TTUR percentile moved the *other* way, so it
   does not change the verdict; it is recorded rather than explained.
4. **The plane's `contradiction` / `new_vantage` / `new_modality` classes have
   still never fired.** See §2.1.
5. **Criterion 2 was not re-measured here.** The −41.0 % figure is L3-vs-L1 from
   the ladder wave on an earlier image (`000e7bc3`), carrying that wave's
   caveats including the −19.2 % engine-side secondary measure. Only its
   accuracy was recomputed, on scorer v2.
6. **The site attribution for the s05 worst sync stretch** (`lifecycle.merge_index`)
   comes from the correlation container's `sync_span` log line, not from a file
   in the run directory; the magnitude (443.5 ms) and the overrun count (0) are
   in `metrics-final.txt`.
7. **Tombstone debt keeps growing** — 67,927 suppressed device entries after s05
   (`launcher.log`). Tracker 175, unrelated to this programme, but it is the
   reason onboard rates are not comparable across distant runs.

---

## 8. Artefacts

- Run dirs: `/var/tmp/scale-runs/storm-s05-08301919`,
  `/var/tmp/scale-runs/storm-s06-08302033` — each with `report.json`,
  `report.md`, `accuracy-report.json`, `accuracy-report.md`, `ttur.tsv`,
  `ttur-scope.json`, `metrics-final.txt`, `ground-truth.json`,
  `correlation-completion.json`, `lag-curve.json`, `twin-score.log`,
  `launcher.log`, `state.json`.
- Commits: `0bfdce1c` (tracker 185 bound), `06450430` (tracker 191 scorer v2),
  `a9d9a10c` (default-ON flip, `docker-compose.yml:1201`).
- Decision rule: `RUN_PLAN_P3_AB_2026-08-29.md` §7.
- Prior verdicts: `P3_AB_2P5K_VERDICT_2026-08-29.md`,
  `STORM_S04_2P5K_VERDICT_2026-08-30.md`,
  `P3_PAIR_2P5K_VERDICT_2026-08-30.md` (incl. its §7 re-grade).
- Programme: `P4_PROGRAMME_WRITEUP_2026-08-29.md` §7/§8.
- Invariants: `docs/audit/INVARIANTS.md` §10.
