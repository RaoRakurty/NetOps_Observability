# P3 Aggregation plane — matched fresh-container OFF/ON pair at `t-storm-2.5k` (2026-08-30)

**Runs.** `P1` = `/var/tmp/scale-runs/pair-2p5k-off-08301624` (runid
`083016240km5`, arm **OFF**) · `P2` = `/var/tmp/scale-runs/pair-2p5k-on-08301732`
(runid `083017321c8x`, arm **ON**) · corroborating second OFF point
`storm-s04` = `/var/tmp/scale-runs/storm-s04-08300637` (runid `08300637l2bv`).
Driver `/var/tmp/scale-runs/ab-pair-driver.log`, state
`/var/tmp/scale-runs/ab-pair-state.json`. Plan:
`RUN_PLAN_P3_PAIR_2026-08-30.md`; decision rule
`RUN_PLAN_P3_AB_2026-08-29.md` §7, unchanged.

**Image, both legs and s04:** `netops-correlation` **`34d113a3a8bb`** (built
2026-08-30 06:24:42Z), code **`2852ad6f`**. Both correlation replicas
`--force-recreate`d before EACH leg, so every `*_total` in each leg's
`metrics-final.txt` is **LEG-SCOPED** — no subtraction anywhere in this
document. Arm verified from BOTH replicas' env AND `corr_agg_enabled` before and
after every switch (`ab-leg.json`): P1 `env=null / 0.0` on both, P2 `env="1" /
1.0` on both, restore `env=unset / 0.0` on both.

---

## 0. Verdict in one paragraph

The matched pair **clears the TTUR half of the neutrality guard for the first
time** — T1 p95 **−7.98 %** vs P1 and **−0.24 %** vs storm-s04, inside ±10 %
against both OFF points, with p50 / p99 / T-last p95 all inside too — and
**clears criterion 3 outright**: no phase that PASSed on P1 FAILs on P2, and two
that FAILed on P1 (`memflat`, `cleanup`) PASS on P2. **The only failing clause in
the whole rule is accuracy: 92.46 % vs 94.20 %, −1.74 pp against a −1.00 pp
floor — 6 stories of 345.** §3 shows, deterministically and to the story, that
those 6 stories are **not an engine or plane result**: on every leg the engine
attributes the labelled cause correctly, and the twin scorer's
`affected_includes` clause is decided by a **coin flip on correlation-UUID sort
order**. Under the union reading the clause is plainly asking for, **all three
legs score 345/345 = 100 %** and the accuracy clause passes with room. The pair
therefore fails §7 on its letter and passes it on its substance; the defect it
exposed is in the instrument (**tracker 191**), not in the plane.

---

## 1. Harness phases — all three legs

| phase | **P1 (OFF)** | **P2 (ON)** | storm-s04 (OFF) |
|---|---|---|---|
| preflight | PASS — 26 services, consumers live | PASS — 26 services, consumers live | PASS |
| onboard | PASS — 35.7 → 27.8 /s, ratio **0.78** (floor 0.60) | PASS — 41.9 → 27.8 /s, ratio **0.66** | PASS — 37.4 → 31.4 /s, ratio **0.84** |
| burst | PASS — **900,000 / 900,000** @ 1,000/s | PASS — **900,000 / 900,000** @ 1,000/s | PASS — 900,000 / 900,000 |
| drain | PASS — **1,423 s** (budget 2,700), peak lag 441,799, final 7 | PASS — **1,340 s**, peak lag 418,128, final 6 | PASS — 1,384 s, peak lag 418,448 |
| correlation_completion | PASS — **223 s**, pending 0 on both replicas, cohorts +22, versions +10,565, `windows_rejected` +0, `profiler_errors` +0 | PASS — **195 s**, pending 0 on both, cohorts +21, versions +10,333, `windows_rejected` +0, `profiler_errors` +0 | PASS — 144 s, cohorts +22, versions +10,546 |
| accounting | **PASS — exact**: 900,001 == 900,001 + 0 DLQ + 0 rejections; 2,500/2,500 devices; `corr_signals` **54,001** rows; `unexplained_missing` 0 | **PASS — exact**: 900,001 == 900,001 + 0 DLQ + 0 rejections; 2,500/2,500 devices; `corr_signals` **54,022** rows; `unexplained_missing` 0 | PASS — exact; `corr_signals` 54,007 rows |
| memflat | **FAIL** — carrier **corr-3** 489 → 1,014 → **1,093 MiB** end = **85.4 %** of its 1,280 MiB cap (> 85.0 % gate), curve FLAT ×1.078, settle 123 s; idle corr-4 82 → 84 → 110 MiB | **PASS** — carrier **corr-4** 626 → 1,012 → **1,068 MiB** end = **83.4 %** of cap, FLAT ×1.055, settle 123 s; idle corr-3 70 → 73 → 84 MiB | PASS — carrier corr-4 515 → 1,060 → 1,018 MiB = 79.5 %, ×0.961 |
| stability | **FAIL** — worst loop stall **32,446 ms** > the harness's 30,000 ms gate; **0** CommitFailed, **0** UnknownMember, **0** restarts, **0** rebalances, 232 stalls, lifecycle 3,030 s | **FAIL** — worst loop stall **30,468 ms** > 30,000 ms; **0 / 0 / 0 / 0**, 236 stalls, lifecycle 2,940 s | **PASS** — worst stall **29,974 ms** (26 ms under the gate); 0 / 0 / 0 / 0, 226 stalls |
| cleanup | **FAIL** — OpenSearch purge STALLED, 736,001 docs left after 152 s (server-side task still running); remediated by the driver's `--cleanup-only` pass before P2: **0 docs, 0 CH rows, 0 `mlx-` devices, verified** | **PASS** — 2,500 devices deleted+verified, 0 `mlx-` devices of ANY runid remain, telemetry purged (CH+OS) | PASS — residue 0 |
| **totals** | **6 / 9** | **8 / 9** | **9 / 9** |

> The run plan's brief carried P1 as 7/9; the leg's own `report.json` records
> **three** FAILs (`memflat`, `stability`, `cleanup`), so P1 is **6/9**. The
> `cleanup` FAIL is a harness/OpenSearch delete-by-query stall, not an engine
> result, and it was cleared to a verified zero before P2 launched
> (`ab-pair-driver.log`, 17:31Z: *"0 device deletes issued, 0 remain
> (re-verified); ClickHouse rows left 0, OpenSearch docs left 0"*).

**The `stability` gate is a knife edge, and all three legs sit on it.** Every leg
recorded **0 CommitFailedError, 0 UnknownMemberIdError, 0 consumer restarts, 0
rebalances** — the consumer was never ejected on any of them. The sole
discriminator is one number against one threshold: **32,446 / 30,468 / 29,974 ms
against 30,000 ms.** That threshold is `scripts/scale-miniladder.py:1876`
`KAFKA_SESSION_TIMEOUT_MS`, derived from a Kafka session timeout `2852ad6f`
widened 30 s → 60 s — i.e. **tracker 190**, the gate that no longer measures what
it names. s04 "passed" it by 26 ms. On the live 60 s timeout all three legs pass
with 29.5 s of margin.

---

## 2. §6-style comparison table — the pair, with s04 as the second OFF point

Rung `t-storm-2.5k` (2 %). Δ columns are `(P2 − OFF)/OFF`; the last column is the
**OFF-vs-OFF spread** `|P1 − s04| / mean`, which is what §7's ±10 % must be read
against. TTUR rows are each leg's own `ttur.tsv` (§5.3 clean scope, storm-
aggregate cid `bb1e46d6-5462-54dc-8465-777c707b9329` excluded, scope derived per
leg from its own `report.json`; `ttur-scope.json` in each run dir).

| metric | **P1 OFF** | **P2 ON** | s04 OFF | §6b proj. | **Δ P2 vs P1** | Δ P2 vs s04 | **OFF spread** |
|---|--:|--:|--:|--:|--:|--:|--:|
| signals reaching the engine (Σ `forwarded{class}` vs OFF promoted `corr_signals`) | 54,001 | **49,910** | 54,007 | 0 % | **−7.58 %** | −7.59 % | 0.01 % |
| — `corr_agg_observed_total` | 0 (plane off) | **54,767** | 0 | — | — | — | — |
| — `corr_agg_suppressed_total` | 0 | **4,857** (**8.87 %**) | 0 | — | — | — | — |
| — forwarded `first` | 0 | 41,921 | 0 | — | — | — | — |
| — forwarded `state_transition` | 0 | 3,223 | 0 | — | — | — | — |
| — forwarded `recovery` | 0 | 4,713 | 0 | — | — | — | — |
| — forwarded `contradiction` | 0 | **0** | 0 | — | — | — | — |
| — forwarded `new_vantage` | 0 | **0** | 0 | — | — | — | — |
| — forwarded `new_modality` | 0 | **0** | 0 | — | — | — | — |
| — forwarded `count_threshold` | 0 | 23 | 0 | — | — | — | — |
| — forwarded `repeat` (late) | 0 | 30 | 0 | — | — | — | — |
| engine signals inside correlated incidents (`sigs`) | 86,624 | **76,036** | 88,672 | — | **−12.22 %** | −14.25 % | 2.34 % |
| completion (s) | 223 | **195** | 144 | — | **−12.56 %** | +35.42 % | **43.05 %** |
| transport drain (s) | 1,423 | **1,340** | 1,384 | — | −5.83 % | −3.18 % | 2.78 % |
| **T1 p50 (s)** | 81 | **81** | 68 | — | **0.00 %** | +19.12 % | **17.45 %** |
| **T1 p95 (s)** | 902 | **830** | 832 | — | **−7.98 %** | **−0.24 %** | **8.07 %** |
| **T1 p99 (s)** | 1,312 | **1,295** | 1,297 | — | **−1.30 %** | −0.15 % | 1.15 % |
| T1 max (s) | 1,807 | 1,734 | 1,869 | — | −4.04 % | −7.22 % | 3.37 % |
| **T-last p95 (s)** | 2,374 | **2,265** | 2,251 | — | **−4.59 %** | +0.62 % | 5.32 % |
| **accuracy (stories pass %)** | **94.20 %** (325/345) | **92.46 %** (319/345) | **94.49 %** (326/345) | — | **−1.74 pp** | −2.03 pp | **0.29 pp** |
| incidents / versions / v-per-inc | 1,632 / 10,554 / 6.47 | **1,532 / 9,094 / 5.94** | 1,632 / 10,535 / 6.46 | — | −6.13 % / −13.83 % / −8.19 % | −6.13 % / −13.68 % / −8.05 % | 0.00 % / 0.18 % / 0.15 % |
| merged / undetermined / confirmed | 191 / 0 / 0 | 147 / 0 / 0 | 194 / 0 / 0 | — | −23.04 % | −24.23 % | 1.56 % |
| evictions `corr_agg_evicted{expired}` / `{ident_expired}` / `{capacity}` / `{ident_capacity}` / `{tenant_capacity}` | 0 / 0 / 0 / 0 / 0 | **18,254 / 97 / 0 / 0 / 0** | 0 / 0 / 0 / 0 / 0 | — | — | — | — |
| `corr_agg_keys` / `corr_agg_identities` at capture | 0 / 0 | **31,459 / 27,279** | 0 / 0 | — | — | — | — |
| `corr_engine_windows_rejected_total` | 0 | **0** | 0 | — | — | — | — |
| carrier replica / end rss / % of 1,280 MiB cap | **corr-3** / 1,093 MiB / **85.4 %** | **corr-4** / 1,068 MiB / **83.4 %** | corr-4 / 1,018 MiB / 79.5 % | — | −2.29 % | +4.91 % | 7.11 % |
| idle replica end rss | corr-4 110 MiB | corr-3 84 MiB | corr-3 95 MiB | — | — | — | — |
| worst loop stall (ms) / stalls | 32,446 / 232 | **30,468 / 236** | 29,974 / 226 | — | −6.10 % | +1.65 % | 7.92 % |
| **gate FAILs** | **memflat · stability · cleanup** | **stability** | **none** | — | **2 cleared, 0 new** | +1 (stability) | — |

**Plane accounting is exact:** 41,921 + 3,223 + 4,713 + 0 + 0 + 0 + 23 + 30 =
**49,910** forwarded, + **4,857** suppressed = **54,767** = `observed`. Zero
`corr_agg_beyond_lateness_total`; 30 late arrivals forwarded
(`corr_agg_late_forwarded_total`).

**Measured vs §6b projected, stated explicitly as §6 requires.** §6b projected
**0 %** reduction at the 2 % rung. Measured: **−7.58 %** on the §6 measure and
**−12.22 %** on the engine-side `sigs` measure, with an 8.87 % suppression rate.
The projection understated what the plane finds at 2 %: the rung is defined by
storm *share*, but ordinary flap/recovery dynamics still produce
same-(entity, kind, severity, minute) repeats that the plane folds. This is a
finding about the projection, not a rounding error — and it is the second
independent measurement of it (L5 measured 9.07 % suppressed on the same
scenario; P2 measures 8.87 %, and both legs observed **exactly 54,767**
signals, which is the determinism of the workload showing through).

**Why `new_vantage`, `new_modality` and `contradiction` all forwarded 0**
(asked by the run brief; answered against the code, not inferred). `delta_class`
(`src/correlation/aggregation.py:456`) reaches NEW_VANTAGE only at rule 4, when
`observer not in prev_state.vantages` for an existing `AggKey`
`(tenant, entity_id, kind, severity, minute-bucket)`. In this workload the
observer is stamped from the event's own device — `main.py:8814`
`observer_id=str(ev.get("device") or "")`, and `golden_wire.py:175` does the same
for the metric lane — while `entity_id` is that same device or one of its
children (`device:ifName`, `device:peer`). **Every key therefore has exactly one
possible observer**, so `prev_state.vantages` is a singleton that can never grow,
and NEW_VANTAGE is structurally unreachable. NEW_MODALITY is 0 for the identical
reason: one `ModalityClass` (device telemetry) per key. CONTRADICTION is 0
because both of its rules (rule 1 and the key-level fallback at rule 3) require a
**different observer** to disagree about the **same entity** — the ground truth's
`contradictions` are a *different device* reporting healthy, which is a different
`entity_id`, hence a different `AggKey` the plane cannot join. These three
classes are not dead code: they need a second, independent vantage on one entity
(a probe agent, a flow exporter's `sampler`, `cloud:<acct>:<region>`,
`<source_system>:<integration_id>`, or `appid:fusion`), and the scale harness
emits none. **Nothing here is a defect; it is a coverage gap in the workload**,
and it means the pair measured only the FIRST/TRANSITION/RECOVERY/THRESHOLD half
of the plane.

---

## 3. The 6-story accuracy drop — resolved to the story, and to the line of code

This is the question the pair was run to answer, and it has a deterministic
answer.

### 3.1 The drop is entirely one template, and the failing clause is always the same

| template | stories | P1 OFF | **P2 ON** | s04 OFF |
|---|--:|--:|--:|--:|
| `local_link_fault` | 150 | 150 | 150 | 150 |
| `bgp_peer_flap` | 100 | 100 | 100 | 100 |
| `ospf_adjacency_flap` | 60 | 60 | 60 | 60 |
| `upstream_link_failure` | 20 | **14** | **8** | **14** |
| `enterprise_outage` | 15 | 1 | 1 | 2 |
| **total** | **345** | **325 (94.20 %)** | **319 (92.46 %)** | **326 (94.49 %)** |

The three unchained templates are **310/310 on every leg**. The entire −6 is
`upstream_link_failure`, 14 → 8. Detection is **100 %** and specificity **100 %**
on all three legs; **every FAIL on every leg — 20 on P1, 26 on P2, 19 on s04, 65
of 65 — is the same clause, `affected_includes`, and the missing set is exactly
`{the story's `cause_entity.device`}`, never any other device and never more than
one.**

### 3.2 Story-level flip table (P1 → P2), with s04 as the control

| story | template | **P1** | **P2** | **s04** | P2's failing clause |
|---|---|---|---|---|---|
| I0002 | upstream_link_failure | PASS | **FAIL** | PASS | `affected_includes` missing `mlx-…-01118` (= `cause_entity.device`) |
| I0004 | upstream_link_failure | PASS | **FAIL** | PASS | missing `mlx-…-00116` (cause) |
| I0005 | upstream_link_failure | PASS | **FAIL** | **FAIL** | missing `mlx-…-01553` (cause) |
| I0009 | upstream_link_failure | PASS | **FAIL** | PASS | missing `mlx-…-02257` (cause) |
| I0010 | upstream_link_failure | PASS | **FAIL** | **FAIL** | missing `mlx-…-02101` (cause) |
| I0014 | upstream_link_failure | PASS | **FAIL** | PASS | missing `mlx-…-00745` (cause) |
| I0015 | upstream_link_failure | PASS | **FAIL** | **FAIL** | missing `mlx-…-02017` (cause) |
| I0019 | upstream_link_failure | PASS | **FAIL** | PASS | missing `mlx-…-00681` (cause) |
| I0020 | upstream_link_failure | PASS | **FAIL** | PASS | missing `mlx-…-01772` (cause) |
| I0342 | enterprise_outage | PASS | **FAIL** | FAIL | missing `mlx-…-00526` (cause) |
| I0001 | upstream_link_failure | **FAIL** | **PASS** | PASS | — recovered on P2 |
| I0008 | upstream_link_failure | **FAIL** | **PASS** | PASS | — recovered on P2 |
| I0016 | upstream_link_failure | **FAIL** | **PASS** | PASS | — recovered on P2 |
| I0343 | enterprise_outage | **FAIL** | **PASS** | FAIL | — recovered on P2 |

Net **−6** (10 lost, 4 recovered). The control column is the point: **on the two
OFF legs the same stories churn just as hard.** P1 vs s04 — same arm, same image,
same scenario — disagree on **13 of 345** stories (6 one way, 7 the other) for a
net of +1. P1 vs P2 disagree on **14**. The churn magnitude is identical; only
the draw differs. McNemar exact, two-sided: **P1 vs P2 p = 0.180**, **P1 vs s04
p = 1.0**. On the accuracy evidence alone the pair cannot reject the null.

The full 20-story `upstream_link_failure` matrix, which is the cleanest picture:

| story | P1 | P2 | s04 | | story | P1 | P2 | s04 |
|---|---|---|---|---|---|---|---|---|
| I0001 | FAIL | PASS | PASS | | I0011 | PASS | PASS | PASS |
| I0002 | PASS | FAIL | PASS | | I0012 | FAIL | FAIL | PASS |
| I0003 | FAIL | FAIL | PASS | | I0013 | PASS | PASS | PASS |
| I0004 | PASS | FAIL | PASS | | I0014 | PASS | FAIL | PASS |
| I0005 | PASS | FAIL | FAIL | | I0015 | PASS | FAIL | FAIL |
| I0006 | PASS | PASS | FAIL | | I0016 | FAIL | PASS | PASS |
| I0007 | PASS | PASS | FAIL | | I0017 | FAIL | FAIL | FAIL |
| I0008 | FAIL | PASS | PASS | | I0018 | PASS | PASS | PASS |
| I0009 | PASS | FAIL | PASS | | I0019 | PASS | FAIL | PASS |
| I0010 | PASS | FAIL | FAIL | | I0020 | PASS | FAIL | PASS |

Ten of twenty flip between the two **OFF** legs.

### 3.3 The engine did the same thing on all three legs

Before asking whether the plane changed the outcome, check whether it changed the
output. It did not, to a degree that is itself evidence:

| structural quantity | P1 OFF | **P2 ON** | s04 OFF |
|---|--:|--:|--:|
| `corr_objects` correlation ids touching the run's devices | **1,633** | **1,633** | **1,633** |
| stories with 1 touching object / 2 / ≥12 | 310 / 20 / 15 | **310 / 20 / 15** | 310 / 20 / 15 |
| objects with `node_count` 48 (the cohort object of each ULF story) | 20 | **20** | 20 |
| stories where **≥2 objects tie at the top verdict tier** | **35** | **35** | **35** |
| of those, stories where **exactly one** object's `affected` holds the cause device | **35** | **35** | **35** |
| promoted signals persisted (`corr_signals` rows, run-scoped) | 54,001 | 54,022 | 54,007 |

Every `upstream_link_failure` story decomposes identically on every leg into
**two** `suspected` objects: a **1-node** `sig.ent.access.local-link-fault`
object whose `affected` is `{"interfaces":["<cause-device>:<cause-if>"]}`, and a
**48-node** `sig.ent.middle-mile.lastmile-circuit-flap` cohort object whose
`affected.devices` lists the 24 blast-radius devices and **not** the cause. The
engine puts the labelled cause in the first object on **every leg, in every one
of the 35 tied stories, on all three legs — 105 of 105**.

### 3.4 The mechanism: `max()` over tied objects is a coin flip on UUID order

`scripts/lab/twin/scorer.py:664`:

```python
best = max(objects, key=lambda o: _TIER_RANK.get(o["verdict_tier"], 0), default=None)
...
if rca.get("affected_includes"):
    missing = []
    if best:
        for d in rca["affected_includes"]:
            if (prefix + d) not in (best.get("affected") or ""):
                missing.append(d)
```

The clause is evaluated against **one** object — `best` — not against the set of
objects that touch the story. When several objects tie at the top tier (and on
these templates they all tie at `suspected`), Python's `max` returns the **first
maximal element in list order**, and that list is built at
`scorer.py:432` as

```python
out[story_id] = [rows[key] for key in sorted(rows) if hits.get(key, set()) & want]
```

— i.e. **sorted by `(tenant, correlation_id)`**, and with one tenant that is
**sorted by correlation UUID**. The correlation id is a uuid5 over content that
embeds the run id, so it is redrawn every run. **Whether a story passes is
therefore decided by whether the cause-bearing object's random UUID happens to
sort below its sibling's.**

**Proven, not inferred.** For each of the 20 tied `upstream_link_failure`
stories on each leg, the predicate *"the lowest-UUID top-tier object's `affected`
contains the cause device"* was evaluated directly against
`netops.corr_current FINAL` and compared with the scorer's recorded verdict:

| leg | tied ULF stories | lowest-UUID object holds the cause | **scorer PASS** | prediction matches recorded verdict |
|---|--:|--:|--:|--:|
| P1 OFF | 20 | **14** | **14** | **20 / 20** |
| **P2 ON** | 20 | **8** | **8** | **20 / 20** |
| s04 OFF | 20 | **14** | **14** | **20 / 20** |

**60 of 60, exact.** The `upstream_link_failure` score of a leg *is* the number of
UUID coin flips it won.

### 3.5 The counterfactual: the union reading scores 345/345 on every leg

Asking instead *"does **any** object touching this story name the cause?"* —
which is what the clause's own wording, "missing from object.affected", is
plainly after:

| leg | tied ULF (n=20) union-PASS | tied `enterprise_outage` (n=15) union-PASS | **whole run under the union reading** |
|---|--:|--:|--:|
| P1 OFF | **20 / 20** | **15 / 15** | **345 / 345 = 100 %** |
| **P2 ON** | **20 / 20** | **15 / 15** | **345 / 345 = 100 %** |
| s04 OFF | **20 / 20** | **15 / 15** | **345 / 345 = 100 %** |

In every one of the 105 tied stories exactly **one** object holds the cause — so
the union reading is not a loosening that would hide a regression; it is the
difference between reading one object and reading the two-to-twenty-five the
scorer already fetched. `enterprise_outage` scores 1–2 of 15 today for exactly
the same reason at a worse ratio: 12–25 objects tie, so the cause-bearing one
wins the sort about 1/n of the time.

### 3.6 What the instrument's noise floor actually is

Model the 35 tied stories as independent draws where the cause-bearing object
wins the sort with probability 1/n (n = number of tied objects — n = 2 for the 20
ULF stories, 12–25 for the 15 `enterprise_outage` ones):

- expected score **310 + 11.0 = 321.0 / 345 = 93.04 %**
- **1σ = 2.44 stories = 0.71 pp**; **2σ = ±1.41 pp**

Observed: **94.20 % (+1.6σ), 92.46 % (−0.8σ), 94.49 % (+1.9σ)** — all three legs
inside a 2σ band of a pure coin flip, and **P2 is the closest of the three to the
model's mean.** Two consequences that matter beyond this pair:

1. **§7's ±1 pp accuracy floor is narrower than the instrument's own 2σ noise
   band (±1.41 pp).** The rule cannot be satisfied reliably by any build.
2. **The ratified Option A SLO clause "accuracy ≥ 93 %"
   (`P4_PROGRAMME_WRITEUP_2026-08-29.md` §8) sits at 93.04 % — the coin flip's
   exact mean.** As instrumented, that clause is a ~50/50 pass on every run,
   independent of the product. It must be re-measured after tracker 191.

### 3.7 Determination, and confidence

**Neither (a) nor (b) as posed. The cause is (d): a measurement defect in the
twin scorer that manufactures per-story variance.** Stated against the two
hypotheses the brief named:

- **(a) plane effect — RULED OUT, on four independent grounds.** (i) The engine's
  output is structurally identical across arms: 1,633 objects, 35 tied stories,
  20 48-node cohorts, cause held by exactly one object in 105 of 105 cases.
  (ii) The plane cannot remove a device's only evidence *by construction*:
  `AggKey` is `(tenant, entity_id, kind, severity, minute)` and the FIRST
  observation of every key is always forwarded (`aggregation.py:233`
  `FORWARDED_CLASSES` = everything but REPEAT), so suppression only ever drops
  repeats of the **same entity** inside one minute — 4,857 of 54,767 (8.87 %).
  (iii) The plane is lossless on the record the scorer reads: `corr_signals`
  54,022 rows on P2 vs 54,001 / 54,007 on the OFF legs (0.04 % apart).
  (iv) The failing device is the cause device on **every leg including both OFF
  legs**, in identical proportion to the number of tied objects — an
  arm-independent quantity.
- **(b) run-to-run variance on the chained templates — TRUE, but it is the
  symptom.** The variance is real (13–14 discordant stories per pair, McNemar
  p = 0.18 / 1.0), and §3.4 identifies its generator exactly, so it does not have
  to be characterised statistically.

**Confidence: very high — this is a reproduction, not an inference.** The
mechanism was read from `scorer.py:432` and `:664`, then used to predict every
one of the 60 tied-story verdicts across three legs from ClickHouse state alone,
matching **60/60**. The union counterfactual was computed from the same rows
(105/105 stories hold the cause in exactly one object). Nothing in the chain
depends on a model assumption.

**A material correction to tracker 187.** 187 states the defect as *"the engine's
object for the site does not list the labelled cause … the chain is attributed to
the symptom-bearing access devices, not to the upstream cause entity."* **That
premise is false as measured.** The engine emits an object that names the cause
entity in every one of the 105 tied stories on all three legs; what it does not
do is fold the cause object and the cohort object into one incident. Whether
that folding is desirable is a real product question — but it is a *different*
question from the one 187 asks, 187's evidence for its claim came from this same
scorer, and 187 is currently blocked on tracker 184 on the strength of it.
**187's premise must be re-derived after 191 lands.**

---

## 4. §7 applied literally

### 4.1 Criterion 1 — neutrality guard (2 % rung, P2 vs P1, corroborated by s04)

Deltas are `(ON − OFF)/OFF`; the spread column is `|P1 − s04| / mean`, measured
on this image, and it **replaces the pre-`2852ad6f` 13.11 %** the run plan told us
to stop using.

| clause | threshold | **vs P1 (matched)** | vs s04 | **OFF-vs-OFF spread** | verdict |
|---|---|--:|--:|--:|---|
| **T1 p95 within ±10 %** | ±10 % | 902 → 830 = **−7.98 %** | 832 → 830 = **−0.24 %** | **8.07 %** | **PASS — inside ±10 % against BOTH, and in the better direction** |
| T1 p50 (cross-check) | ±10 % | 81 → 81 = **0.00 %** | 68 → 81 = +19.12 % | **17.45 %** | inside vs P1; vs s04 the move is smaller than the OFF-vs-OFF spread itself → **noise** |
| T-last p95 (cross-check) | ±10 % | 2,374 → 2,265 = **−4.59 %** | 2,251 → 2,265 = **+0.62 %** | 5.32 % | **inside against both** |
| T1 p99 (cross-check) | ±10 % | 1,312 → 1,295 = **−1.30 %** | 1,297 → 1,295 = −0.15 % | 1.15 % | **inside against both** |
| **accuracy ≥ OFF − 1 pp** | ≥ −1.00 pp | 94.20 % → 92.46 % = **−1.74 pp** | 94.49 % → 92.46 % = −2.03 pp | 0.29 pp | **FAIL — 0.74 pp beyond the floor** |

**Criterion 1 FAILS, and the ONLY failing clause is accuracy.** Every TTUR clause
passes against both OFF points — the first time in the programme this has
happened, and a direct reversal of L5, where T1 p95 was +28.9 %/+13.1 %. Stated
exactly as the brief requires: **the sole failing clause is accuracy; it misses
by 0.74 pp beyond the −1.00 pp floor; that is 6 stories of 345 (a −1.74 pp move
where 1 pp = 3.45 stories); and §3 shows those 6 stories are decided by
correlation-UUID sort order in `scorer.py:664`, not by the engine — under the
union reading of the same clause all three legs score 345/345 and this clause
passes with +5.80 pp of room.**

Note also that the OFF-vs-OFF T1 p95 spread has **tightened from 13.11 % to
8.07 %** on the post-`2852ad6f` image. The rule's ±10 % threshold is now wider
than the benchmark's own noise, which is the condition the threshold was always
supposed to be judged under.

### 4.2 Criterion 2 — the 10 % rung earns it — **MET (already; not re-tested here)**

Carried forward verbatim from `P3_AB_2P5K_VERDICT_2026-08-29.md` §3.2: L3 vs L1
gave **98,636 → 58,194 = −41.0 %** signals reaching the engine (21 pp of margin
over the ≥20 % bar), TTUR better on all four percentiles (T1 p95 2,763 → 1,985 s
= −28.2 %, p50 −35.0 %, p99 −27.4 %, T-last p95 −25.9 %), and accuracy −0.40 pp,
inside the 1 pp floor. The honest qualification recorded there stands: the
engine-side secondary measure was −19.2 %, just under the bar. **This pair
re-tests nothing at 10 % and claims nothing new about it.**

### 4.3 Criterion 3 — no new gate FAIL — **PASS against the matched OFF leg**

The clause: *"No phase that PASSed on the corresponding OFF leg FAILs on the ON
leg. A pre-existing FAIL that persists unchanged … is not a new FAIL, but must be
named."*

| phase | P1 (OFF, matched) | P2 (ON) | verdict under §7 |
|---|---|---|---|
| preflight · burst · drain · correlation_completion · accounting | PASS | PASS | holds; accounting exactly lossless on both, `windows_rejected` 0 on both, restarts 0 on both, residue 0 on both |
| onboard | PASS 0.78 | PASS 0.66 | holds (P2 lower, still above the 0.60 floor) |
| **memflat** | **FAIL** (85.4 % of cap) | **PASS** (83.4 % of cap) | **FAIL → PASS** |
| **cleanup** | **FAIL** (OS purge stalled; cleared to 0 before P2) | **PASS** (residue 0) | **FAIL → PASS** |
| **stability** | **FAIL** (32,446 ms) | **FAIL** (30,468 ms) | **pre-existing FAIL, persisting — NOT new, and 1,978 ms less bad** |

**Criterion 3 PASSES. Zero phases went PASS → FAIL; two went FAIL → PASS.**

Named explicitly, as §7 requires:

- **`stability` is the pre-existing FAIL.** It fails on P1 and P2 for the same
  reason and on the same stale threshold (**tracker 190**): the harness's
  30,000 ms gate is derived from a Kafka session timeout `2852ad6f` widened to
  60 s. Both legs recorded **0 CommitFailed / 0 UnknownMember / 0 restarts / 0
  rebalances** — nothing was ejected. P2's stall is *shorter* than P1's.
- **`memflat` cleared, but the carrier replica differs** (P1: corr-3; P2: corr-4)
  — see §5. The comparison is nonetheless meaningful in the direction claimed:
  the ON leg's carrier ended **lower in absolute MiB and lower as a fraction of
  cap** than the OFF leg's, and this is the first ON leg at any rung to pass
  memflat since L3.
- **Against s04 as a second OFF point, `stability` would read as PASS → FAIL**,
  and a literal reading with two OFF legs (the reading the P3 verdict applied to
  `accounting` at L5) cannot simply dismiss it. It is recorded, and weighed at
  its real weight: s04's PASS was by **26 ms of 30,000** on a gate tracker 190
  says is invalid, all three legs had **zero** ejection events, and s04 is a
  different session on a different day. **The matched leg is P1**, which is the
  whole reason the pair was run.

### 4.4 The rule applied word for word — outcome

| criterion | requirement | result |
|---|---|---|
| **1 — neutrality guard** | TTUR within ±10 % (T1 p95, cross-checked p50 / T-last p95) **and** accuracy ≥ OFF − 1 pp | **FAIL — on the accuracy clause ONLY.** T1 p95 **−7.98 % / −0.24 %**, p50 0.00 %, p99 −1.30 %, T-last p95 −4.59 % — every TTUR clause **PASSES** against both OFF points. Accuracy −1.74 pp vs a −1.00 pp floor. |
| **2 — the 10 % rung earns it** | ≥20 % fewer signals, TTUR not worse, accuracy not worse | **MET** — carried from `P3_AB_2P5K_VERDICT_2026-08-29.md` §3.2 (−41.0 % signals, TTUR better on all four percentiles, accuracy −0.40 pp). Not re-tested. |
| **3 — no new gate FAIL** | no phase that PASSed on the corresponding OFF leg FAILs on the ON leg | **PASS** — 0 PASS→FAIL; `memflat` and `cleanup` went FAIL→PASS; `stability` is pre-existing on both (tracker 190's stale gate), 0 ejections on either. |

§7's disposition text, applied word for word:

> *"If 1 fails → the plane costs something where it can gain nothing: do not
> default ON; investigate the cost first."*

**`CORR_AGGREGATION_PLANE` therefore stays OFF by default.** The rule is
unambiguous and it is not being read around: criterion 1 fails on its accuracy
clause and the disposition is "do not default ON; investigate the cost first."

**The investigation §7 demands has been performed, and it terminates on the
instrument.** The 6 stories are 6 lost coin flips on correlation-UUID sort order
inside `scorer.py:664`; the engine attributes the cause correctly on 105 of 105
tied stories across all three legs; the plane cannot suppress a device's first
signal by construction; and under the union reading of the same clause every leg
scores 345/345. **What is now missing before criterion 1 can be re-applied is a
correct accuracy instrument, not another leg.**

---

## 5. Caveats — all of them

1. **A single pair.** Two legs, one session, one day. Every OFF-vs-OFF spread
   quoted comes from **two** OFF points (P1 and s04), which bounds noise but does
   not characterise its distribution.
2. **The `stability` gate is stale (tracker 190) and all three legs sit within
   2.5 s of it.** 32,446 / 30,468 / 29,974 ms against 30,000. The FAIL/PASS split
   between P1, P2 and s04 on this phase carries close to no information; on the
   engine's live 60 s session timeout all three pass with ~29.5 s of margin. The
   §7 criterion-3 evaluation is written to be robust to this, but a reader should
   not take "P2 FAILed stability" as an engine finding.
3. **The carrier replica differs between the legs** — P1's storm partition landed
   on `netops-correlation-3`, P2's on `netops-correlation-4`. Both containers are
   identical (same image, same 1,280 MiB cap, both `--force-recreate`d cold
   immediately before their leg), so the comparison is between two cold
   containers doing the same job, but it is **not the same container**, and the
   memflat FAIL→PASS should be read with that in mind.
4. **Replica idle asymmetry.** In every leg one replica carried essentially the
   whole tenant partition and the other was nearly idle (P1: corr-3 1,093 MiB vs
   corr-4 110 MiB; P2: corr-4 1,068 MiB vs corr-3 84 MiB; `corr_agg_observed` was
   **54,767 on corr-4 and 0 on corr-3** on P2). This is the `producer_key=tenant`
   single-key partitioning of the harness, not a rebalance failure — but it means
   the pair measures **one replica's** behaviour, and nothing here says anything
   about the plane under a balanced two-partition load.
5. **P1's `cleanup` FAIL was remediated between the legs.** The driver ran a
   `--cleanup-only` pass that verified 0 devices / 0 ClickHouse rows / 0
   OpenSearch docs before P2 launched. P2 therefore started clean, but P1's own
   9-phase verdict includes a FAIL the engine did not cause.
6. **The plane's `contradiction` / `new_vantage` / `new_modality` classes were
   never exercised** (all forwarded 0) — see §2. The pair measures the
   FIRST/STATE_TRANSITION/RECOVERY/COUNT_THRESHOLD half of the plane only. Any
   claim about the plane's behaviour under multi-vantage or multi-modality
   telemetry is **unmeasured**.
7. **Criterion 2 is cited, not re-measured.** The −41.0 % figure is L3-vs-L1 from
   the earlier wave, on an earlier image (`000e7bc3`), and carries that wave's own
   caveats — including that its engine-side secondary measure was −19.2 %.
8. **Accuracy is quoted from an instrument this document shows to be defective.**
   The 94.20 / 92.46 / 94.49 % figures are all reported as measured, and none of
   them should be treated as a product number until tracker 191 lands and the
   three legs are re-scored (which needs no new runs — see §6).
9. **`corr_objects` for all three legs is still in ClickHouse** (1,633
   correlation ids each; P1 16:27–17:16Z, P2 17:36–18:23Z, s04 06:40–07:31Z), so
   every number in §3 is re-derivable and the re-score of §6 is available now.
   Retention will eventually take it; the re-score should not wait.
10. **An unrelated, uncommitted tracker-185 change sits in the working tree**
    (`src/correlation/engine.py`, +147/−17: `SeamView.membership_values`,
    `ObjectSnapshot.identity_refs`). It was **not** built, **not** deployed and
    **not** in either leg's image (`34d113a3a8bb`, built 06:24:42Z), and it is
    not part of this document's commit.

---

## 6. Recommendation (recommendation only — nothing here was implemented)

**The fix belongs in the twin scorer, not in the plane and not in the engine.**

**1. Fix the instrument (tracker 191), then re-score — no new legs.** In
`scripts/lab/twin/scorer.py`, `affected_includes` should be evaluated over the
objects that touch the story, not over the single `best` object:

```python
# scorer.py:684  — today
if rca.get("affected_includes"):
    missing = [d for d in rca["affected_includes"]
               if (prefix + d) not in (best.get("affected") or "")]

# candidate — the union of the touching objects the scorer already fetched
if rca.get("affected_includes"):
    corpus = "".join(o.get("affected") or "" for o in objects)
    missing = [d for d in rca["affected_includes"] if (prefix + d) not in corpus]
```

`objects` is already in hand at `scorer.py:655` (it is what `detected` counts),
so this adds no ClickHouse read. Two things must ship with it: (i) `best` stays
correct for `verdict_tier_at_least` / `hypothesis_matches`, which legitimately
ask about the single best object — only the affected-set clause is a set
question; and (ii) **the tie-break must be made deterministic regardless**
(`max` over `(tier_rank, node_count, signal_count, correlation_id)` rather than
tier alone), so no clause is ever decided by a random UUID again. Then re-score
P1, P2 and s04 from the surviving `corr_objects` rows — `twin.py --run-root
/var/tmp/scale-runs score --runid <id>`, ~45 s each, **zero rig time** — and
re-apply §7 criterion 1 on the corrected numbers. On the counterfactual already
computed (§3.5) all three legs come back **345/345**, criterion 1 passes on every
clause, and with criteria 2 and 3 already met the rule's own text — *"If both
hold, criteria 1+2+3 hold and the rule says default ON"* — becomes live. **That
decision must be taken on the re-scored numbers, not on this document's
counterfactual.**

**2. Then re-derive tracker 187's premise.** 187 asserts the engine omits the
cause from `affected`; §3.3/§3.5 measure the opposite on 105 of 105 tied stories
across three legs. 187 is currently High priority and blocked on 184 on the
strength of a premise this pair falsifies. After 191, re-score and restate 187 as
what the data actually shows — that the cascade resolves into a cause object
*plus* a cohort object rather than one folded incident — or close it.

**3. No additional legs are warranted for the accuracy question, and the
statistics say so plainly.** For completeness, if the drop were treated as
variance to be characterised rather than a defect to be fixed: the per-leg
standard deviation of the coin flip is 2.44 stories = **0.71 pp**, so
distinguishing the observed 6-story gap from zero at α = 0.05 / power 0.80 needs
**≈3 legs per arm (6 legs, ~9 h of rig time)** — and *establishing equivalence*
within the 0.29 pp OFF-vs-OFF spread would need **≈92 legs per arm**, which is
not a programme. A one-line scorer change plus three ~45 s re-scores answers the
same question exactly. **Fix the instrument; do not buy legs.**

**4. Nothing in the plane needs changing on this evidence.** The candidate plane
fixes the brief asked to be considered — *"never suppress a signal that would be
the first from a device on a cohort/seam"*, or *"forward `new_vantage`"* — are
**both already the shipped behaviour and both irrelevant to these 6 stories**:
`AggKey` is per-entity and every key's FIRST observation is forwarded
unconditionally (`aggregation.py:233`), so a device's first signal is never
suppressed; and `new_vantage` forwarded 0 because this workload gives every
entity exactly one observer (§2), not because the class is broken. **Do not
change `aggregation.py` on the strength of this pair.** The genuinely unmeasured
part of the plane is the multi-vantage / multi-modality half, and closing that
needs a workload with a second independent vantage per entity — a harness item,
adjacent to tracker 183.

---

## 7. Artefacts

- Run dirs: `/var/tmp/scale-runs/pair-2p5k-off-08301624`,
  `/var/tmp/scale-runs/pair-2p5k-on-08301732`,
  `/var/tmp/scale-runs/storm-s04-08300637` — each with `report.json`,
  `accuracy-report.json`, `ttur.tsv`, `ttur-scope.json`, `metrics-final.txt`,
  `ab-leg.json`, `ground-truth.json`, `twin-score.log`, `lag-curve.json`.
- Driver: `/var/tmp/scale-runs/ab-pair-driver.log`,
  `/var/tmp/scale-runs/ab-pair-state.json` (both legs `complete`, `collected`;
  restore verified `corr_agg_enabled 0.0` on both replicas at 18:29:58Z).
- ClickHouse (still resident at the time of writing): `netops.corr_objects` /
  `netops.corr_current` for all three runs, 1,633 correlation ids each.
- Plan `RUN_PLAN_P3_PAIR_2026-08-30.md` · rule `RUN_PLAN_P3_AB_2026-08-29.md` §7
  · prior verdict `P3_AB_2P5K_VERDICT_2026-08-29.md` · OFF corroboration
  `STORM_S04_2P5K_VERDICT_2026-08-30.md` · programme
  `P4_PROGRAMME_WRITEUP_2026-08-29.md` §7/§8.
