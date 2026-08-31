# Host ceiling — the reference box (2026-08-31)

**Project 1 §D deliverable** (`docs/projects/01-SCALE-TESTING.md`). Completes the
capacity design of `docs/scale/SHARDING_AND_CAPACITY_MODEL_2026-08-28.md`, whose
plan step 2 is *"measure the single-shard ceiling — devices/tenant at nominal AND
storm."* This document is that measurement.

**Box under test:** 4 cores (Xeon E5-2683 v4 @ 2.1 GHz), 15 GiB RAM, 77 GB disk —
the owner's single box. Owner constraint (2026-08-28): no more hardware; the P5
scale-out proof is dropped. Every number below is **RIG-GATE**: measured on a
named run on this box, cited to the artefact it came from. Nothing is modelled.

---

## 1. The number

> **The clean host ceiling on the reference box is 2,500 devices at 0.4 eps per
> device — 1,000 eps sustained — carrying a storm up to a 25 % storm share, with
> the ratified storm-time SLO met on every clause.**

**This is measured, not extrapolated.** It is the largest fleet that has been run
to a graded verdict on this box with the gates green; it is not an interpolation
between a passing rung and a failing one.

Evidence line, all on the shipped configuration (`CORR_AGGREGATION_PLANE` ON by
default, `a9d9a10c`):

- `storm-s05` (OFF control) **9/9** and `storm-s06` (ON, shipped default)
  **9/9** — `t-storm-2.5k`, completion **95.0 s / 124.3 s** of a 2,700 s budget,
  accounting exact **900,001 == 900,001 + 0 DLQ + 0 rejections**, carrier memory
  **83.2 % / 82.7 %** of its 1,280 MiB cap ×1.02 FLAT, accuracy **345/345 =
  100.00 %** on twin scorer v2 both arms
  (`STORM_S05_S06_CLOSEOUT_2026-08-30.md` §1/§2).
- `storm-s07` (post-engine-wave, code `de8ca5b1`) **8/9** — completion **94 s**,
  accounting exact, accuracy **345/345**; the single `memflat` FAIL is
  attributed with evidence to tracker **186** and a 7-minute-old api process,
  not to the fleet size (`PROJECT1_WAVE_VALIDATION_2026-08-31.md` §1/§4).
- Storm ladder at the same 2,500 devices: **2 %** rung 9/9 both arms, **10 %**
  rung 9/9 both arms (completion 170 s OFF → 130 s ON), **25 %** rung
  **INCOMPLETE OFF → 192 s PASS ON** (`P3_AB_2P5K_VERDICT_2026-08-29.md` §2.1/§2.2).

**Two honest qualifications on the headline.**

1. At the **25 % storm share** the ON arm is **8/9**, not 9/9 — `memflat` is the
   one FAIL — and its accuracy figure, **89.06 %**, is a **v1-scorer** number
   with no published v2 re-score for that rung. The SLO's own clauses
   (evaluate within 45 min of burst end, lose nothing, stay in memory caps) are
   met; "9/9" is not. The 9/9 claim belongs to the 2 % and 10 % rungs.
2. The **nominal** profile at 2,500 devices is the *tighter* of the two, not the
   looser: `t-nominal-2.5k` completion PASSes at **1,986 / 2,439 / 2,515 s**
   against a 2,700 s budget — **74–93 % of budget consumed** — and those three
   legs ran on **P2-era builds** (`p2-s04b`, `p2-s05`, `p2-s06`), not on the
   shipped post-wave build. The 2,500 nominal rung is **inside** its budget, not
   comfortable in it, and it has not been re-run on the current image.

---

## 2. The three ceilings above it

Each sits on a **different axis**, which is why no single device count exists
between 2,500 and 5,000. Source for §2 unless stated:
`/var/tmp/scale-runs/ladder-n5k-08310426/ceiling-facts.json` (run `08310426f5wf`,
profile `t-nominal-5k`, 5,000 devices).

### (a) Engine per-cohort algorithmic cost — axis: FLEET SIZE — the binding one

| measure | 2,500 devices | 5,000 devices | step |
|---|--:|--:|--:|
| `corr_cohort_open_objects` | 454–456 | **13,524** | **29.8×** for a 2× fleet |
| `corr_engine_epoch_seconds_max` | 107–188 s | **3,391.4 s** | **18–32×** |
| `corr_engine_pending_peak` | 3,516–3,589 | 35,355 | 9.9× |
| `corr_engine_prep_nodes` | 18,186–18,188 | 32,935 | 1.81× (≈ linear) |

One epoch ran **3,391 s = 89 % of the entire 3,811 s completion budget**, and
`corr_engine_epoch_cohorts_max = 1` — that epoch was **one cohort**. The pending
curve is a **3-step staircase**, not a drain: flat at 70,015 for 1,217 s, one
−1,000 step, flat for 1,446 s, then **−34,255 in a single sample**, net **9.5
events/s**. Pending falls only when a whole cohort's window closes.

**It is not a resource limit.** During completion the carrier used **0.672 of its
2.0-core quota** (0.17 of the 4-core host) with **0.61 %** CFS throttling — the
cores were available and unused. `corr_cohort_components_memo_hits_total` is
**0** against 62,476 components ranked. `epoch_budget_exits` fired 4 times but
only *between* cohorts, so it cannot pre-empt a cohort in flight. This is
single-threaded algorithmic cost, not starvation.

### (b) Consumer plane — axis: RATE — ~1,040–1,070 eps

Two independent measurements of the same number in one run:
**1,036 eps** consumed during the burst with the injector running
((1,800,001 − 483,983) / 1,270.2 s), and **1,051 eps** drained after it stopped
((483,983 − 28) / 460.4 s), linear across every segment (1,087–1,102/s). They
agree to within 1.5 %. At the ratified 0.4 eps/device this hard-caps the fleet at
**2,600–2,675 devices** regardless of what the engine could do.

### (c) Harness injector — ~1,417 eps — a MEASUREMENT bound, not a product bound

The 5k rung asked for 2,000 eps and got **1,417** (window extended 900 → 1,270 s).
**93.7 %** of the burst wall clock was inside `kafka-console-producer`; host CPU
was **98.6–99.8 %** busy with `node_load1` at **26.03** on 4 cores (6.5×); and
`user.slice` — the mini-ladder's own single-threaded Python event generation —
was the **largest single CPU consumer at 1.316 of 4 cores**, ahead of every
container. It was **not** Kafka backpressure: 0 produce failures, 0 retries, the
kafka cgroup at 0.681 of a 2.0-core quota, kafka memory FLAT (×1.002), and the
broker served the 483,983-message backlog back at 1,050 eps immediately after.

> **Any claim above ~1,400 eps on this box measures the harness, not the
> product.** This bound applies to every rung in §4 marked ⏳.

### Forecast bounds (not yet binding, but next in line)

- **Carrier replica memory** — **1,097 MiB of a 1,280 MiB cap = 85.7 %** at 5,000
  devices, with 33,760 events still pending and the largest cohort not yet
  evaluated. One more cohort of that size is an OOM kill. The run was stopped by
  the completion timer, not by an OOM: 0 restarts. The leak verdict is honestly
  **UNKNOWN** (no pending-0 anchor), not FAIL.
- **ClickHouse anon growth** — 762 → **1,319 MiB (×1.73)** after input stopped,
  failing the ×1.3 memflat gate, with **1 `MEMORY_LIMIT_EXCEEDED`** (victim: a
  Select on `corr_current`/`corr_objects`). But peak `MemoryTracking` was only
  **63.0 %** of the 4,096 MiB server cap — versus **107.6 %** at 2,500 devices on
  `p2-s06`. ClickHouse was under *less* absolute pressure at 5,000 devices
  precisely because the engine never fed it the backlog. It is downstream of
  (a), not an independent limiter.

---

## 3. Degradation shape beyond the ceiling — the sellable part

At **2× the ceiling** (5,000 devices, 1,800,001 events) the platform **lost
nothing, stayed up, and degraded only in latency**:

- **Lossless, exactly.** `1,800,001 injected == 1,800,001 persisted + 0 DLQ + 0
  counted rejections`; **5,000/5,000** devices covered in `corr_signals`.
- **Stable.** 0 CommitFailed, 0 UnknownMember, **0 restarts** over a 5,973 s
  lifecycle; worst loop stall **5,924 ms = 9.9 %** of the 60,000 ms session
  timeout. No consumer ejection of any kind.
- **No shedding, no errors.** `windows_rejected` **0**, `profiler_errors` **0**.
  The engine did not refuse, drop or error — it had not finished.
- **Latency only.** T1 **p50 2,126 s / p95 4,367 s / p99 4,535 s / max 4,658 s**,
  T-last p95 4,974 s over 34,296 incidents (`ttur.tsv`) — and that row covers
  **only the incidents whose windows actually evaluated**; **33,760 events were
  still pending at the 3,811 s cap**, so the true tail is worse than the row
  shows. `ttur-scope.json` carries the caveat in the artefact itself.
- **Cleanup still clean.** 5,000 devices deleted and verified, 0 residue of any
  run id, CH+OS purged.

**Overload on this platform is queueing, never loss.** That is the property to
sell: past the ceiling the customer waits longer for an RCA verdict; they do not
lose an event, a device, or a consumer.

---

## 4. The rung table

| rung | profile / run | devices × eps | completion (budget) | accounting | verdict |
|---|---|---|--:|---|---|
| 2.5k nominal | `t-nominal-2.5k` · `p2-s04b` / `p2-s05` / `p2-s06` | 2,500 × 1,000 | **2,515 / 1,986 / 2,439 s** (2,700) | exact | **PASS** — 74–93 % of budget; P2-era builds |
| 2.5k storm 2 % OFF | `t-storm-2.5k` · `storm-s05` | 2,500 × 1,000 | **95.0 s** (2,700) | 900,001 == 900,001 + 0 DLQ | **9/9**, accuracy 345/345 v2 |
| 2.5k storm 2 % ON | `t-storm-2.5k` · `storm-s06` | 2,500 × 1,000 | **124.3 s** (2,700) | 900,001 == 900,001 + 0 DLQ | **9/9**, accuracy 345/345 v2 — shipped default |
| 2.5k storm 2 % ON, post-wave | `t-storm-2.5k` · `storm-s07` | 2,500 × 1,000 | **94 s** (2,700) | 900,001 == 900,001 + 0 DLQ | **8/9** — `memflat` → tracker 186 |
| 2.5k storm 10 % OFF | `t-storm-10-2.5k` · `agg-10-off` (L1) | 2,500 × 1,000 | **170 s** (2,700) | exact | **9/9** |
| 2.5k storm 10 % ON | `t-storm-10-2.5k` · `agg-10-on` (L3) | 2,500 × 1,000 | **130 s** (2,700) | exact | **9/9**, −41.0 % signals to the engine |
| 2.5k storm 25 % OFF | `t-storm-25-2.5k` · `agg-25-off` (L2) | 2,500 × 1,000 | **INCOMPLETE** — 78,663 pending at cap | — | **6/9** — drain, completion, memflat |
| 2.5k storm 25 % ON | `t-storm-25-2.5k` · `agg-25-on` (L4) | 2,500 × 1,000 | **192 s** (2,700) | exact | **8/9** — `memflat` only; accuracy 89.06 % (v1 scorer) |
| 2.5k storm 50 % | `t-storm-50-2.5k` | 2,500 × 1,000 | — | — | **NEVER RUN** — planned in the P4 §1 ladder, not executed |
| **5k nominal** | `t-nominal-5k` · `ladder-n5k-08310426` | 5,000 × 1,417 eff. (2,000 planned) | **INCOMPLETE** — 33,760 pending at the 3,811 s cap, oldest 502 s | **1,800,001 == 1,800,001 + 0 DLQ** | **FAIL** — completion + memflat; stability/accounting/cleanup PASS |
| ⏳ 5k storm | `t-storm-5k` · `ladder-s5k-08310703` (run `08310703ujbf`, **in flight**) | 5,000 × 2,000 req. | — | — | Will establish whether storm dynamics change (a)'s open-object explosion, and gives the 5k rung its first **accuracy** number (the nominal rung carries no scenario and is unscoreable) |
| ⏳ 3,500 isolating rung | `t-nominal` @ 3,500 | 3,500 × 1,000 (0.29 eps/dev) | — | — | Holds eps **under** the measured consumer ceiling and varies **only** fleet size — places the engine's own device ceiling directly, with no new limiter introduced |
| ⏳ 10k "cannot be offered" | `t-nominal-10k` / `t-storm-10k` | 10,000 × ≤1,400 | — | — | Documentation rung: records *how* the box fails at 4× the ceiling, so the hosting spec can refuse the configuration with evidence rather than by assertion. Note the injector bound: 10k × 0.4 = 4,000 eps **cannot be offered by this harness** |

---

## 5. Per-device envelope and the pricing feed

At the ceiling (2,500 devices, 1,000 eps), **per device**:

| quantity | value | basis |
|---|--:|---|
| sustained event rate | **0.4 eps** | ratified `t-nominal-2.5k` envelope; met exactly at 2,500 on all three counts — offered, absorbed, evaluated |
| carrier memory, working set | **0.42–0.43 MiB** | carrier end rss 1,059–1,065 MiB ÷ 2,500 (`storm-s05`/`s06` memflat) |
| carrier memory, provisioned | **0.51 MiB** | the 1,280 MiB replica cap ÷ 2,500 — the number to size a host with |
| storage / day | **n/a — NOT MEASURED** | no run instruments bytes on disk; see below |

**Storage/day is honestly n/a.** No mini-ladder phase records on-disk volume;
`report.json` carries memory bytes only. What *is* measured, per 900,001-event
storm leg at 2,500 devices: **1,800,001 → 1:1 OpenSearch docs** (the 5k leg
persisted exactly one doc per event), **54,000–54,021 `corr_signals` rows**, and
**10,191–10,546 persisted correlation-object versions**. *Derived* by arithmetic
on those measured ratios, at the ceiling's 1,000 eps: ~**86.4 M events/day**,
~**5.2 M `corr_signals` rows/day**, ~**0.99 M object versions/day**. The only
byte-level datum on record is `corr_objects.hypotheses` at **31,151 B/row
uncompressed** (67.8 GB of that table) from the tracker-186 analysis — a
table-level figure, not a per-device/day rate. **Retention pricing has no
measured basis until a rung instruments disk.**

**The per-tenant cap binds before the host cap — a storm lands on ONE replica.**
The producer key is the tenant (`producer_key_mode=tenant`, key `global`), so a
tenant's whole stream lands on **one partition → one correlation replica**. This
is structural, not a defect of any rung: at 5,000 devices the carrier held
**34,789 window signals to the idle replica's 271**; the 2,500-device nominal
siblings show the same 100/0 split. Consequences for pricing:

- A **single tenant** cannot exceed the single-shard ceiling by adding replicas.
  Per-tenant device caps must be set at or below the host ceiling — they are the
  binding limit, not the host total.
- Adding replicas adds **tenant capacity**, not per-tenant capacity — exactly the
  Scenario A/B split in `SHARDING_AND_CAPACITY_MODEL_2026-08-28.md`.
- **Burst = SLO, not billing** holds on the evidence: the 25 % storm share is
  absorbed inside the ratified SLO on the shipped ON configuration.

**Owner capacity model, position:** validate 1K ✓ (`GA_WORKLOAD_CONTRACT_1K.md`)
→ **host ceiling = THIS DOCUMENT (2,500 devices @ 0.4 eps/device)** → **per-tenant
limits next**, and §5's storm-concentration note is the input to that step.

---

## 6. What would raise the ceiling (recommendations only — nothing is scheduled)

1. **The per-cohort algorithmic term — axis: fleet size — the biggest lever by
   far.** The 5k rung names it: cohort formation scales on **open objects**
   (454 → 13,524 for a 2× fleet), not on changed ones, and one cohort can own an
   epoch for 3,391 s with no in-cohort pre-emption (`epoch_cohorts_max 1`, and
   the 4 budget exits fire only *between* cohorts). Three separable sub-levers:
   scale cohort formation on the changed set rather than the open set; add an
   in-cohort yield point so the epoch budget can pre-empt work already in flight;
   bound open objects per cohort. This moves the device axis directly.
2. **Rank-memo hit rate — currently contributing nothing at ANY scale.**
   `corr_cohort_components_memo_hits_total` is **0** at 5,000 devices (62,476
   ranked) *and* **0** at 2,500 on both storm legs (30,405 and 23,515 ranked).
   That rules out "the memo works but 5k blows its capacity" — it never hits on
   this workload at all. The run data does not say **why**: there is no
   key-collision or eviction counter on the memo path. The honest next step is to
   **instrument the memo key before optimising it**; a memo that hit even
   modestly would cut the ranking term that dominates (1).
3. **Consumer-plane parallelism — axis: rate.** The ~1,050 eps plane rate is
   pinned to one partition by the tenant key. More partitions per tenant would
   raise the rate but **split the correlation domain**, which is the governing
   constraint of the sharding model — correlation only happens within a shard.
   This lever therefore trades rate against correlation completeness and needs
   the topology-domain sharding work (Scenario A, plan step 4), not just a
   partition count.
4. **P5 scale-out — dropped by the owner (2026-08-28), included for contrast.**
   It would have moved the **tenant-count** axis (Scenario B, embarrassingly
   parallel), not the single-shard ceiling — and both scenarios bottom out on the
   single-shard ceiling. Dropping it costs nothing that this document measures.
5. **Harness injector (measurement, not product).** Pre-generated event corpora
   or a multi-process producer would lift the ~1,417 eps offer bound. Required
   before *any* rung above ~1,400 eps can be graded, but it raises no product
   ceiling — the consumer plane could not absorb the extra rate today anyway.

---

## 7. Honesty tier

- **Every number is RIG-GATE**: measured on a named run on the named box
  (4 cores / 15 GiB / 77 GB), cited to `ceiling-facts.json`, `report.json`,
  `ttur.tsv`, `metrics-final.txt`, `accuracy-report.json` or the dated verdict doc
  that carries the SQL. No number in this document is modelled, interpolated or
  projected except where explicitly labelled **derived** (§5's per-day row counts,
  arithmetic on measured ratios) or ⏳ **pending** (§4).
- **The ~1,417 eps injector bound applies to every rate claim above ~1,400 eps.**
  Above it the mini-ladder's own single-threaded generation is the largest CPU
  consumer on the box, and any such rung measures the harness rather than the
  product. No rung above 1,400 eps has been offered, and none should be graded
  until the injector is fixed.
- **What this document does not claim:** it does not claim 2,500 is comfortable
  (the nominal rung uses 74–93 % of its budget), it does not claim 9/9 at the
  25 % storm share (that rung is 8/9 with a v1-scorer accuracy figure), it does
  not claim a storage-per-device figure, and it does not claim a ceiling anywhere
  between 2,500 and 5,000 — the two limiters sit on different axes, so no single
  intermediate device count exists until the ⏳ 3,500 isolating rung is run.
