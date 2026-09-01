# Host ceiling — the reference box (2026-08-31)

**Project 1 §D deliverable** (`docs/projects/01-SCALE-TESTING.md`). Completes the
capacity design of `docs/scale/SHARDING_AND_CAPACITY_MODEL_2026-08-28.md`, whose
plan step 2 is *"measure the single-shard ceiling — devices/tenant at nominal AND
storm."* This document is that measurement.

**Box under test:** 4 cores (Xeon E5-2683 v4 @ 2.1 GHz), 15 GiB RAM, 77 GB disk —
the owner's single box. Owner constraint (2026-08-28): no more hardware; the P5
scale-out proof is dropped. Every number below is **RIG-GATE**: measured on a
named run on this box, cited to the artefact it came from. Nothing is modelled.

> **Terminology note (owner, 2026-09-01).** Where this document labels a
> latency "TTUR" (e.g. "TTUR T1 p95"), the quantity reported is **T1 — time to
> first correlated version — an engineering lifecycle metric**
> (`scale-rca-latency.py` T0..T6). **"TTUR" proper is reserved for
> time-to-first-correct-operator-actionable-RCA, which has not yet been
> measured** (tracker 205 defines it). T1 is not marketed as TTUR.

---

## 1. The number

> **The clean host ceiling on the reference box is a TWO-AXIS ENVELOPE, not a
> single device count.**
>
> - **Axis 1 — RATE: ≤ ~1,000 eps sustained.** This is the axis the ceiling was
>   measured on, and it is the one that binds first. At **2,500 devices ×
>   0.4 eps/device = 1,000 eps** the box carries a storm up to a **25 % storm
>   share** with the ratified storm-time SLO met on every clause.
> - **Axis 2 — FLEET AT STORM DENSITY: the per-cohort cost wall lies somewhere
>   in (3,500, 5,000] devices.** With the rate held at or below ~1,000 eps the
>   envelope **extends to ~3,500 devices at ~0.29 eps/device**, where every
>   clause the correlation engine owns is clean. At 5,000 devices it is not.
>
> **Inside the envelope:** ~3,500 devices at ~0.29 eps/device, or the
> proven-in-depth 2,500 devices at 0.4 eps/device — in both cases at
> **≤ ~1,000 eps**.

**Both points are measured, not extrapolated.** Each is a fleet that has been run
to a graded verdict on this box with the engine's own gates green; neither is an
interpolation between a passing rung and a failing one.

**They are not equally proven, and this document does not treat them as such.**
The 2,500 × 0.4 point rests on **four independent legs** carrying **345/345
accuracy on each**; the 3,500 × 0.29 point rests on **one** leg
(`ladder-s3k5-08311750`, below). **The number to plan against remains 2,500
devices at 0.4 eps/device.** What the 3,500 rung adds is narrower and important:
**at 3,500 devices it is not the fleet size that binds** — the two open FAILs
there are the same tracker-186 backfill-worker memory clauses that also fail at
2,500 devices, and every engine-side and transport-side limiter is clear.

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
- **`storm-s08` / `storm-s09` — the close-out cycle (2026-09-01), and the SLO
  leg of record.** s08 (**6/9**) found the programme's last defect: the api's
  in-memory metrics store (`timeintel.MemMetricsStore.by`) grew unbounded on
  backfill catch-up to **100.0 % of its 565 MiB cap** (memflat FAIL; the auth
  timeouts it caused failed cleanup) — found, fixed (`eb29c87a`) and validated
  in one cycle (`API_MEMSTORE_DEFECT_2026-09-01.md`). s09, on the fully-fixed
  images (correlation `a9e99871e812` / `36036db5`, api `eefcc527730a`), is
  **8/9 with every SLO clause met**: completion **93.7 s** (ties the s07
  record), accounting exact, accuracy **345/345**, and **memflat PASS — the
  first 2,500-device rung ever to pass it on any profile** (carrier ×0.954 FLAT
  at 78.0 % of cap; api 33.4 %; the 558 ClickHouse refusals are the backfill's
  own 512 MiB budget working as designed, fully exempted). The sole FAIL is the
  onboard last/first-ratio clause — a measured harness artifact (tracker 202).
  **`storm-s09` is the leg of record for the ratified SLO**
  (`PROJECT1_DONE_2026-09-01.md` §5).
- Storm ladder at the same 2,500 devices: **2 %** rung 9/9 both arms, **10 %**
  rung 9/9 both arms (completion 170 s OFF → 130 s ON), **25 %** rung
  **INCOMPLETE OFF → 192 s PASS ON** (`P3_AB_2P5K_VERDICT_2026-08-29.md` §2.1/§2.2).
- `ladder-n2k5-08311437` (run `08311437us3b`, **nominal**, shipped post-wave
  image — correlation `26daf9680050`, api `4350dc839d8e`) **8/9** —
  `t-nominal-2.5k` completion **1,828 s of a 2,908 s budget (62.9 %)**, the
  fastest ever recorded on this profile; accounting exact **900,001 == 900,001
  + 0 DLQ + 0 counted rejections**, 2,500/2,500 devices covered; both
  correlation replicas **FLAT** (carrier 805.2 MiB = 62.9 % of its 1,280 MiB
  cap, anchored on a real `pending == 0`); TTUR T1 **p50/p95 646 / 1,753 s**,
  T-last p95 **2,564 s** with **no scope caveat**. The single `memflat` FAIL is
  tracker **186** in both of its clauses (§4).
- **The fleet axis, extended: `ladder-s3k5-08311750`** (run `083117507rl2`,
  `t-storm-2.5k` generated at **3,500 devices**, same shipped image —
  correlation `2d617a1ba1fa`, api `dfe4f7553d44`, `cfd7ebdc`) — **7/9**.
  Completion **144 s of a 2,700 s budget (5.3 %)** — *2,500-device class*;
  accounting exact **900,001 == 900,001 + 0 DLQ + 0 counted rejections** with
  **3,500/3,500** devices covered; accuracy **483/483 = 100.00 %** twin v2
  (detection 1.000, specificity 1.000, **zero fails in any template**); TTUR T1
  **p50/p95 118 / 810 s**, T-last p95 **2,038 s**, **no scope caveat**; carrier
  memory **59.7 %** of its 1,280 MiB cap, **FLAT** on a real `pending == 0`
  anchor; stability **0/0/0/0**, worst loop stall 3,745 ms = 6.2 % of the
  session timeout; cleanup residue **0**. The two FAILs are `onboard`
  (**CONFOUNDED** — the 199 builder's full pytest suite was on the host during
  onboarding) and `memflat` (**tracker 186**, both clauses). §2's new subsection
  reads this rung.

**One honest qualification stands on the headline; the second is now discharged.**

1. At the **25 % storm share** the ON arm is **8/9**, not 9/9 — `memflat` is the
   one FAIL — and its accuracy figure, **89.06 %**, is a **v1-scorer** number
   with no published v2 re-score for that rung. The SLO's own clauses
   (evaluate within 45 min of burst end, lose nothing, stay in memory caps) are
   met; "9/9" is not. The 9/9 claim belongs to the 2 % and 10 % rungs.
2. **RESOLVED (2026-08-31).** The nominal qualification — that the three
   passing `t-nominal-2.5k` legs consumed 74–93 % of budget on **P2-era builds**
   and had never been graded on the shipped image — has been discharged by
   `ladder-n2k5-08311437`. On the shipped image the same profile completes in
   **1,828 s of a 2,908 s budget (62.9 %)**: **−21.0 % against the three-leg
   P2-era cohort mean** (1,828 vs 2,313 s) and **−7.9 % against the single best
   P2 leg** (`p2-s05`, 1,986 s). The comparison is **same-session** — all four
   legs were re-queried in one `clickhouse-client` session with the verbatim
   clean-scope SQL of `RUN_PLAN_P3_AB_2026-08-29.md` §5.3, AGG_CID excluded,
   each leg scoped from its own `report.json` — and the re-query **reproduces
   every published P2 figure to within ±0.2 %** (s04b T1 p95 2,207 vs 2,208
   published; s05 1,948 vs 1,947; s06 2,101 vs 2,105). Read the two deltas
   differently: the **−7.9 % vs the best single leg is INSIDE** the profile's
   own ±10 % leg-to-leg noise floor and must not be sold as a proven speed-up on
   its own; the **−21.0 % vs the cohort mean is outside it**, and so is the
   latency move — **five measures fell together into a −10 % to −15 % band
   against the P2 *best* leg** (T1 p95 −10.0 %, T1 max −13.5 %, T-last p95
   −12.2 %, drain −14.8 %, peak lag −13.0 %), and −15.9 % to −28.4 % against the
   mean (T1 p95 −15.9 %, T1 p99 −17.4 %, T1 max −17.4 %, T-last p95 −19.7 %,
   drain −28.4 %). Noise does not move five percentiles the same way at once. The rung is therefore no longer "inside its
   budget, not comfortable in it" — and it earned that from a **worse** starting
   position: **+18 % mean and +70 % peak host `node_load1`** against `p2-s05`,
   with the consumer plane measuring ~35 % slower under backfill contention, so
   the gain is a **lower bound**, not an inflated one.

---

## 2. The ceilings above it — and what binds first

Each sits on a **different axis**, which is why the ceiling is stated in §1 as an
envelope over two axes rather than as one device count. Sources for §2 unless
stated: `/var/tmp/scale-runs/ladder-n5k-08310426/ceiling-facts.json` (run
`08310426f5wf`, profile `t-nominal-5k`) and
`/var/tmp/scale-runs/ladder-s5k-08310703/ceiling-facts.json` (run `08310703ujbf`,
profile `t-storm-5k`) — both 5,000 devices — plus
`/var/tmp/scale-runs/ladder-s3k5-08311750/ceiling-facts.json` (run
`083117507rl2`, `t-storm-2.5k` at 3,500 devices) for the isolating rung below.

### The binding-resource ranking, after the 5k storm rung

The storm rung is the **controlled variable-change** the ladder was built for:
same 5,000 devices, same 1,800,001 events, same box, and — decisively — the
**same carrier process** (`netops-correlation-5`, StartedAt `2026-08-31T04:12:15Z`,
never recreated between the two runs), so every engine figure below is a delta on
one pid. Only the workload **shape** differs (1.77 % storm share vs none). It
**confirms the head** of the nominal rung's ranking and **rewrites its tail**:

1. **Engine per-cohort algorithmic cost — axis: fleet size — now PROVEN, not
   inferred.** n5k inferred cohort cost from a single rung; s5k changed one
   variable on the same process and got **1.42× the window signals → 2.11× the
   components** (62,476 → 131,904) and **2.47× the preparation seconds**
   (20.7 → 51.1 s over only 18 more preparations, so per-preparation cost rose
   ~2.1×). Net completion progress **collapsed 11-fold, 9.5 → 0.98 events/s**,
   while `corr_engine_epoch_seconds_max` **did not move at all** — 3,391.4 s in
   both captures, literally **the same unfinished epoch**. Cost scales
   superlinearly in **signal density**, not merely in device count.
   **Bounded below by the 3,500-device rung (2026-08-31):** this cost is real but
   it **does not engage at 3,500 devices with the rate held at 1,000 eps** —
   `epoch_seconds_max` **167.5 s** with **0** budget exits there. The wall is
   bracketed to **(3,500, 5,000] devices at storm density**, and the ranking's
   head is a statement about *where the axis runs*, not about where it starts.
2. **Correlation carrier memory — PROMOTED from rank 5; the wall is arriving.**
   n5k filed it as "the forecast of the next bound" at 85.7 % of the 1,280 MiB
   cap. s5k collected on that forecast: **94.1 %**, no pending-0 anchor, 48,434
   events still queued and the largest cohort never evaluated. That 1.42× signal
   increase cost **8.4 points of headroom**, so the next comparable step does not
   time out — it **OOM-kills**. Memory is now a hard second wall, not a symptom.
3. **Consumer plane — REFRAMED as shape-dependent, and demoted.** The same
   two-measurement method that yielded a "hard ~1,040–1,070 eps" plane at nominal
   yields **half that under storm: 516 eps during the burst, 547 eps draining with
   the injector off** (agreeing to 6 %). The plane rate is a function of the
   **workload**, not of the box — **1,036–1,051 eps nominal vs 516–547 eps storm**
   — and it still decided neither verdict: drain PASSed in budget on both rungs.
4. **Harness injector host-CPU** — a measurement bound, not a product bound
   (§2c); also shape-dependent, and higher under storm.
5. **ClickHouse — under LESS pressure the worse the engine does.** 1.73× anchor
   plus one `MEMORY_LIMIT_EXCEEDED` at nominal became **1.17× and clean** at
   storm. That is not good news: it is the signature of the engine **starving its
   own downstream** — less backlog reached ClickHouse because less was ever
   evaluated.

**One n5k rationale is RETIRED.** "Memory tracks open objects, which track the
algorithmic problem in rank 1" does not survive this rung:
`corr_cohort_open_objects` **fell 11 %** (13,524 → 11,998) while carrier RSS
**rose 10 %** (1,097 → 1,204 MiB). The correct proxy is **components per cohort**
(2.11×), not open-object count. The conclusion — memory is downstream of the
engine — survives; that particular proxy does not.

**And a decisive negative result: suppression is not a completion lever.** The
Aggregation plane held its rate at double the fleet — **8.46 % at 5k storm
against an 8.86–8.89 % band at 2.5k** — and removed 9,368 signals exactly as
designed. Pending still went **33,760 → 48,434** and progress still fell 11×.
Shaving 8.5 % off an input whose per-unit cost grows 2.1× is arithmetically
irrelevant. The plane is itself under strain: **77 % eviction rate against 57 %
at nominal**.

### The 3,500-device isolating rung — the FLEET axis alone does not bind there

`ladder-s3k5-08311750` (run `083117507rl2`) is the rung §4 had marked ⏳. It does
one thing: **holds the event rate at 1,000 eps — under the measured consumer
plane — and varies only fleet size, 2,500 → 3,500 devices**, on the same
`t-storm-2.5k` scenario generator and the same shipped image. Per-device rate
therefore falls **0.40 → 0.286 eps/device**. No new limiter is introduced: the
injector was not saturated (**1,000 eps asked, 1,000 eps achieved, in exactly
900 s with no window extension** — the only rung above 2,500 devices where §2c's
harness bound is irrelevant *by construction*), the plane was not saturated, and
the burst window was not stretched. **Fleet size is the only variable that moved.**

**It came back clean on every clause the engine owns.**

| measure | 2,500 storm (s05 / s06 / s07) | **3,500 storm** | 5,000 storm |
|---|--:|--:|--:|
| completion (budget 2,700 s) | 95.0 / 124.3 / 93.7 s | **144.2 s (5.3 %)** | **INCOMPLETE**, 48,434 pending at cap |
| pending-curve shape | single/short close | **ONE step**: flat 3,211 for 130 s, one cohort close → 0 | 3-step staircase, never reaches 0 |
| `corr_engine_epoch_seconds_max` | 107–188 s | **167.5 s** | **3,391.4 s** (same unfinished epoch) |
| `corr_engine_epoch_budget_exits_total` | — | **0** | 10 |
| components per window signal | — | **2.15** | **4.73** (s5k − n5k delta, same pid) |
| seconds per preparation | — | **0.263 s** | **1.688 s** (6.4×) |
| carrier memory, % of 1,280 MiB cap | 82.7–83.2 % | **59.7 %, FLAT** on a real `pending == 0` | 94.1 %, **no anchor** |
| transport drain | 1,244 / 1,245 / 1,321 s @ 334–354 eps | **1,061 s @ 417 eps** | 2,232 s @ 547 eps |
| TTUR T1 p95 / max | 816–908 / 1,717–1,766 s | **810 / 1,595 s** | 4,987 / 5,940 s (scoped-to-completed) |
| incidents ending `undetermined` | 0 | **0** | 2,905 of 25,580 (11.4 %) |
| accuracy (twin v2) | 345/345 = 100 % ×4 legs | **483/483 = 100.00 %** | 644/690 = 93.33 % |

Three readings deserve to be stated plainly, because two of them are
counter-intuitive:

1. **The T1 tail did not degrade — it sits inside, and partly below, the
   2,500-device band.** T1 p95 **810 s** is below that cohort's own 816–908 s
   range and T1 max **1,595 s** below its 1,717–1,766 s range, *on 32.5 % more
   incidents* (2,164 vs 1,633). Only T1 p50 moves materially (81 → 118 s, +45 %).
2. **The mechanism is density, not size.** Holding the rate while growing the
   fleet makes the workload **thinner, not heavier**: incidents rose 32.5 % while
   total folded signals **fell 52.8 %** (39,790 vs 84,253) — signals per incident
   **18.4 vs 51.6, −64 %**. Versions per incident barely moved (6.54 vs 6.32), so
   the engine did the same per-object work over a larger, sparser population, and
   merges halved (87 vs 180) because fewer stories overlap. This is exactly why
   rank 1's axis is **signal density**, and why a fleet-size increase that
   *lowers* density does not trip it.
3. **Transport got further from binding, not closer.** From a comparable peak
   lag (442,580 vs 415,749–441,274) the bus drained **faster than all three
   2,500-device storm legs**.

**What the rung does NOT license.** It does not raise §1's 2,500 × 0.4 figure —
that is a different point on the *rate* axis, proven by four legs; this is one leg
at a lower per-device rate. It does not prove **3,500 devices at 0.4 eps/device**
(= 1,400 eps), a point that has never been run and would sit *above* the measured
consumer plane. It does not locate the cohort-cost wall — it brackets it to
**(3,500, 5,000] devices at storm density** and no finer; **no rung exists between
them.** And it does not discharge `memflat`: the rung is **7/9**, and both FAILs
are open — `onboard` **CONFOUNDED** (the 199 builder's full pytest suite was
hammering the 4-core host through onboarding and was lifted mid-run; all 3,500
devices were created, 0 failures, in 182 s of a 533 s budget, so the workload ran
and the decay clause cannot be cleanly attributed to the api), and `memflat`
attributed to **tracker 186** in both clauses (§4).

### (a) Engine per-cohort algorithmic cost — axis: FLEET SIZE — the binding one

| measure | 2,500 devices | 5,000 nominal | 5,000 storm | step (2.5k → 5k nominal) |
|---|--:|--:|--:|--:|
| `corr_cohort_open_objects` | 454–456 | **13,524** | 11,998 | **29.8×** for a 2× fleet |
| `corr_engine_epoch_seconds_max` | 107–188 s | **3,391.4 s** | **3,391.4 s** (same epoch) | **18–32×** |
| `corr_engine_pending_peak` | 3,516–3,589 | 35,355 | 49,434 | 9.9× |
| `corr_engine_prep_nodes` | 18,186–18,188 | 32,935 | 31,851 | 1.81× (≈ linear) |
| `corr_cohort_components_total` | 23,515–30,405 ranked | 62,476 | **131,904** (2.11×) | — |
| `corr_engine_prep_seconds_total` | — | 20.7 s | **51.1 s** (2.47×) | — |

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
agree to within 1.5 %. At the ratified 0.4 eps/device this caps the fleet at
**2,600–2,675 devices** regardless of what the engine could do.

**s5k reframes this as a workload property, not a box property.** The identical
method on the storm rung yields **516 eps** during the burst and **547 eps**
draining with the injector stopped — half the nominal number, on the same box and
the same process. Peak transport lag was **1,221,005** (2.5× the nominal rung's
483,983) and the bus still cleared it to 24 in **2,232 s, inside budget**:
transport is not the limiter on either rung. Read the plane rate as a **band —
1,036–1,051 eps nominal, 516–547 eps storm** — and size against the storm end.

### (c) Harness injector — ~1,417 eps — a MEASUREMENT bound, not a product bound

The 5k rung asked for 2,000 eps and got **1,417** (window extended 900 → 1,270 s).
**93.7 %** of the burst wall clock was inside `kafka-console-producer`; host CPU
was **98.6–99.8 %** busy with `node_load1` at **26.03** on 4 cores (6.5×); and
`user.slice` — the mini-ladder's own single-threaded Python event generation —
was the **largest single CPU consumer at 1.316 of 4 cores**, ahead of every
container. It was **not** Kafka backpressure: 0 produce failures, 0 retries, the
kafka cgroup at 0.681 of a 2.0-core quota, kafka memory FLAT (×1.002), and the
broker served the 483,983-message backlog back at 1,050 eps immediately after.

> **Any claim in the ~1,400–1,600 eps region on this box measures the harness,
> not the product.** This bound applies to every rung in §4 marked ⏳.

The bound is itself shape-dependent: the storm rung offered **1,605 eps** —
80.2 % of its 2,000 eps plan but **13.3 % above** the nominal sibling's 1,417 eps,
because the storm profile's smaller, denser events generate faster per event.
**96.1 %** of its burst wall clock was inside `kafka-console-producer` and **63 of
90 chunks overran their own 10 s slot**, so the injector — not the stack — again
set the pace (window stretched 900 → 1,122 s, bound 1,350 s not exceeded, 0
produce failures). The offered/absorbed gap therefore **widened from 1.37× to
3.11×** under storm: the injector got faster while the stack got slower.

### The forecast bound that arrived, the one that receded, and one that is further off than its watch item says

- **Carrier replica memory — ARRIVED (rank 2).** At 5k nominal it stood at
  **1,097 MiB of a 1,280 MiB cap = 85.7 %** with 33,760 events pending. At 5k
  storm it stands at **1,204 MiB = 94.1 %** with **48,434 pending and 11,998 open
  cohort objects**, having risen 65 MiB (+5.8 %) across the completion phase
  alone. RSS tracks the pending staircase exactly — it steps **up ~39 MiB at each
  cohort close** — i.e. the carrier's memory *is* the open-cohort working set,
  which is why memory and completion fail together. Neither run was stopped by an
  OOM (0 restarts on both); both were stopped by the completion timer. The leak
  verdict stays honestly **UNKNOWN** (no pending-0 anchor), not FAIL — but the
  headroom is gone.
- **ClickHouse anon growth — RECEDED.** At 5k nominal: 762 → **1,319 MiB
  (×1.73)** after input stopped, failing the ×1.3 memflat gate, with **1
  `MEMORY_LIMIT_EXCEEDED`** (victim: a Select on `corr_current`/`corr_objects`),
  though peak `MemoryTracking` was only **63.0 %** of the 4,096 MiB server cap
  versus **107.6 %** at 2,500 devices on `p2-s06`. At 5k storm it is **1,149 MiB
  anon, 21.6 % of its cgroup cap, ×1.17, FLAT, zero `MEMORY_LIMIT_EXCEEDED`**.
  ClickHouse is under *less* absolute pressure the harder the workload, precisely
  because the engine never fed it the backlog. It is downstream of (a), not an
  independent limiter.
- **The tracker-187 history-accumulator cap — further away than the watch item
  says, because the watch item is on the WRONG AXIS.** The wave validation
  filed a watch on `corr_affected_history_entities_max` at **16,622 of the
  20,000 cap = 83.1 %** (`PROJECT1_WAVE_VALIDATION_2026-08-31.md` §187 guard).
  That is a **`t-storm-2.5k`** reading. On `ladder-n2k5-08311437` — same box,
  same 2,500 devices, same shipped image, nominal profile — the same gauge reads
  **6,390 = 32.0 % of cap**, with `corr_affected_history_truncated_total` still
  **0**. **Refined wording:** the guard sits at *83.1 % of cap at 2,500 devices
  under storm and 32 % at the same fleet size nominal*; it therefore tracks
  **signal density / blast radius** — the same axis as rank 1 above — **not
  device count**. The rung that would move it is a **storm** rung at a larger
  fleet; no nominal rung, at any size run so far, approaches it.

### At the ceiling on the shipped image: the engine's memory is FIXED

The shipped-image nominal rung (`ladder-n2k5-08311437`) settles what the earlier
2,500-device legs could not: **the correlation engine's memory behaviour on this
profile is fixed.**

- **Both replicas FLAT, on a real anchor.** The carrier `netops-correlation-5`
  ends at **805.2 MiB = 62.9 %** of its 1,280 MiB cap, **×1.006** against a
  `corr_engine_pending == 0` anchor — an *actual* convergence, not a cap
  expiry. The idle replica sits at 108.2 MiB = 8.5 % of the same cap.
- **The working set is bounded by the cohort population, not by the backlog.**
  RSS rises 674.5 MiB at t = 4.3 s to a **~800 MiB plateau from t ≈ 990 s and
  then does not move for the remaining 840 s — while pending falls 18,771 → 0.**
  Memory stopped growing with 18,771 events still to evaluate. Contrast the 5k
  rungs above, where RSS stepped **up** ~39 MiB at every cohort close.
- **The `memflat` carrier has MIGRATED across waves — and it has left the
  engine.** `p2-s05`'s FAIL was **correlation replica-3 at ×1.37**;
  `p2-s06`'s was **ClickHouse peaking at 107.6 %** of its server cap; here both
  correlation replicas are FLAT, ClickHouse's anon clause **PASSES at ×1.136**
  and its peak is down to **95.3 %**, and the entire FAIL has moved to the
  **api process plus 4 `MEMORY_LIMIT_EXCEEDED`** — i.e. to the time-intelligence
  backfill worker of tracker **186**, and to nothing else (§4).
- **Where it binds on this rung, ranked:** (1) **api process memory** — the
  backfill working set at **504 MiB of a 565 MiB cap = 89.2 %**, reached on an
  *idle* stack 33 min after the run, so it binds **first and without any
  telemetry load at all**; (2) **ClickHouse server memory** — the same worker's
  1.62 GiB query against the 4 GiB cap, binding only *during* a pass;
  (3) **consumer plane** at ~675–710 eps on a contended host, which set the
  backlog but drained it in 323 s; (4) **the correlation engine's per-cohort
  cost — NOT AT ALL**, converging with 37 % of its memory and 37 % of its time
  budget unused.

---

## 3. Degradation shape beyond the ceiling — the sellable part

At **2× the ceiling** (5,000 devices, 1,800,001 events) the platform **lost
nothing, stayed up, and degraded only in latency — and, under storm, in recall**.
Both 5k rungs, nominal (`ladder-n5k-08310426`) and storm (`ladder-s5k-08310703`),
show the same shape; figures below are the nominal rung unless the storm rung is
named:

- **Lossless, exactly.** `1,800,001 injected == 1,800,001 persisted + 0 DLQ + 0
  counted rejections`; **5,000/5,000** devices covered in `corr_signals`.
- **Stable, on both rungs.** 0 CommitFailed, 0 UnknownMember, 0 rebalances,
  **0 restarts** over a 5,973 s lifecycle nominal and a **7,138 s** lifecycle
  storm; worst loop stall **5,924 ms = 9.9 %** of the 60,000 ms session timeout —
  **identical on both**, so it is the same bounded pause, not a new one. No
  consumer ejection of any kind.
- **No shedding, no errors, on both rungs.** `windows_rejected` **0**,
  `profiler_errors` **0**, `window_overflow_dropped` **0**. The engine did not
  refuse, drop or error — it had not finished.
- **Latency only.** T1 **p50 2,126 s / p95 4,367 s / p99 4,535 s / max 4,658 s**,
  T-last p95 4,974 s over 34,296 incidents (`ttur.tsv`) — and that row covers
  **only the incidents whose windows actually evaluated**; **33,760 events were
  still pending at the 3,811 s cap**, so the true tail is worse than the row
  shows. `ttur-scope.json` carries the caveat in the artefact itself. The **storm**
  rung, same scoping caveat: T1 **p50 2,752 s / p95 4,987 s / p99 5,738 s / max
  5,940 s**, T-last p95 **5,891 s** over **25,580** incidents — 25 % *fewer*
  incidents evaluated, each carrying **1.39× the versions** (vpi 1.53 → 2.13) and
  folding in more signals (52,200 → 60,134); `merged` 16 → 196; `undetermined`
  flat in absolute terms (2,957 → 2,905) but up from 8.6 % to **11.4 %** of
  in-scope incidents. The storm shape makes each surviving incident **heavier and
  slower** without much changing the tier mix.
- **Cleanup still clean.** 5,000 devices deleted and verified, 0 residue of any
  run id, CH+OS purged.

**And now the measured accuracy shape, from the 5k storm rung** (the nominal rung
carries no scenario and is unscoreable): **at 2× the ceiling, accuracy degrades by
RECALL only.** Twin scorer v2 gives **644/690 = 93.33 %** with **detection 0.9551**
and **specificity 1.000** — *every* negative control passed, so the loss carries
**zero false positives**. All 46 misses split into **31 windows that never
evaluated** (no correlation object exists for those entities at all) and **15
starved-undetermined** objects that did form and touch the story's entities but
assembled too little evidence to rank a hypothesis. Neither class is a
misattribution: **the engine never guesses.** Both are the same root cause seen at
two depths — the pending backlog — corroborated by the TTUR row (2,905 of 25,580
in-scope incidents ended `undetermined`, **0** reached `confirmed`). Contrast
`t-storm-2.5k`, which scores **345/345 = 100.0 %** on four independent runs —
and, at **3,500 devices** with the rate held at 1,000 eps, **483/483 = 100.00 %
with 0 fails in any template**, including the two that carried *all 46* losses at
5,000 (`bgp_peer_flap` 140/140 here vs 36 fails there; `enterprise_outage` 21/21
vs 10). The recall loss tracks **the backlog**, not the fleet size. The
−6.67 points are **characterisation of overload, not an SLO breach**: the accuracy
SLO is defined at the ceiling, and a score taken while 48,434 events are still
queued measures the backlog, not the correlator. **OPEN:** all 46 failures fall in
a **154 s onset band** (story `t0_offset` 271.6–425.1 s of a 1,122 s burst; 0
failures out of the 528 stories outside it), and within that band the loss is
template-selective (`bgp_peer_flap` 36/43, `enterprise_outage` 10/11 failed;
`local_link_fault` 0/59, `ospf_adjacency_flap` 0/39, `upstream_link_failure` 0/10
passed). The band is **not** the storm's own peak — scenario load inside it was
*below* mean — and the discriminator is not determined by the run data. Joining
the epoch timeline to story `t0` is the open next step.

**Overload on this platform is queueing, never loss.** That is the property to
sell: past the ceiling the customer waits longer for an RCA verdict; they do not
lose an event, a device, or a consumer.

**And at the ceiling, the platform's own background work completes under live
load — at a cost that is itself the open defect.** On `ladder-n2k5-08311437` the
time-intelligence backfill ran continuously *through* the burst and the drain,
and **every pass completed at the full budget: 6/6 passes, `pages=10`,
`written=20,000`, zero `ended early` / `degraded` / `wide fetch skipped`
warnings** (`docker logs netops-api-1`, component `timeintel`). The bounded-pass
machinery (10 pages, 1 rescan + 9 forward, durable watermark) held against a live
2,500-device, 900,001-event leg — the watermark advanced 13.8 h of backlog per
~78 min of wall clock. **The cost is the finding.** Those passes issued **1,043
ClickHouse queries reading 1,104.2 GB to emit 65,088 rows — ~17 MB of ClickHouse
read per row written** — with **263 GB of it issued *inside* the 969 s burst
window**, while the consumer plane was trying to hold 928 eps on a 4-core host.
That single ratio is the measured case for tracker **197** (the `seam_type`
projection, which deletes the wide read); it is also the most plausible non-host
explanation for this leg's ~675–710 eps consumer plane against 1,036–1,051 eps on
`ladder-n5k` — **contention, not a correlation-engine regression.**

**Postscript (2026-09-01): the backfill's other cost — the api's own memory —
was found and closed by the same gate, at the ceiling rather than beyond it.**
On `storm-s08` the api reached **100.0 % of its 565 MiB cap** during an ordinary
2,500-device run: `timeintel.MemMetricsStore.by` — the in-memory backend the
lab's file store selects — retained EVERY snapshot the backfill catch-up folded
(measured **778 MiB** anonymous against a **780 MB** prediction from ~3 KB/row ×
260k rows; a full catch-up would have needed ~2.7 GiB, so the breach was
guaranteed, not incidental). Its observed failure mode was the 10k rung's
auth-latency cascade reproduced at 1× load. Fixed **`eb29c87a`** (per-tenant cap
= SnapshotCap 20,000, derived from what reads can return; 366 d retention;
amortized compaction); deploy-H validation read **+91 / +24 / +6.7 MiB over
three consecutive 20k-row passes, settling ~155 MiB = 27 % of cap**, and
`storm-s09`'s memflat PASS (api ×1.035 at 33.4 % of cap) is the rig-level proof.
Full record: `API_MEMSTORE_DEFECT_2026-09-01.md`.

---

## 4. The rung table

| rung | profile / run | devices × eps | completion (budget) | accounting | verdict |
|---|---|---|--:|---|---|
| 2.5k nominal, P2-era | `t-nominal-2.5k` · `p2-s04b` / `p2-s05` / `p2-s06` | 2,500 × 1,000 | **2,515 / 1,986 / 2,439 s** (2,700) | exact (`p2-s04b` injected 870,001) | **PASS** — 74–93 % of budget; P2-era builds. Superseded on the shipped image by the row below |
| **2.5k nominal, shipped image** | `t-nominal-2.5k` · `ladder-n2k5-08311437` (run `08311437us3b`) | 2,500 × 928 eff. (1,000 planned) | **1,828 s** (2,908) — **62.9 % of budget**, the **fastest `t-nominal-2.5k` ever recorded** | **900,001 == 900,001 + 0 DLQ + 0 rejections**, 2,500/2,500 devices | **8/9** — the §1 qualification-2 caveat **DISCHARGED**. **−21.0 % completion vs the P2 cohort mean** (−7.9 % vs the best single leg). Stability is the **programme best on any profile**: worst loop stall **2,711 ms = 4.5 %** of the 60 s session timeout, **0/0/0/0** CommitFailed / UnknownMember / restarts / rebalances over 3,634 s. Onboard **PASS but FLOOR-EXACT** (0.601 against a 0.600 floor, under the host confound below). TTUR T1 **p50/p95 646 / 1,753 s**, T-last p95 **2,564 s** over 11,211 incidents — **true convergence, no scope caveat** (pending 0 on both replicas, oldest age 0.0 s). Cleanup PASS, residue 0. Single FAIL = **`memflat`, both clauses tracker 186** |
| 2.5k storm 2 % OFF | `t-storm-2.5k` · `storm-s05` | 2,500 × 1,000 | **95.0 s** (2,700) | 900,001 == 900,001 + 0 DLQ | **9/9**, accuracy 345/345 v2 |
| 2.5k storm 2 % ON | `t-storm-2.5k` · `storm-s06` | 2,500 × 1,000 | **124.3 s** (2,700) | 900,001 == 900,001 + 0 DLQ | **9/9**, accuracy 345/345 v2 — shipped default |
| 2.5k storm 2 % ON, post-wave | `t-storm-2.5k` · `storm-s07` | 2,500 × 1,000 | **94 s** (2,700) | 900,001 == 900,001 + 0 DLQ | **8/9** — `memflat` → tracker 186 |
| 2.5k storm 2 % ON, s08 | `t-storm-2.5k` · `storm-s08` (run `09010312jpiu`) | 2,500 × 995 eff. | **124 s** (2,714) | 900,001 == 900,001 + 0 DLQ | **6/9** — onboard (0.57), `memflat` (api **100.0 % of its 565 MiB cap** — the unbounded `MemMetricsStore`, fixed `eb29c87a`; correlation carrier itself ×0.965 FLAT at 74.9 %), cleanup (the defect's auth timeouts; residue recovered to 0 before s09). Accuracy **345/345** v2. T1 p95 **1,101 s** — the only reading ever outside the band, owned by the api defect (`API_MEMSTORE_DEFECT_2026-09-01.md`) |
| **2.5k storm 2 % ON, s09 — SLO leg of record** | `t-storm-2.5k` · `storm-s09` (run `09010750fq0u`) | 2,500 × 1,000 | **93.7 s** (2,700) — ties the record | **900,001 == 900,001 + 0 DLQ + 0 rejections**, 2,500/2,500 devices | **8/9 — every SLO clause MET (4/4)**, and **`memflat` PASS: the first 2,500-device rung ever to pass it on any profile** (all 9 containers within ×1.3 and under 85 % of caps; carrier ×0.954 FLAT = 78.0 %; api 33.4 % under `eb29c87a`; CH p99 37.5 %, +558 refusals fully exempted — the 512 MiB budget working as designed). Accuracy **345/345** v2 (detection 1.000, specificity 1.000). T1 p95 **912 s**, drain 1,349.6 s, stability 0/0/0/0 (worst stall 6,464 ms = 10.8 %), cleanup residue 0. Sole FAIL: onboard ratio 0.56 — harness artifact, tracker 202 (`PROJECT1_DONE_2026-09-01.md`) |
| 2.5k storm 10 % OFF | `t-storm-10-2.5k` · `agg-10-off` (L1) | 2,500 × 1,000 | **170 s** (2,700) | exact | **9/9** |
| 2.5k storm 10 % ON | `t-storm-10-2.5k` · `agg-10-on` (L3) | 2,500 × 1,000 | **130 s** (2,700) | exact | **9/9**, −41.0 % signals to the engine |
| 2.5k storm 25 % OFF | `t-storm-25-2.5k` · `agg-25-off` (L2) | 2,500 × 1,000 | **INCOMPLETE** — 78,663 pending at cap | — | **6/9** — drain, completion, memflat |
| 2.5k storm 25 % ON | `t-storm-25-2.5k` · `agg-25-on` (L4) | 2,500 × 1,000 | **192 s** (2,700) | exact | **8/9** — `memflat` only; accuracy 89.06 % (v1 scorer) |
| 2.5k storm 50 % | `t-storm-50-2.5k` | 2,500 × 1,000 | — | — | **NEVER RUN** — planned in the P4 §1 ladder, not executed |
| **5k nominal** | `t-nominal-5k` · `ladder-n5k-08310426` | 5,000 × 1,417 eff. (2,000 planned) | **INCOMPLETE** — 33,760 pending at the 3,811 s cap, oldest 502 s | **1,800,001 == 1,800,001 + 0 DLQ** | **FAIL** — completion + memflat; stability/accounting/cleanup PASS |
| **5k storm** | `t-storm-5k` · `ladder-s5k-08310703` (run `08310703ujbf`) | 5,000 × 1,605 eff. (2,000 planned) | **INCOMPLETE** — 48,434 pending at the 3,366 s cap, oldest 511 s | **1,800,001 == 1,800,001 + 0 DLQ** | **FAIL** — onboard (**CONFOUNDED**), completion, memflat; burst/drain/accounting/stability/cleanup PASS. Drain 2,232 s from a 1,221,005 peak lag; carrier **94.1 %** of cap; stability 0 CommitFailed / 0 UnknownMember / 0 restarts; accuracy **644/690 = 93.33 %** twin v2 (detection 0.9551, specificity **1.000**); T1 p50/p95 **2,752 / 4,987 s** scoped-to-completed |
| **3,500 isolating rung** | `t-storm-2.5k` @ **3,500** · `ladder-s3k5-08311750` (run `083117507rl2`) | 3,500 × **1,000 achieved** (0.286 eps/dev) | **144.2 s** (2,700) — **5.3 % of budget**, *2,500-device class* | **900,001 == 900,001 + 0 DLQ + 0 rejections**, 3,500/3,500 devices | **7/9** — the fleet axis **does not bind here**. Offered load exact (1,000 of 1,000 eps in exactly 900 s, **no window extension**), so no new limiter was introduced. Accuracy **483/483 = 100.00 %** twin v2, **0 fails in any of the 5 templates**, detection 1.000, specificity 1.000. TTUR T1 **p50/p95 118 / 810 s**, T-last p95 **2,038 s**, **no scope caveat** — p95 and max sit *below* the 2,500-device storm band, **0** incidents `undetermined`. Carrier **59.7 %** of its 1,280 MiB cap, FLAT on a real `pending == 0`; `epoch_seconds_max` **167.5 s**, **0** budget exits. Drain **1,061 s @ 417 eps** from a 442,580 peak — faster than all three 2,500-device storm legs. Stability **0/0/0/0**, worst stall 3,745 ms = 6.2 %. Cleanup residue 0. FAILs: `onboard` **CONFOUNDED** (0.523 vs a 0.600 floor, under the 199-builder pytest suite on the host; 3,500 created, 0 failures, 182 s of a 533 s budget) and `memflat` (**tracker 186**, both clauses). **NOTE the profile change:** this rung was planned as `t-nominal` @ 3,500 and was run on **`t-storm-2.5k` @ 3,500** — a storm scenario (483 stories, 2.45 % achieved share), which is the *harder* of the two and the one that carries accuracy |
| ⏳ 10k "cannot be offered" | `t-nominal-10k` / `t-storm-10k` | 10,000 × ≤1,400 | — | — | Documentation rung: records *how* the box fails at 4× the ceiling, so the hosting spec can refuse the configuration with evidence rather than by assertion. Note the injector bound: 10k × 0.4 = 4,000 eps **cannot be offered by this harness** |

**The 5k-storm `onboard` FAIL is CONFOUNDED and is not a reading of record.** All
5,000 devices were created, in 463 s of a 633 s budget, 0 failures — the gate
tripped on the *decay* clause: 40.5/s in the first window to 9.1/s in the last,
ratio **0.224 against a 0.6 floor**. A **concurrent Go test suite was hammering
the 4-core host throughout onboarding**, so the decay is not cleanly attributable
to the api. The nominal sibling — same 5,000 devices, **same api image**, no
concurrent load — **PASSED at ratio 0.80**, and that is the onboard-decay signal
of record.

**The shipped-image nominal rung's single FAIL is tracker 186 — in BOTH of its
clauses, and in neither one the engine.**

- **The api clause.** Judged **×2.343** against the warm (end-of-burst) anchor,
  so it covers only the window *after* input stopped — and the mechanism is a
  **bounded sawtooth, not a slope**. 34 `docker stats` samples across two
  consecutive backfill cycles on an *idle* stack, 33 min after the run and after
  cleanup had deleted all 2,500 devices and purged 900,001 OpenSearch docs, give
  peak **504.2 → 508.9 MiB (+0.9 %)** and trough **407.3 → 405.0 MiB (−0.6 %)**:
  **the floor is level and does not rise.** Period = one backfill pass, ~13 min;
  every peak lands on a pass boundary and every trough between passes, on an
  unrestarted process (started 14:33:35Z, 0 restarts). What is serious is the
  **LEVEL, not the slope**: the worker parks the api at **405–509 MiB of a
  565 MiB cap = 72–90 %** permanently, leaving ~10 % headroom for everything else
  the api does. That is what the gate is correctly refusing to pass.
- **The ClickHouse clause.** The anon slope **PASSES** (×1.136, under the ×1.3
  gate); the FAIL is the **+4 `MEMORY_LIMIT_EXCEEDED`** — and all four were
  raised **in one second** (`system.error_log`, 15:19:49). Three are now named:
  **1 backfill-negotiation `Select` swinging 1.623 GiB**, **2 background
  `MergeParts` it evicted**, and **1 unattributable** (`system.text_log` is not
  enabled on this deployment, so `query_log`/`part_log` account for only three;
  it is almost certainly a sub-thread raise of one of the three). The episode is
  a **single overcommit** and the backfill query is its **cause, not its
  co-victim** — the storm-s07 pattern of tracker 186 reproduced verbatim on a
  nominal leg. Peak `MemoryTracking` **3,905 MiB = 95.3 %** of the 4,096 MiB
  server cap; p50 **flat at 1.0–1.3 GiB**; all twelve of the window's
  highest-memory queries are backfill `SELECT`s at 1.61–1.66 GiB, the heaviest
  non-backfill consumer being a `MergeParts` at 194 MiB.
- **The causal fix is in the build but NOT in force.** The worker carries its own
  512 MiB per-query ceiling (`timeIntelBackfillMemoryBytes`, present in this api
  image `4350dc839d8e` / `9ed38cbb`), yet the passes still peaked at **1.623
  GiB** — the attributed `background` settings profile
  (`deployment/docker/clickhouse/workload-profiles.xml`) sets
  `max_memory_usage` from `CH_BG_MEM`, defaulted to **2 GiB**, which is what the
  queries actually ran under. **With the 512 MiB budget effective the lane cannot
  overcommit a 4 GiB server, and the eviction chain that fails this gate cannot
  form.** That is the pending causal fix for the last missing gate on this rung —
  a settings-precedence fix, not new engine work.
- **UPDATE (3,500-device rung, image `dfe4f7553d44`): the 512 MiB budget IS NOW
  IN FORCE — and the gate still fails.** On that run **363 of the 365** exempted
  raises name `maximum: 512.00 MiB` — the worker's own
  `timeIntelBackfillMemoryBytes` ceiling, not the 2 GiB `CH_BG_MEM` background
  profile — and the heaviest raiser used **498 MiB**, against the 1.623 GiB
  recorded above. The downstream evidence agrees: peak `MemoryTracking` fell to
  **89.1 %** of the 4 GiB cap with **p99 at 38.5 %** (against 95.3 % peak on the
  n2k5 rung), and ClickHouse's **anon slope PASSES at ×0.869** — memory *fell*
  after input stopped. **Two consequences, and neither is a discharge.** (i) The
  settings-precedence defect is fixed on this image, so that item is closed —
  but **2 of the 365 raises still hit the 4 GiB SERVER total** via
  `OvercommitTracker` (18:14:50 and 18:29:51, both selecting the backfill query
  as victim), so the lane no longer overcommits *on its own* while the server can
  still reach its ceiling under concurrent load. (ii) The gate now fails on
  refusals that are **the budget working as designed** — which argues the next
  look belongs on the **exemption clause**, not on the budget.
  *(Source: `ladder-s3k5-08311750/ceiling-facts.json` → `memflat_split`.)*
- **And the 5 unexempted raises on that rung are NOT a second consumer.** They
  are 5 extra `system.errors` increments raised by **the same 365 backfill
  queries** — the second reader thread of 5 of them tripping the per-query
  tracker before cancellation propagated (`max_threads = 2` on every raising
  query; 365 queries with 5 double-raises = 370 exactly). The negative half is
  proven: `system.part_log` over the window has **zero** rows with `error != 0`
  (so *no* merge or mutation raised it — unlike the n2k5 episode), the
  ClickHouse **`.err.log` and the full 771 MB server log contain exactly 365
  raises and not one more**, `system.query_log` has 365 rows all `Select` on
  `netops.corr_objects`, and `sum(remote)` is 0. The positive half is
  **inferred**, because `system.query_thread_log` is **not enabled** on this
  deployment. **Recommendation: enable `query_thread_log` (or `text_log`) before
  the next rung** — every "`query_log` cannot name them" residue in this
  programme (1 at n5k, 1 at n2k5, 5 here) is unresolvable without per-thread
  accounting, and each one costs an unexplained line in a gate verdict.

**The onboard PASS is floor-exact and host-confounded, in the honest direction.**
2,500 devices created in 82.1 s, first-window 41.94/s → last-window 25.21/s,
ratio **0.601 against a 0.600 floor**. This leg ran at **+18 % mean / +70 % peak**
host `node_load1` versus `p2-s05` (17.6 / 28.43 vs 14.9 / 16.72, VictoriaMetrics
`node_load1`, 300 s step), corroborated by 2 retried-and-recovered DELETE socket
timeouts in cleanup and the ~35 %-slower consumer plane. It is a **contended
measurement, not a linearity claim** — and it makes every comparative gain on
this rung a lower bound. Tombstone debt is now **10,000** suppressed entries
(2,500 this run) — tracker 175's accumulation, re-read at api boot.

**Both 5k rungs now fail on the same engine constraint, from opposite ends:**
nominal ran out of **time** with memory headroom left (85.7 %); storm is running
out of **memory as well as time** (94.1 %, 48,434 pending). What the storm rung
adds at 2,500 devices is that the storm profile also scores **345/345 accuracy on
four runs** there — the clean ceiling of §1 is unchanged.

---

## 5. Per-device envelope and the pricing feed

At the ceiling (2,500 devices, 1,000 eps), **per device**:

| quantity | value | basis |
|---|--:|---|
| sustained event rate | **0.4 eps** | ratified `t-nominal-2.5k` envelope; met exactly at 2,500 on all three counts — offered, absorbed, evaluated |
| carrier memory, working set | **0.32–0.43 MiB** | carrier end rss 1,059–1,065 MiB ÷ 2,500 storm (`storm-s05`/`s06` memflat); **0.322 MiB** nominal on the shipped image (805.2 MiB ÷ 2,500, `ladder-n2k5-08311437`) — size on the storm end |
| carrier memory, provisioned | **0.51 MiB** | the 1,280 MiB replica cap ÷ 2,500 — the number to size a host with |
| storage / day | **n/a — NOT MEASURED** | no run instruments bytes on disk; see below |

**And the device count stretches when the per-device rate falls.** The second
point of §1's envelope is the same box carrying **3,500 devices at 0.286
eps/device** — cite the `ladder-s3k5-08311750` row in §4 — for the same ~1,000
eps offered, with completion at 5.3 % of budget, accuracy 483/483 and the carrier
at 59.7 % of its memory cap. That is a **40 % larger device count at 72 % of the
per-device rate**, and it changes what the pricing model may sell:

| point | devices | eps/device | offered eps | evidence weight |
|---|--:|--:|--:|---|
| planning ceiling | **2,500** | **0.40** | ~1,000 | four legs, 345/345 accuracy on each |
| stretched fleet | **3,500** | **0.286** | ~1,000 | **one** leg, 483/483 accuracy |
| out of envelope | 5,000 | **0.283–0.321 achieved** (0.40 planned) | 1,417–1,605 | two legs, both **INCOMPLETE** |

> **What the host ceiling actually constrains is EVENTS PER SECOND. Devices are
> the billable proxy, and the proxy holds only at an assumed per-device rate.**

Consequently: **price per device with a stated eps-per-device assumption, and
meter the deviation.** A device count sold without one is unbacked by this
document — a fleet of quieter devices legitimately buys more slots on the same
box, and a fleet of noisier ones buys fewer. Carrier memory per device is *not*
the constraint that moves here: the 3,500-device rung ended at **0.218 MiB/device
working set** (764.1 MiB ÷ 3,500) against 0.32–0.43 MiB/device at 2,500, i.e. the
thinner fleet is cheaper per device on memory as well. The **provisioned** figure
is what a host is sized on and it falls the same way — **0.37 MiB/device**
(1,280 MiB ÷ 3,500) against 0.51 at 2,500. Both are single-leg readings and carry
the same one-leg caveat as the row above.

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
is structural, not a defect of any rung: at 5,000 devices nominal the carrier held
**34,789 window signals to the idle replica's 271**, and at 5,000 devices storm
**49,463 to that same idle replica's 271**; the 2,500-device nominal siblings show
the same 100/0 split.

**The skew is total at 5k, and per-replica normalisations must account for it.**
On the storm rung the idle replica `netops-correlation-4` did **essentially
nothing**: `corr_ingest_events{counter="syslog_received"}` reads **2,235** against
`netops-correlation-5`'s **3,639,650** — process-lifetime counters spanning both
5k rungs, so the ratio is if anything generous to corr-4. Its memory reflects
that: **108.6 MiB, 8.5 % of the same 1,280 MiB cap, FLAT**, beside the carrier's
1,204 MiB at 94.1 %. Any quantity divided by "replica count" is therefore wrong by
the replica count at 5k — **divide by the carrier, not by the fleet of replicas**.
The 0.42–0.51 MiB/device rows above are already carrier-only for this reason.

Consequences for pricing:

- A **single tenant** cannot exceed the single-shard ceiling by adding replicas.
  Per-tenant device caps must be set at or below the host ceiling — they are the
  binding limit, not the host total.
- Adding replicas adds **tenant capacity**, not per-tenant capacity — exactly the
  Scenario A/B split in `SHARDING_AND_CAPACITY_MODEL_2026-08-28.md`.
- **Burst = SLO, not billing** holds on the evidence: the 25 % storm share is
  absorbed inside the ratified SLO on the shipped ON configuration.

**Owner capacity model, position:** validate 1K ✓ (`GA_WORKLOAD_CONTRACT_1K.md`)
→ **host ceiling = THIS DOCUMENT — a two-axis envelope: ≤ ~1,000 eps AND a fleet
under the cohort-cost wall, i.e. 2,500 devices @ 0.4 eps/device for planning,
extending to ~3,500 @ ~0.29 on one leg** → **per-tenant limits next**, and §5's
storm-concentration note is the input to that step.

---

## 6. What would raise the ceiling (recommendations only — nothing is scheduled)

1. **The per-cohort algorithmic term — the biggest lever by far, and now the
   PROVEN one.** The 5k nominal rung names it: cohort formation scales on **open
   objects** (454 → 13,524 for a 2× fleet), not on changed ones, and one cohort
   can own an epoch for 3,391 s with no in-cohort pre-emption (`epoch_cohorts_max
   1`, and the 4 budget exits fire only *between* cohorts). The 5k **storm** rung
   proves the cost is causal and not merely correlated with fleet size: on the
   same process, 1.42× the signals bought **2.11× the components and 2.47× the
   prep seconds**, and progress fell 9.5 → 0.98 events/s while the same epoch
   stayed unfinished. Note the axis is **signal density**, not device count
   alone. Three separable sub-levers:
   scale cohort formation on the changed set rather than the open set; add an
   in-cohort yield point so the epoch budget can pre-empt work already in flight;
   bound open objects per cohort. This moves the device axis directly.
2. **Rank-memo hit rate — currently contributing nothing at ANY scale.**
   `corr_cohort_components_memo_hits_total` is **0** at 5,000 devices nominal
   (62,476 ranked), **0** at 5,000 devices storm (131,904 ranked) *and* **0** at
   2,500 on both storm legs (30,405 and 23,515 ranked).
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
- **The injector bound applies to every rate claim in the ~1,400–1,600 eps
  region.** It is not one number: the nominal profile tops out at **1,417 eps**
  and the storm profile at **1,605 eps**, because storm events are cheaper to
  generate. In both cases the mini-ladder's own single-threaded generation, not
  the stack, set the pace (96.1 % of the storm burst's wall clock inside
  `kafka-console-producer`, 63 of 90 chunks over their slot, 0 produce failures),
  so the offered rate is a property of the harness. No rung has been offered above
  1,605 eps, and none should be graded until the injector is fixed.
- **`memflat` history, stated honestly: no 2,500-device rung passed it until
  `storm-s09` (2026-09-01).** The failing carrier migrated across waves —
  a correlation replica (`p2-s05`), ClickHouse's server cap (`p2-s06`), the
  time-intelligence backfill worker of tracker 186 (`storm-s07`,
  `ladder-n2k5-08311437`, `ladder-s3k5`), and finally the api's unbounded
  `MemMetricsStore` (`storm-s08`) — each traced, none waived. With the 186
  chain landed (watermark + splitter `9ed38cbb`, the 512 MiB budget made
  effective by `cfd7ebdc`, irreducible-only skips `e86ec6aa`) and the metrics
  store bounded (`eb29c87a`), **`storm-s09` passes `memflat` outright** — all 9
  containers inside the gates, carrier ×0.954 FLAT, and the 558 refusals being
  the budget working as designed, fully exempted (trackers 186/199 CLOSED;
  `PROJECT1_DONE_2026-09-01.md`). `t-nominal-2.5k` carries **no scenario**, so correlation *quality* is
  not measurable on it by construction — the 345/345 accuracy proof belongs to
  the scenario-carrying sibling `t-storm-2.5k`.
- **The 5k accuracy figure is characterisation, not a graded SLO number.** It was
  taken while 48,434 events were still queued; the accuracy SLO is defined at the
  ceiling, where the same storm profile scores 100 %. The 5k-storm `onboard` FAIL
  is likewise CONFOUNDED (concurrent host load) and is superseded by the nominal
  sibling's PASS on the same image.
- **What this document does not claim:** it does not claim 2,500 is comfortable
  on the P2-era builds (those legs use 74–93 % of budget) — on the **shipped**
  image the nominal rung is now graded at **62.9 % of budget**, but at **8/9**,
  and its −7.9 % gain over the single best P2 leg is inside the profile's own
  ±10 % noise floor (only the −21.0 % against the cohort mean, and the five
  simultaneous TTUR percentile moves, sit outside it); it does not claim 9/9 at
  the 25 % storm share (that rung is 8/9
  with a v1-scorer accuracy figure), it does not claim a storage-per-device
  figure, it does not claim to explain the 154 s accuracy-loss band or its
  template selectivity at 5k storm (left open); and — **updated 2026-08-31** — it
  no longer claims that nothing is known between 2,500 and 5,000, but it still
  does not claim a *ceiling* there. The 3,500 isolating rung has been run and is
  clean, which **brackets the cohort-cost wall to (3,500, 5,000] devices at storm
  density** and nothing finer: no rung exists between those two, and the 3,500
  reading is **one leg at 0.286 eps/device**, not a re-measured ceiling at the
  ratified 0.4. **3,500 devices at 0.4 eps/device (1,400 eps) has never been run
  and would sit above the measured consumer plane.**
- **The 3,500 rung's own honesty tier.** Its `onboard` FAIL is **CONFOUNDED**
  (concurrent pytest suite on the host, lifted mid-run) and is not a reading of
  record in either direction. Its `memflat` FAIL is **open**, attributed to
  tracker 186 in both clauses; the api clause is attributed **by pattern, not by
  measurement** — the two-cycle idle census that proved the sawtooth on the n2k5
  rung was **not** run here, because a 10k rung was already loading the same box,
  and a later `docker stats` sample is **inadmissible** for the same reason.
  Its accuracy figure is **one leg** against four at 2,500 devices. And
  `metrics-final.txt` for that rung is **NOT leg-scoped** — both correlation
  processes pre-date the run (17:05:14Z and 16:35:15Z vs a 17:50:34Z start) and
  their `*_total` counters include the 155d-arm traffic; deltas are derivable only
  for the four gauges the harness baselined at preflight, and for the *idle*
  replica the delta for this run is **zero** (all 376 of its `agg_observed` are
  pre-run residue).
