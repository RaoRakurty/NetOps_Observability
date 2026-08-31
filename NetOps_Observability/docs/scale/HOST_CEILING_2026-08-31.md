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

## 2. The ceilings above it — and what binds first

Each sits on a **different axis**, which is why no single device count exists
between 2,500 and 5,000. Sources for §2 unless stated:
`/var/tmp/scale-runs/ladder-n5k-08310426/ceiling-facts.json` (run `08310426f5wf`,
profile `t-nominal-5k`) and
`/var/tmp/scale-runs/ladder-s5k-08310703/ceiling-facts.json` (run `08310703ujbf`,
profile `t-storm-5k`) — both 5,000 devices.

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

### The forecast bound that arrived, and the one that receded

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
`t-storm-2.5k`, which scores **345/345 = 100.0 %** on four independent runs. The
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
| **5k storm** | `t-storm-5k` · `ladder-s5k-08310703` (run `08310703ujbf`) | 5,000 × 1,605 eff. (2,000 planned) | **INCOMPLETE** — 48,434 pending at the 3,366 s cap, oldest 511 s | **1,800,001 == 1,800,001 + 0 DLQ** | **FAIL** — onboard (**CONFOUNDED**), completion, memflat; burst/drain/accounting/stability/cleanup PASS. Drain 2,232 s from a 1,221,005 peak lag; carrier **94.1 %** of cap; stability 0 CommitFailed / 0 UnknownMember / 0 restarts; accuracy **644/690 = 93.33 %** twin v2 (detection 0.9551, specificity **1.000**); T1 p50/p95 **2,752 / 4,987 s** scoped-to-completed |
| ⏳ 2.5k nominal, shipped image | `t-nominal-2.5k` on the post-wave build | 2,500 × 1,000 | — | — | Re-run of the §1 qualification 2 caveat: the three passing legs are **P2-era** builds (`p2-s04b`/`p2-s05`/`p2-s06`) at 74–93 % of budget. The ceiling's tightest rung has never been graded on the shipped image |
| ⏳ 3,500 isolating rung | `t-nominal` @ 3,500 | 3,500 × 1,000 (0.29 eps/dev) | — | — | Holds eps **under** the measured consumer ceiling and varies **only** fleet size — places the engine's own device ceiling directly, with no new limiter introduced |
| ⏳ 10k "cannot be offered" | `t-nominal-10k` / `t-storm-10k` | 10,000 × ≤1,400 | — | — | Documentation rung: records *how* the box fails at 4× the ceiling, so the hosting spec can refuse the configuration with evidence rather than by assertion. Note the injector bound: 10k × 0.4 = 4,000 eps **cannot be offered by this harness** |

**The 5k-storm `onboard` FAIL is CONFOUNDED and is not a reading of record.** All
5,000 devices were created, in 463 s of a 633 s budget, 0 failures — the gate
tripped on the *decay* clause: 40.5/s in the first window to 9.1/s in the last,
ratio **0.224 against a 0.6 floor**. A **concurrent Go test suite was hammering
the 4-core host throughout onboarding**, so the decay is not cleanly attributable
to the api. The nominal sibling — same 5,000 devices, **same api image**, no
concurrent load — **PASSED at ratio 0.80**, and that is the onboard-decay signal
of record.

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
→ **host ceiling = THIS DOCUMENT (2,500 devices @ 0.4 eps/device)** → **per-tenant
limits next**, and §5's storm-concentration note is the input to that step.

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
- **The 5k accuracy figure is characterisation, not a graded SLO number.** It was
  taken while 48,434 events were still queued; the accuracy SLO is defined at the
  ceiling, where the same storm profile scores 100 %. The 5k-storm `onboard` FAIL
  is likewise CONFOUNDED (concurrent host load) and is superseded by the nominal
  sibling's PASS on the same image.
- **What this document does not claim:** it does not claim 2,500 is comfortable
  (the nominal rung uses 74–93 % of its budget, and has not been re-run on the
  shipped image), it does not claim 9/9 at the 25 % storm share (that rung is 8/9
  with a v1-scorer accuracy figure), it does not claim a storage-per-device
  figure, it does not claim to explain the 154 s accuracy-loss band or its
  template selectivity at 5k storm (left open), and it does not claim a ceiling
  anywhere between 2,500 and 5,000 — the limiters sit on different axes, so no
  single intermediate device count exists until the ⏳ 3,500 isolating rung is run.
