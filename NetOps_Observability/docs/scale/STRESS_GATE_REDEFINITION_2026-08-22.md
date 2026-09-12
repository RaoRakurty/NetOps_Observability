# Stress-gate redefinition — externally anchored storm qualification

**Date:** 2026-08-22 · **Status: RATIFIED (owner, 2026-08-22 — "approve
all", with the standing rider that industry numbers are the FLOOR: wherever
there is scope to beat industry products, take it and record the stretch
target beside the floor).**
Companion to `EPS_BASELINE_PROPOSAL_2026-08-22.md` (the workload bands this
document grades against) and the pre-GA architecture review (which found the
old gate ungraded). Evidence: two research sweeps (~60 sources; SIEM/NMS
vendor sizing + standards, and the storm-measurement literature — IMC/SIGCOMM/
ToN corpora, ISA-18.2/EEMUA-191, streaming-benchmark methodology). Full
citations live in the research deliverables; the load-bearing anchors are
inlined here.

---

## 1. What was wrong with the old gate, in one paragraph

The nightly stress test (2,000 eps × 100 % promotion × all 1,000 devices
simultaneously, absolute completion within a fixed budget) was an **ungraded**
bar: its parameters came from a rule of thumb whose "nominal" was never
defined, and measured against the literature it is unrealistic on every axis —
blast radius (real correlated failures touch single-digit % of an estate; ours
touches 100 %), amplitude (the aggregated correlator tier sees ~10× typical /
~100× worst measured; ours sustains ~10× fleet-wide with 100 % promotion ≈
20–200× real admitted load), shape (real storms decay — >95 % of causally
related alarms arrive within 1 minute — or *escalate over hours*; ours is a
flat plateau), and pass criterion (absolute completion of an unratifiable
workload, where the literature grades overload on invariants + recovery).
It remains an excellent **defect finder** — it found 168, the archive
amplification, and the durability losses — so it is retained as a probe and
retired as a pass/fail capacity bar.

## 2. The evidence anchors (per axis)

| Axis | Anchor | Source class |
|---|---|---|
| Amplitude at the CORRELATOR tier | **~10× typical daily peak churn, up to ~100× on bad days** (BGP aggregate, 4 tier-1 monitors, 8 yrs); **12.7×** sustained flood-vs-baseline (cleanest alarm-tier split); post-trip tail ~600× for ONE 10-min window | peer-reviewed + ISA-committee trade press |
| Amplitude is TIER-dependent | per-port L2 storm ~10⁵× · per-prefix BGP ~96× · aggregate correlator ~10× · transport/log ~3× — **never quote one multiplier without a denominator** | peer-reviewed |
| Blast radius | >50 % of failure events isolated; only 10 % of groups >4 links; largest group ever = 180 links <2 % of estate (planned maintenance); ~90 % of causally-associated alarms within 1 topology hop; >90 % of BGP events touch <40 prefixes | 3 independent domains |
| Duration | **Bimodal:** >70 % of failures are sub-10-second flaps (noise, pre-correlation suppression); **80 % of real incidents last 10–100 min** (103 Google post-mortems); one traced flood ~40 min sharp-rise/sharp-decay | peer-reviewed |
| Escalation class | Real storms can RAMP: 5,001 → 740,946 pps over ~5 h (production field log); self-resolving precursor spikes for weeks before a 4-day collapse | field logs / post-mortems |
| Chronic noise | ~10⁵ flap events/hour excluded from a datacenter study's analysis; one device emitted 250 spurious "link down"/hour for 2.5 months; 49 % of a production alarm stream was chattering | peer-reviewed + vendor |
| Flood definition (formal standards) | ISA-18.2 / EEMUA-191: flood = **>10 alarms/10 min/operator**, exits at **<5/10 min**; target **<1 % of time in flood**; upset tiers <10 / 20–100 / >100 per 10 min | the only formal standards quantifying event storms |
| Overload pass criterion | **Sustainable throughput** = highest load without continuously-increasing event-time lag (ICDE 2018, verbatim); mechanically checkable via a **lag-trend slope** over ≥5 min after 1 min warm-up (Theodolite); grade at **90 %** of it (100 % ≈ 2× tail latency) | benchmark literature |
| Recovery criterion | Recovered = metrics within **15 % of baseline for ≥40 s**; censored if not recovered within the window (DEBS 2024); burst test = pre-accumulated backlog + measured catch-up (OSPBench) | benchmark literature |
| Burst-vs-provisioning split | "If an overload is sustained, the system is not provisioned properly" (VLDB 2006) — sustained capacity and storm survival are DIFFERENT tests and must not share a criterion | peer-reviewed |
| Degradation contract | Subset (fewer, fully-correct results) vs bounded-error (all results, degraded confidence) is an explicit product choice; no vendor states one | peer-reviewed |
| Correlator-tier capacity norm | IBM Netcool/Impact sized at **350–500 eps sustained, 1,000 eps momentary**; Moogsoft Alert Builder <20–100 eps against 10,000 eps ingest — correlation capacity runs ~10× below ingest capacity industry-wide | vendor sizing docs |
| Burst policy precedents | FortiSIEM: burst to 5× licensed from banked EPS, drops above 1.1× sustained, says provision compute for 5×; QRadar 2–3× peak licensing | vendor docs |

The IBM anchor deserves one sentence of its own: our measured single-owner
ceiling (≤400–500 admitted sig/s, pre-168 density) sits **exactly in the
industry band for commercial correlation engines**. The platform was never
slow by its class; it was being graded against a workload no class survives.

## 3. Principle 1 — capacity is stated PER TIER, never for "the platform"

Following the IBM/Moogsoft pattern and the tier-dependent amplitude evidence,
every capacity statement in the contract names its tier:

| Tier | Unit | Bound by | Storm multiplier seen |
|---|---|---|---|
| Ingest/transport (syslog-ng, Vector, Kafka) | raw msgs/s | broker + parsing | ~3–10× (plus chatter floor) |
| Suppression/de-chatter + classification | raw msgs/s → admitted sig/s | classifier throughput | absorbs the 10⁵-events/hour chronic-flap class |
| **Correlation** | admitted sig/s + active objects | single-owner CPU + persistence | ~10× |
| Persistence (ClickHouse) | rows/s | archive shape (fixed by 156 v2) | follows objects |

De-chatter/suppression capacity becomes an **explicit ingest-tier
requirement** (the literature's raw firehose is dominated by sub-10 s flap
noise that must die before correlation) — today this exists implicitly as
classifier admission + dedup; the contract states it.

## 4. Principle 2 — two test families, per the burst-vs-provisioning split

**Family T (provisioning / sustained):** measures **sustainable throughput**
per owner replica (Karimov definition; Theodolite lag-slope as the detector:
linear regression over pending depth for ≥5 min after warm-up; sustainable ⇔
slope ≤ 0 + noise band). GA claims are made at **90 %** of the measured
number. Nominal and p95 band tests (EPS proposal §5) are Family T and must
pass with pending → 0 continuously.

**Family S (storm / burst):** never graded on real-time keep-up. Graded on:
1. **Invariant gates (absolute, unchanged):** no silent loss (accounting
   equation exact), no weld (168), memory bounded, no crash/rebalance,
   degradation DECLARED (`storm_mode` on every snapshot scored under it),
   tenant isolation.
2. **Goodput flatness DURING the storm** (the criterion the whole
   vendor/SRE corpus converges on — AWS: goodput must "plateau… and remain
   flat even when more throughput is applied"; Google: degrade or reject but
   never collapse): cohorts-completed/sec and correctly-evaluated signals/sec
   must hold at the sustainable rate while saturated — a collapse toward zero
   under offered load is a FAIL even if recovery later succeeds.
3. **Recovery:** post-storm, pending → 0 within the drain budget, and
   steady-state metrics back within **15 % of pre-storm baseline for ≥ 40 s**
   (DEBS-2024 rule); the 170 completion gate applies at the recovery deadline,
   not during the storm. Recovery time is MEASURED the RFC 2544 §26.5 way:
   timestamp the load step-down, timestamp the return-to-baseline, report the
   difference, repeat and average. **Recovery-hysteresis check** (Google SRE:
   a system healthy at 10,000 QPS that breaks at 11,000 may need load dropped
   to ~1,000 to recover): recovery is verified at NOMINAL load — if pending
   does not drain at nominal after the storm ends, that is the metastable-
   failure signature and an automatic FAIL with a named cause.
4. **Degradation contract (subset model — proposed):** anything the engine
   evaluates is fully correct; under overload it evaluates less and says so
   (storm_mode + counted expiry-before-evaluation), it never emits degraded
   verdicts silently. Sustained expiry-before-evaluation outside a declared
   storm window becomes an ALERT (the platform's true "cannot keep up"
   signal).

## 5. The redefined storm profiles

All compose with the ratified 1K-per-tenant envelope and the EPS baseline
(nominal 400 raw / ~20 admitted sig/s fleet). Blast-radius devices emit at
their storm rate; the rest of the estate stays at nominal. Promotion during a
storm is HIGH by nature (storm content is control-plane): 30 % planning value.

| Profile | Shape | Parameters (1K rung) | Anchors | Pass criteria |
|---|---|---|---|---|
| **S1 — design storm** (supported; pass/fail for GA) | step, sharp decay | blast radius **10 %** (100 devices) × ~36 EPS/device + 900 at nominal ⇒ **~4,000 raw / ~1,200 admitted sig/s**, duration **15 min** | aggregate-tier 10×; radius ≪ estate (real max <2 %; 10 % adds margin); duration inside the 10–100 min incident band | Family S invariants · drain ≤ **3× duration** · DEBS recovery rule |
| **S1-long — endurance storm** (supported) | step | same rate, **60 min** | 80 % of incidents last 10–100 min | same; drain ≤ 3× duration |
| **S2 — escalation storm** (NEW; supported) | linear ramp 1× → 10× over **60 min**, hold 15 min | ends at S1 rate | the 5-hour pps ramp field log; CareGroup precursors — step-only rigs miss the slow-escalation killer | Family S invariants · storm_mode fires DURING the ramp (declaration latency recorded) · recovery as S1 |
| **S3 — saturation probe** (engineering only; today's harness, relabelled) | flat plateau | 2,000 eps × 100 % promotion × estate-wide × 5 min | none — deliberately beyond any measured reality (~20–200× admitted); retained as the defect finder that caught 168/archive/durability | **Invariants + trend only**: measure sustained throughput during the run; FAIL only on invariant breach or >10 % throughput regression vs. last S3. NEVER a completion bar |
| **S4 — chatter probe** (NEW; ingest tier) | continuous | 3–5 devices in sub-10 s flap loops (~50–250 events/hr each) for 24 h alongside nominal | the 250/hr chronic device; the 10⁵/hr flap class; 49 % chatter share | Zero correlation-tier impact: object count and per-cycle cost flat; suppression counters move; no RCA object churn from chatter |

Trap-lane storm rider (applies to S1/S2): affected devices also emit traps at
up to the vendor-recognized storm line (20 traps/s/device), same grading.

## 6. What changes operationally

| Item | Today | Proposed |
|---|---|---|
| Nightly cron | S3 stress → guaranteed FAIL noise, confounded evidence | **Family T nominal** (regression detection, must PASS) |
| Weekly | — | S1 + S4 |
| Pre-release / on-demand | — | S1-long, S2, S3 (trend), full ladder |
| 72 h soak | blocked on undefined workload | Family T nominal + one embedded S1 exercise + S4 running throughout, promotion-realistic profile |
| Tracker 166 pass bar | absolute completion of S3 | Family T at ratified bands + S1 pass |
| Harness | single profile, flat, estate-wide, null-keyed | blast-radius parameter, ramp generator, chatter generator, tenant-keyed injection, `workload_class` stamped in every report |
| Capacity claims | one number | per-tier numbers + the 90 %-of-sustainable grading rule + a stated burst policy (precedent: FortiSIEM 5×/1.1×) |

## 7. Honest limits of the evidence

Storm-duration distributions exist only for network *failures* (10–100 min),
not alarm *floods* (single traced examples); S1's 15-min primary duration is a
band choice, not a measured median. Broadcast-storm rates have **no**
peer-reviewed production measurement — the L2 numbers rest on vendor logs and
regulator post-mortems. The 30 % storm-promotion figure is reasoned (storm
content is control-plane), not measured; the first S1 run measures it. The
blast-radius 10 % is deliberately ~5× above the largest measured unplanned
correlated group, as margin.

## 7a. Vendor/standards mechanics (merged from the completed standards sweep;
ISA-18.2-2016 read in full text — see the research deliverable for verbatim
citations)

Three findings that shaped the sections above:

1. **Storms are defined WITH HYSTERESIS in every formal standard**, and the
   band is human-factors-derived: ISA-18.2 flood entry >10 alarms/10 min,
   exit <5/10 min (2:1); the band spans EEMUA-191's two worst tiers exactly.
   Consequence adopted: `storm_mode` should gain hysteresis (enter at the
   high threshold, exit at ~half) instead of today's single
   `STORM_BUFFER_FRACTION` line — filed as an implementation note, not a
   blocker.
2. **Averages hide storms — the standards demand peak AND average graded
   simultaneously.** Worked example from real plant data: an hourly average
   below the action limit concealed 9.3 % time-in-flood against a <1 %
   target. Our gates therefore always grade peak 10-min-window rates
   alongside run averages.
3. **The convergent industry acceptance criterion is "flat goodput +
   unattended recovery", not "no loss"** — adopted verbatim into Family S
   criteria 2–3 above, including the RFC 2544 §26.5 recovery-time recipe
   (the only numeric overload→release→recovery methodology published
   anywhere) and Google's recovery-hysteresis warning.

Corroboration for chosen parameters: Sumo Logic's published burst multipliers
are **10×/8×/6×/4×** by tier (10× at our scale class — independently matching
S1's amplitude); FortiSIEM allows a **5× accumulated burst bank** over a 1.1×
instantaneous ceiling; QRadar and ArcSight treat peak ≈ **1.5–2× sustained**;
AWS MSK Express publishes **1.5×** sustained→max. Catch-up sizing now has a
formula instead of folklore: **drain_time = lag/(k−1)** where k =
capacity÷arrival — our "drain ≤3× duration" gate implies k ≥ 1 + (m−1)/3 for
a storm at multiple m of sustainable rate, which the qualification MEASURES
rather than assumes. And the degrade-before-drop pattern QRadar documents
(route raw to storage, uncategorized but searchable) is **already our
architecture** — raw signals persist to corr_signals/OpenSearch regardless of
correlation backlog; the contract now claims it explicitly, alongside the
3GPP TS 32.111-2 post-overload resynchronization shape (declare state
untrustworthy → rebuild → declare trustworthy), which is what `storm_mode`
plus the 170 completion gate already implement informally.

## 8. Ratification asks (owner)

1. Adopt the **two-family structure** (T = provisioning, S = storm) and
   retire absolute completion as the S3 criterion. *Default: yes.*
2. Ratify the **S1/S1-long/S2/S4 parameters** in §5. *Default: as tabled.*
3. Adopt the **subset degradation contract** (§4.3) as the stated product
   behaviour under overload. *Default: yes — it is what the engine already
   does; this makes it a promise instead of an accident.*
4. Approve the **operational cadence** change (§6), including switching the
   nightly cron from S3 to Family T nominal. *Default: yes.*
5. Confirm S3 stays in the suite as an engineering probe with trend grading.
   *Default: yes.*

**All five asks: APPROVED at defaults (owner, 2026-08-22).**

## 9. Beyond-industry targets (owner rider: floors vs stretches)

Industry anchors above are FLOORS. Stretch targets, recorded beside them and
graded as *measured-then-claimed*, never assumed:

| Dimension | Industry floor | Correlix stretch |
|---|---|---|
| Ingest under overload | FortiSIEM drops >1.1×; QRadar queue-full drop is "unrecoverable" | **Never-drop raw**: Kafka holds the backlog (7-day retention) and corr_signals persists every event even while correlation lags — already architecture, now a claim. Gate: S3 accounting stays exact at ANY offered rate |
| Storm drain | drain ≤3× duration (our S1 gate; industry has no published number) | **≤2× duration** once post-fix capacity is measured (model says ~2.4× at the conservative pre-168 ceiling — the fix should beat 2×) |
| Degradation declaration | no vendor declares per-result degradation | **Per-snapshot `storm_mode` + counted expiry** — finer than anything found in the corpus; keep and market it |
| Degradation contract | no vendor states one | **Stated subset contract** (fewer, fully-correct incidents) — first-in-class by the research's own finding |
| Correlator capacity | IBM Impact 350–500 eps sustained / 1,000 burst | **Measure post-fix single-owner ceiling and claim at 90 %**; the fix removes a 98.6 % persistence tax, so exceeding 1,000 admitted sig/s sustained is the target to verify in Falsification Test B |
| Recovery verification | RFC 2544 measures recovery time; nobody verifies at nominal | **Recovery-hysteresis check at nominal** (metastability detection) — not found in any vendor's qualification |
