# EPS baseline proposal — externally grounded, 1K → 10K

**Date:** 2026-08-22 · **Status: RATIFIED (owner, 2026-08-22 — "approve
all"): §10 decisions 1–6 approved at their recommended defaults; decision 4's
1K rung was ratified earlier the same day. Standing rider: industry-derived
numbers are FLOORS — see the gate spec §9 for the stretch targets.** Companion to `GA_WORKLOAD_CONTRACT_1K.md` (which established
that no approved rate existed) and `PREGA_ARCHITECTURE_REVIEW_2026-08-22.md`
(which made ratification a condition for grading any further qualification).

**Method:** two independent market-research sweeps (SIEM/log-collector sizing
standards; NMS/telemetry benchmarks and measured academic corpora), reconciled
against everything measured in this tree. Every external number below carries
its source; every internal number carries its run id or file. Where evidence
conflicts, the conflict is shown, not averaged away.

---

## 1. The two headline results

**1. The 182-vs-5,000 conflict dissolves once "nominal" and "storm" are
separated.** Credible sustained syslog rates for network devices are
**0.1–2 EPS/device** (SIEM planning tables) and **0.006–0.26 EPS/device**
(measured production corpora: SINET4 backbone, Baidu datacenter switches,
tier-1 ISP routers in IMC 2010). Storm/peak multipliers for network devices are
**~10×** (SolarWinds per-device peak table; SANS switch peak; FortiSIEM's
provision-for-5×-burst license rule; QRadar 2–3× diurnal). So for 1,000 network
devices: **nominal ≈ 400 EPS raw, storm ≈ 4,000 EPS raw.** The planner's 5,000
is a legitimate *storm-headroom ingest-sizing* figure; the measured 182 is a
legitimate *nominal-band* figure; neither was wrong — they were answers to
different questions that the contract never separated.

**2. The promotion ratio is externally grounded at ~0.5–7 %, NOT 100 %.**
Control-plane/protocol messages (BGP, OSPF, MPLS, link events) were **0.49 %**
of raw volume on a 158-device national backbone over 456 days (IM 2017/SINET4);
**~4 %** of messages survived preprocessing into that study's causal-analysis
engine; the IMC 2010 tier-1-ISP study distilled raw syslog to actionable events
by **>3 orders of magnitude**; the adjacent HPC corpus (BGL) is 7.34 %
alert-tagged; NOC surveys report <5 % of alerts actionable. The harness's 100 %
promotion is therefore **~20–200× reality** — which converts the standing
`CORRELATION_STRESS` label from a caution into a measurement.

## 2. External evidence anchors (condensed; full tables in the research annexes)

| Quantity | Value band | Strongest sources |
|---|---|---|
| Router syslog, sustained | 0.1–2 EPS/dev (measured: 0.006–0.1) | QRadar tbl 0.25 · ISA 0.1 · Logmanager 2 · IMC 2010 derived |
| Switch syslog, sustained | 0.1–1 EPS/dev (measured: 0.05–0.26) | Logmanager 1 · SANS 0.73 · IWQoS 2017 derived |
| Firewall syslog | 3–400 EPS/dev — **the outlier class; 70–95 % informational session logs** | ISA (3 branch → 50 perimeter) · Logmanager 200–400 · Fortinet FAZ methodology |
| WLC / AP | 1–5 EPS (controller) · 5 EPS/AP (only per-AP figure found) | ISA · Logmanager |
| Peak multiplier, network devices | **~10×** (security devices 50–150×, attack-defined) | SolarWinds whitepaper per-device table · SANS 2009 |
| Burst policy precedents | provision 5× licensed (FortiSIEM, hard rule) · 2–3× (QRadar) | vendor docs |
| Promotion-ratio analogues | **0.5 % control-plane · ~4 % post-preprocess · 7.3 % (HPC) · <5 % NOC-actionable** | IM 2017 · IMC 2010 · BGL · OpsRamp/incident.io |
| Trap rates | normal ≪ 1/s/dev; storm line = 20/s/dev (CA Spectrum) · 50/s/source (NNMi) · 10/s/dev sizing (LogicMonitor) | vendor docs |
| Flows | ~100–200 fps/Gbps (Kentik example); 1–2 % of throughput rule; collectors 40–300 k fps | Kentik · Plixer · SolarWinds NTA |
| gNMI | 48-port switch, interface counters ≈ 1,900 values/sample → **~64 values/s @30 s**; SP-core worst case 70 k values/s @5 s | Cisco xrdocs · Juniper interval guideline |
| SNMP polling | ~10–50 items/dev, 60 s-class cadence → **0.2–1 value/s/dev** | PRTG · LogicMonitor · Zabbix |
| Incident frequency | device failures ~0.2–1.9/dev/**year**; a ~2,000-router ISP distills to **100–200 events/day** | SIGCOMM 2011 (Microsoft) · IMC 2010 |
| Capacity-claim form | per collection unit, native units (EPS / fps / NVPS / elements) + headroom rule (85 % SolarWinds; 5× FortiSIEM) | vendor docs |

## 3. Internal evidence the baseline must reconcile

| Figure | Value | Nature |
|---|---|---|
| Planner `medium` (1K dev) | 5,000 EPS (5.0/dev); flows 20 k fps; probes 167/s; 10 tenants | sizing input, never validated |
| Planner ladder | demo 4.0 · small 10.0 · medium 5.0 · large 3.0 EPS/dev | flat firewall-grade rates for all classes |
| Measured lab p90 (`08210203s5sp`) | 182 sig/s burst-active, 12 min, ~100 % promotion | measured, synthetic single-kind |
| Harness stress default | 2,000 EPS × 5 min = 600 k events | deliberate ~10× overload |
| Single-owner ceiling | ≤400–500 admitted sig/s (pre-168 density; per-HALF-tenant due to the null-key artifact — production single-owner value **unmeasured**, Falsification Test B) | measured bracket, contaminated twice |
| Live object population | 1,626/1,509 open objects at 1K stress | measured |

## 4. Reference fleet mix (1K profile) — PROPOSED

"1,000 devices" must name a composition, or per-class rates cannot compose.
Proposed enterprise reference estate (adjustable at ratification):

| Class | Count | Nominal EPS/dev | Anchors | Fleet EPS |
|---|---:|---:|---|---:|
| Core/edge routers | 20 | 0.5 | QRadar 0.25 · Logmanager 2 · measured ≤0.1 | 10 |
| Access/dist switches | 600 | 0.3 | Logmanager 1 · SANS 0.73 · measured 0.05–0.26 | 180 |
| Firewalls (**management/security events only** — see rule below) | 40 | 2.0 | ISA branch 3 · session logs excluded | 80 |
| Wireless controllers | 10 | 2.0 | ISA 1 · aggregates client events | 20 |
| Access points (via WLC) | 300 | 0.2 | Logmanager 5 is full client logging; mgmt-plane share taken | 60 |
| LB / VPN / other | 30 | 1.0 | ISA LB 1 · Logmanager 5 | 30 |
| **Total** | **1,000** | **0.38 avg** | | **≈380** |

**Firewall session-log rule (proposed, load-bearing):** Correlix is a NetOps
RCA platform, not a SIEM. The supported contract assumes firewalls forward
system/link/HA/routing events, **not per-session traffic logs** (the 70–95 %
informational bulk that drives SIEM sizing). A customer pointing full session
logging at the syslog port is an ingest-tier sizing event, not a correlation
workload — this single rule is why our per-device average (0.38) can be 10×
under the SIEM planning tables and still be honest.

## 5. Proposed syslog baseline — 1K profile

| Band | Raw EPS | Promotion | Admitted sig/s | Basis |
|---|---:|---:|---:|---|
| **Nominal** (24 h sustained) | **400** (0.4/dev) | 5 % | **20** | §4 composition; promotion §6 |
| **p95 / busy-hour** | **800** (2×) | 5 % | **40** | QRadar 2–3× diurnal; conservative 2× |
| **Design storm S1** (regional; ≤15 min) | **4,000** (10×) | **30 %** | **~1,200** | SolarWinds 10× network-device peak; storm content IS control-plane, so promotion rises |
| **Stress S2** (estate-wide; ≤5 min; qualification only) | 2,000 @ 100 % | 100 % | **2,000** | = today's harness. Kept as the falsification workload, never described as a supported customer profile |
| Conservative planning bound (all bands) | ×1 | **15 %** | ×3 on admitted | covers the promotion band's upper edge (BGL 7.3 %, margin ×2) |

Supporting lanes, 1K (nominal → storm): **traps** 50/s → 2,000/s fleet (normal
≪1/s/dev; storm line 20/s/dev on affected radius); **flows** 20,000 fps
(planner value RETAINED — consistent with ~100–200 fps/Gbps at a 100–200 Gbps
monitored estate; sampled); **gNMI** ~32–64 k values/s full estate at 60–30 s
interface-counter cadence (provisional — planner has no figure today);
**SNMP polls** 200–1,000 values/s; **probes** 167/s (planner, retained).
Metrics/gNMI reach correlation only as anomaly episodes — their admitted
contribution is ~0 nominal and is not added to the sig/s columns.

Bytes/event: the 250 B planner assumption sits at the low edge of the external
250–500 B band — acceptable; note 500 B for conservative transport sizing.

**Storm behaviour is part of the contract, stated as policy not aspiration:**
S1 produces ~1.08 M admitted signals in 15 min against a 150 k window and a
real-time engine rate below the storm rate. The supported behaviour is:
Kafka holds the backlog (proven), `storm_mode` is declared on every snapshot
scored under it (exists), overflow/expiry-before-evaluation are counted
(exists), and **pending returns to zero within `drain_factor` × storm duration**
— proposed **3×** for S1 (today's harness gate), measured-then-set for S2.
RCA breadth under storm is bounded-and-declared, never silently wrong.

## 6. Promotion ratio — the single highest-leverage number

Proposed for ratification: **plan at 5 %, bound at 15 %, storm at 30 %,
label 100 % as CORRELATION_STRESS only.** Grounding: 0.49 % measured
control-plane share (SINET4) · ~4 % post-preprocessing input share (same
study) · >1000× raw→event distillation (IMC 2010) · 7.34 % alert share in the
adjacent HPC corpus · <5 % NOC-actionable surveys. The 5 % plan is thus ~10×
above the only directly-measured network control-plane share — deliberately
conservative without being fictional. **First-customer telemetry must
re-measure it** (the promotion ratio is observable in production as
`signals admitted / raw received` — both already counted).

## 7. Incident & object-count model (what production O actually is)

External incident data: device failures 0.2–1.9/device/**year** (Microsoft,
SIGCOMM 2011), links ~5.2 device + 40.8 link failures/day across a whole
multi-thousand-device DC estate; a ~2,000-router tier-1 ISP distills to
**100–200 actionable events/day**. Scaled to 1K devices: **~50–100 RCA-worthy
events/day ⇒ simultaneously-active objects O ≈ single digits to low tens**
nominal, rising to ~blast-radius size (10²–10³) only inside a storm window.

Consequence, and it is the most reassuring number in this document: the
qualification's **1,626 live open objects is ~100× the expected production
nominal**. The per-object cost model (4.3 ms scoring, ~28 ms non-archive
persistence) at production O is trivially inside budget; even the unfixed
archive defect would be latent at O ≈ 20. The architecture review's verdict is
therefore *re-confirmed from the demand side*: the platform's measured pain is
a property of the 100×-reality stress workload, and the archive fix + ratified
workload put 1K far inside the envelope.

## 8. The ladder — 1K → 2.5K → 5K → 10K

Scaling rules (each dimension its own rule, per contract §14O): nominal
syslog/traps/polls scale ~linearly with devices; **storm depth scales with
blast radius, not estate size** (S1 held constant per-incident; estate-wide S2
scales only as a synthetic gate); flows scale with monitored traffic; incident
frequency scales ~linearly; tenant structure does NOT scale linearly.

`D_total` = devices per deployment. `D_tenant_max` = largest single tenant —
**the binding number** (tenant → one partition → one owner replica → one core).
Verdicts use the conservative pre-168 ceiling bracket (≤400–500 admitted
sig/s/owner) and must be re-graded after Falsification Test B.

| Rung | D_total | **D_tenant_max** (proposed) | Nominal raw EPS | Admitted 5 %/15 % (largest tenant) | S1 storm admitted | Capacity verdict vs single owner |
|---|---:|---:|---:|---:|---:|---|
| **1K** | 1,000 | **1,000 — RATIFIED (owner, 2026-08-22)** | 400 | 20 / 60 | ~1,200/s ≤15 min | Nominal: **trivial**. S1: drains ~2.4× duration at 500/s — inside the 3× gate. **Supported after archive fix** |
| **2.5K** | 2,500 | **2,500** | 1,000 | 50 / 150 | ~1,200/s (blast-radius-bound) | Nominal inside ceiling even at 15 %. S1 unchanged per-incident; concurrent-storm risk rises. **Supported; re-grade at Test B; 163 cap + 162 index due here** |
| **5K** | 5,000 | 2,500 recommended (else single-tenant 5K needs Test B headroom) | 2,000 | 100 / 300 | ~1,200–2,400/s | 15 %-band single-tenant-5K = 300/s ≈ 60–75 % of ceiling **before** storms — thin. **Either cap D_tenant_max at 2.5K or trigger Option B** |
| **10K** | 10,000 | 2,500 multi-tenant (Option B required for more) | 4,000 | 200 / 600 | ~2,400/s | Single-tenant-10K exceeds the ceiling at any promotion ≥5 %. **Option B (worker-process scoring) mandatory for D_tenant_max > ~2.5–5K; BUS_PARTITIONS 4→8 after 155 for ≥4-way tenant spread** |

Reading the ladder against the architecture review: the Option B trigger the
review left evidence-conditional now has a number — **it fires when the owner
ratifies `D_tenant_max` > ~2.5K** (at the 15 % conservative band), or when
Test B measures the post-168 ceiling materially lower than the bracket.

## 9. What this resolves in the standing conflict table

* Planner 5,000 EPS ↔ measured 182: **both retained** — 5,000 re-labelled
  *ingest-tier storm-headroom sizing* (≈ S1 raw at 1K, ×1.25 margin), 380–400
  becomes the *nominal correlation-planning* rate. The planner needs no code
  change; its `syslog_events_per_second` semantics should be documented as
  peak-sizing, and a `nominal_eps` note added at next touch.
* Harness 2,000 @100 % ↔ reality: retained as **S2/CORRELATION_STRESS**, now
  formally ~20–200× measured promotion reality. The realistic profile the
  contract demanded exists as of 2026-08-22 (`--event-mix realistic`, six
  kinds); a *promotion-realistic* variant (mixing sub-floor informational lines
  so admitted/raw ≈ 5–15 %) is the remaining harness gap and is the profile
  the 72 h soak should run.
* "1K devices" ambiguity: resolved by carrying `D_total` and `D_tenant_max` as
  separate ratified numbers, recommendation `D_tenant_max = D_total` at 1K
  (enterprise single-tenant honesty).

## 10. Decisions requiring the owner (with recommended defaults)

1. **Ratify the reference fleet mix** (§4) — or supply the real target mix.
2. **Ratify nominal/p95/S1/S2 syslog bands** (§5) — incl. the firewall
   session-log exclusion rule. *Default: as tabled.*
3. **Ratify promotion plan/bound/storm values** (§6). *Default: 5/15/30 %.*
4. **`D_tenant_max` — DECIDED for the 1K rung (owner, 2026-08-22):**
   *"Let's start with 1K per tenant, once that is green then we can scale up."*
   ⇒ the ratified starting envelope is **`D_total` = `D_tenant_max` = 1,000 —
   one tenant holding the full estate**, qualified on a correctly-keyed harness
   (single owner replica carries 100 % of the tenant). Rungs above 1K remain
   OPEN and are decided after 1K is green; the recommended defaults stand
   (2.5K full-tenant next; Option B trigger at `D_tenant_max` > ~2.5K).
5. **Ratify the storm recovery objective** (§5) — S1 drain ≤3× duration;
   S2 gate value set after Falsification Test B. *Default: as stated.*
6. **Bytes/event for transport sizing** — keep 250 B or move to 500 B
   conservative. *Default: keep 250 B, note the band.*

Once 1–3 are signed, tracker 166's remaining criteria become gradeable, the
soak workload (14N) is defined (nominal band + one S1 exercise, promotion-
realistic profile), and `docs/scale/GA_WORKLOAD_CONTRACT_1K.md` §14K can be
re-issued with `RATIFIED` rows replacing `CHARACTERIZATION ONLY`.

## 11. Confidence and limits, stated plainly

External per-device rates span 1–3 orders of magnitude between planning tables
and measured corpora — this proposal anchors nominal near the measured end
plus margin, and storms near the planning end, which is the defensible pairing.
The promotion ratio has exactly one direct network measurement (0.49 %) behind
it; 5 % carries a ×10 cushion but MUST be re-measured on first real traffic.
No per-AP or branch-router figure exists beyond single sources. The capacity
column of §8 rests on a ceiling bracket that is contaminated twice over
(pre-168 density, per-half-tenant split) — every verdict there is conservative
in direction but must be re-graded after Falsification Test B. Nothing in this
document is a supported rate until ratified.
