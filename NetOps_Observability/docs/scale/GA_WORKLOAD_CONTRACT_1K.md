# The 1,000-device GA workload contract — evidence, conflicts, and what is still an owner decision

**Date:** 2026-08-21 · **Status:** evidence assembled; **the contract itself is NOT frozen**
**Purpose:** Phase 14 of the tracker 166 directive. Establish what a supported
1,000-device deployment actually means *before* anyone claims a 1K qualification
or decides whether tracker 167 is GA-blocking.

> **Core rule this document exists to enforce.** "Supports 1,000 devices" is not
> a capacity claim. A capacity claim states the sustained ingest profile, the
> correlation-admitted rate, the candidate density, the tenant skew, the burst
> behaviour and the recovery objective. Device count alone is marketing.

---

## 14A — raw ingest and correlation load are different metrics, and here the gap is ~0

This is the distinction that resolves the "182/s vs 5,000/s — a 27× spread"
question that has been blocking three decisions. **They are not measuring the
same thing, but in the workload we have actually been qualifying against they
almost coincide, and that is the problem.**

| Layer | What it counts |
|---|---|
| **Raw source workload** | syslog msg/s · SNMP traps/s · SNMP poll samples/s · gNMI updates/s · NetFlow/IPFIX records/s · probe results/s · topology updates/s |
| **Correlation workload** | normalized events/s · **signals admitted to the window/s** · candidate pairs/s · scored candidates/s |

### The promotion ratio is the hinge, and ours is ~100 %

`handle_syslog` (`main.py:5887`) admits a syslog line to correlation only if
`syslog_control_signal` or `port_event_signal` classifies it — everything else
is counted in `SYSLOG_RECEIVED` and dropped from the correlation path. So the
classifier *is* the admission filter, and the promotion ratio is a property of
the traffic mix.

`scale-miniladder.py::_syslog_event` injects **100 % `%LINK-3-UPDOWN`** at
severity `err`. Every single line classifies. Cross-checked against the 165
qualification run: 131,041 injected events → 64,482 + 57,997 = **122,479
signals retained across the two replicas**, i.e. essentially 1 signal per event
after expiry.

**Consequence: every rate we have ever measured is simultaneously a raw rate and
a correlation-admitted rate.** We have never measured the platform against a
realistic syslog mix, where the great majority of lines are informational and
never reach the engine. That single unmeasured ratio is what makes the 182 ↔
5,000 comparison unanswerable from existing data.

### And the candidate density of that workload is pathological

Two workloads at identical signal EPS can differ by orders of magnitude in pair
cost. Measured for the harness workload (1,000 devices × 48 interfaces):

| | |
|---|---:|
| retained nodes | 48,000 |
| candidate index groups | 1,048 |
| **groups holding 1,000 nodes each** | **48** (one per interface *name*) |
| Σ C(g,2) over all groups | **25,104,000** |
| candidates emitted by one 5,000-node cohort | **4,854,740** |
| scoring at the measured 30 µs/candidate | **145.6 s** |

The cause was `producers.py:520` stamping a **bare interface name** as a global
correlation token — **tracker 168, now FIXED** (`docs/scale/LOCAL_IDENTITY_SCOPE_168.md`).

### Post-168 density on the identical pattern

| | PRE-168 | POST-168 |
|---|---:|---:|
| largest candidate-index group | 1,000 | **48** |
| Σ C(g,2) over groups | 25,104,000 | **1,128,000** (−95.51 %) |
| candidates / 5K cohort | 4,854,740 | **117,660** (−97.58 %) |
| **candidates / signal** | **970.9** | **23.5** |
| modelled scoring @ 30 µs/cand | 145.6 s | **3.5 s** |
| RCA objects (150 dev × 12 if) | **1** | **150** (ground truth 150) |
| most devices fused into one object | **150** | **1** |
| admitted edges | 144,000 | **9,900** (−93.1 %) |

**Every capacity number measured before this fix is contaminated** and is retained
in this document as `PRE-168 CHARACTERIZATION` — a legitimate pathological
high-density data point, not a capacity claim. That includes the ~800–1,000
signals/s ceiling, the ~384 k carried-edge plateau, and the density inputs to the
1.25 GiB memory qualification.

> **A GA correlation workload is defined by EPS × candidate density, never EPS
> alone — and `candidates/signal` is the number to state.** For this workload it
> is now **23.5**, down from 970.9.

---

## 14J — authoritative sources found in the repository

Every number below is *in the tree*. None of them is an approved commercial
target; the Confidence column says what each one actually is.

| Dimension | Existing value | Source | Confidence / what it really is |
|---|---:|---|---|
| devices (1K profile) | 1,000 | `scripts/resource_planner.py` `PROFILES["medium"]`; `scale-miniladder.py --devices` default | **High** — consistent across planner and harness |
| interfaces | 40,000 | planner `medium` | Medium — a planner sizing input, never measured |
| **syslog EPS** | **5,000** | planner `medium` `syslog_events_per_second` | **Sizing input only.** Feeds ClickHouse/OpenSearch/correlation memory formulas. Never measured, never approved. |
| **syslog EPS** | **2,000** | `scale-miniladder.py --eps` default | **Deliberately ~10× nominal.** Its own help text: *"pick ~10x your nominal syslog rate and ABOVE the ~1k/s correlation drain ceiling so the drain proof is not vacuous"* ⇒ **implies a nominal of ~200/s** |
| **syslog EPS** | **182/s** | `docs/scale/DRAIN_BOTTLENECK_165_2026-08-21.md` — 131,041 events in 721 s | **Measured.** The lab's p90 *active* rate. What 165 was qualified at. |
| syslog EPS (burst) | ~2,000/s implied | `main.py` comment: *"two lines per syslog event, ~4,000 lines/s at the GA burst rate"* | **Low** — an in-code aside, no derivation behind it |
| flows/s | 20,000 | planner `medium` | Sizing input only |
| probe tests/min | 10,000 | planner `medium` | Sizing input only (= 167/s) |
| tenants | 10 | planner `medium` | Sizing input only |
| log event bytes | 250 | planner `log_event_bytes`, class `conservative-provisional` | Self-labelled provisional |
| retained signals per 1k EPS | 25,000 in a 15 min window | planner `corr_window_per_keps`, `conservative-provisional` | Self-labelled provisional |
| correlation memory per 1k EPS | 128 MiB | planner `corr_mem_per_keps`, `conservative-provisional` | Self-labelled provisional |
| **correlation throughput ceiling** | **~850–1,050 events/s per instance** | `docs/scale/CORRELIX_SCALE_TEST_REPORT.md` §7 | **Measured**, but `docs/RESOURCE_SIZING.md` records it as *"a lower bound on a degraded system"* — taken while the P1 correlation-thrash defect was live |
| correlation ceiling (2 replicas) | ~800–1,000/s | tracker 166 bracketing: 182/s drains in 25 s; 790/s in 910 s; 1,651–1,905/s never drains | **Measured** |
| ingest ceiling (this box) | healthy ≤2k EPS; degraded by 5k; **lossy by 10k** | scale test report §3.1 | **Measured**, this host only |
| SNMP poll interval / OIDs per device | — | not found | **Absent** |
| gNMI updates/s per device | — | not found | **Absent** |
| topology/discovery change rate | — | not found | **Absent** |
| tenant skew distribution | — | not found | **Absent** |

### Conflicts, reported rather than merged

1. **Syslog EPS for 1,000 devices: 5,000 (planner) vs ~200 nominal (harness's own
   stated basis) vs 182 measured — a 25–27× spread.** These are not reconcilable
   from evidence in the tree. The planner value is a memory-sizing input that was
   never validated against a measurement; the harness value is a deliberate
   overload multiplier; the 182 is a lab p90 on synthetic traffic. **No approved
   commercial rate exists.**
2. **The correlation ceiling is a lower bound.** `RESOURCE_SIZING.md` explicitly
   refuses to auto-size `BUS_PARTITIONS` from it for exactly this reason. It must
   be re-measured after tracker 168, because the 25 M spurious pairs were in
   every measurement that produced it.
3. **Raw ≠ admitted is untested.** Every measured figure has a ~100 % promotion
   ratio baked in.

---

## 14K — provisional characterization matrix (**CHARACTERIZATION ONLY**)

No approved customer rate exists, so this is *engineering characterization*, not
a GA product envelope. **None of these rows is a supported rate.**

> ⚠ **Every row below is `PRE-168 CHARACTERIZATION`.** All of it was measured
> with the interface-name weld active, i.e. at ~971 candidates/signal instead of
> ~23.5. It is retained as a high-density stress data point and must be
> re-measured post-168 before any of it informs a capacity decision.

| Point | Raw syslog EPS | Promotion assumed | Correlation signals/s | Status | Evidence |
|---|---:|---:|---:|---|---|
| C1 historical low | 182 | ~100 % | ~182 | **PASS** — drains in 25 s, budget 2,164 s | 165 qualification, `08210203s5sp` |
| C2 intermediate | 790 | ~100 % | ~790 | **PASS but marginal** — drains in 910 s, 83 % of budget | `DRAIN_BOTTLENECK_165` Part B |
| C3 boundary | ~800–1,000 | ~100 % | ~800–1,000 | **sustainable ceiling (bracketed)** | 166 bracketing, 2 replicas |
| C4 above boundary | 1,651–1,905 | ~100 % | 1,651–1,905 | **FAIL — never drains** | 166 bracketing |
| C5 planner `medium` | 5,000 | **unmeasured** | unknown (≤5,000) | **NOT CHARACTERIZED** | planner profile only |

**C5 is the whole question.** At a realistic promotion ratio of, say, 5 %, 5,000
raw EPS is 250 correlation signals/s — comfortably inside C3. At the harness's
~100 %, it is 5× beyond the ceiling. The platform's GA capacity therefore turns
on a number nobody has measured.

---

## 14L — is tracker 167 GA-blocking? **Cannot be decided yet, and here is exactly why**

The decision rule is `GA sustained correlation requirement` vs `demonstrated
sustainable correlation capacity`.

* Demonstrated capacity: **~800–1,000 correlation signals/s** across two
  replicas — and that figure is contaminated by tracker 168's spurious pairs, so
  it is a floor, not the true capacity.
* Required capacity: **undefined.** It is `GA raw EPS × promotion ratio`, and
  neither factor is approved.

So:

| If the owner sets… | Then |
|---|---|
| GA raw 5,000 EPS **and** promotion stays ~100 % | requirement 5,000/s vs capacity ~1,000/s ⇒ **167 = GA BLOCKER**, 5× short |
| GA raw 5,000 EPS **and** promotion is ≤ 15 % | requirement ≤750/s vs capacity ~1,000/s ⇒ **167 = headroom**, subject to margin |
| GA raw ~200 EPS (the harness's own nominal) | requirement ~200/s ⇒ **167 = headroom**, 5× margin |

**Status update (2026-08-21): tracker 168 is fixed.** The remaining blocker to
deciding 14L is therefore no longer a defect but the two product questions below
— plus a clean post-168 1K re-run to establish the *uncontaminated* capacity
figure. Candidate density on the qualification workload fell 97.58 %, so the
demonstrated ceiling is expected to move substantially; **how far is unmeasured,
and must not be guessed.** The 167 classification stays open until that run.

---

## 14M / 14N / 14O — implications, stated but not acted on

* **Planner (14M).** The 1,280 MiB correlation floor was qualified at 182/s with
  ~50–53 k retained signals and ~384 k carried edges. If the GA workload retains
  materially more, that qualification remains a valid historical data point but
  does not establish the new envelope. **Do not raise the floor by estimation —
  re-measure.** Note also that the ~384 k carried edges are largely tracker-168
  artifacts, so the memory envelope should be re-qualified *after* 168.
* **Soak (14N).** The 72-hour soak must run the approved normal/GA model, not
  182/s because it is convenient. It stays **BLOCKED** until the model is frozen.
* **Scale-up (14O).** Dimensions must not be multiplied uniformly to 2.5K/5K/10K.
  Devices likely scale linearly; tenant count and hot-tenant skew do not; flow
  records and topology size scale on their own rules; RCA incident frequency does
  not track device count. Each dimension needs its own documented scaling rule.

---

## What the owner has to decide (nothing below can be answered from the code)

1. **What is the supported sustained raw syslog rate for a 1,000-device GA
   deployment?** (planner says 5,000; harness implies ~200; measured 182)
2. **What promotion ratio should the GA model assume** — what fraction of a real
   customer's syslog is link-state / adjacency / optics events that become
   correlation evidence? This is the single highest-leverage unknown.
3. **What are the SNMP poll, gNMI, NetFlow, probe and topology-change rates** for
   the 1K profile? Nothing in the tree defines them.
4. **What tenant skew** should the model assume (share of traffic held by the
   largest tenant, and the tail shape)?
5. **What burst multiplier, duration and recovery objective** does the product
   commit to?

Until 1 and 2 are answered, a tracker 166 pass can only be reported as
**"166 mechanism PASS at \<documented workload\>"**, with **"GA workload
qualification pending"** stated separately. It must not be reported as a 1K GA
pass.


---

## Required provisional characterization (post-168)

Once the clean post-168 1K run establishes the uncontaminated ceiling, the
promotion ratio must be characterized rather than assumed. Suggested points —
**engineering characterization, not expected customer ratios**:

| Raw syslog EPS | Promotion | Correlation signals/s | Note |
|---:|---:|---:|---|
| 2,000 | 5 % | 100 | |
| 2,000 | 15 % | 300 | |
| 2,000 | 30 % | 600 | |
| 2,000 | 100 % | 2,000 | today's harness — `CORRELATION_STRESS` |
| 5,000 | 5 % | 250 | planner `medium` raw rate |
| 5,000 | 15 % | 750 | |
| 5,000 | 30 % | 1,500 | |
| 5,000 | 100 % | 5,000 | |

**Capture `candidates/signal` for every point**, not just EPS — two workloads at
the same signal rate differ by orders of magnitude in pair cost, which is the
entire lesson of tracker 168.

## Harness profiles the GA programme still needs

The current generator emits 100 % `%LINK-3-UPDOWN`. It is a valid *stress*
profile and should be kept — **relabelled `CORRELATION_STRESS`**, never described
as representative syslog. A second **representative mixed-ingest profile** is
required before the soak: irrelevant/noise lines, classifiable-but-not-RCA
operational events, RCA-relevant events, and deterministic injected incident
stories, so that promotion behaviour is exercised rather than assumed at 100 %.

Neither profile exists in mixed form today. Building the mixed profile is a
prerequisite for 14N (soak) and is not yet started.