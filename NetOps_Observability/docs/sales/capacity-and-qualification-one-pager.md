# Correlix — capacity & qualification, in one page

**For customer conversations.** Every number here is measured, on a named box,
on a named run. Where something is not measured, this page says so. Nothing on
this page may be rounded up, restated, or promoted into a stronger claim.

Sources of record — quantitative authority, in this order:
[`../scale/CORRELIX_REFERENCE_CAPACITY_V1.md`](../scale/CORRELIX_REFERENCE_CAPACITY_V1.md)
(the frozen qualification profile) and
[`../HOSTING_SIZING_GUIDE.md`](../HOSTING_SIZING_GUIDE.md) (the language to use).
Nothing here overrides a measured number.

---

## 1. The sentence to say

Use this **verbatim** in every capacity conversation
(`HOSTING_SIZING_GUIDE.md` §1, owner-recommended wording):

> *"Validated on the reference configuration at 2,500 devices and ~1,000 eps;
> actual device capacity depends on event rate, topology density, incident
> cardinality, evidence workload, and tenant distribution."*

**Device count is a proxy.** What the host actually constrains is **events per
second**. Devices are the billable proxy, and the proxy holds only at an assumed
per-device event rate. The five variables in that sentence are not hedging —
they are the real axes, and one of them (tenant distribution) is structural: a
tenant's whole stream lands on one partition and therefore one correlation
replica, so the **per-tenant cap binds before the host cap**, and adding
replicas adds tenant capacity, not per-tenant capacity.

---

## 2. The four capacity tiers — verbatim

From [`../HOSTING_SIZING_GUIDE.md`](../HOSTING_SIZING_GUIDE.md) §3, unaltered:

| tier | meaning | example |
|---|---|---|
| **VALIDATED** | met the full SLO on multiple graded legs at the qualification profile | 2,500 devices @ 0.4 eps/device, ~1,000 eps (four+ legs, 345/345 accuracy each) |
| **MEASURED STRETCH** | one clean graded leg, engine-owned clauses green; not the planning number | ~3,500 devices @ ~0.29 eps/device at the same ~1,000 eps |
| **OUTSIDE ENVELOPE** | run to a graded verdict and FAILED completion; lossless, stable, recall-only accuracy loss | 5,000 devices (both profiles INCOMPLETE) |
| **SATURATION CHARACTERIZATION** | designed-to-fail documentation rung; exists to refuse the configuration with evidence | 10,000 devices at 4× the ceiling |

> **A capacity claim without one of these labels is unbacked. Never promote a
> lower tier's number into a higher tier's sentence.**

Two rules that follow, and that a salesperson must not bend:

- **MEASURED STRETCH is not the planning number.** ~3,500 devices is a real,
  clean, single leg. It is not what you size a customer at. Size at VALIDATED.
- **The negative results are engineering documentation, not marketing.** The
  5K and 10K runs exist so a hosting spec can *refuse* an oversized
  configuration with evidence rather than by assertion. No marketing claim may
  cite them as capacity.

### What "outside the envelope" actually feels like

Worth saying out loud, because it is unusually good news:

**Overload on this platform is queueing, never loss.** Past the ceiling the
customer waits longer for an RCA verdict; they do not lose an event, a device,
or a consumer. At 2× the reference envelope, ingestion stayed lossless and the
consumer group stayed stable (0 restarts, 0 rebalances, 0 shed events) while
completion failed. Accuracy degraded by **recall only** — windows that never
evaluated, and starved-`undetermined` objects. **Zero false positives; the
engine never guesses.** Verdicts arrive late or not yet; they do not arrive
wrong.

---

## 3. The V1 leg of record

The qualification profile is **frozen and versioned**: any semantic change — a
different workload, seed, digest, device count, rate, memory cap, gate clause,
scorer or SLO wording — requires a **new numbered profile (V2)**, never a silent
edit of V1. That is what makes "we reran the qualification" mean something.

**Reference box** (§1): 4 cores (Intel Xeon E5-2683 v4 @ 2.1 GHz), 15 GiB RAM,
77 GB disk, full Docker-Compose stack on **one host**. A rerun on different
hardware is a different measurement and must say so.

**The SLO, verbatim** (ratified 2026-08-30):

> *Under a 15-minute 1,000-eps storm on 2,500 devices, the platform MUST
> evaluate the whole workload within 45 minutes of burst end, lose nothing
> (injected == persisted, 0 DLQ), stay within memory caps, and keep RCA accuracy
> ≥ 93 %. T1 p95 is measured and published every run but is not a pass/fail
> gate.*

**Leg of record: `storm-s11`** (run `090121382mk4`, 2026-09-01) — **9/9 gates,
the first perfect run in programme history**, SLO 4/4:

| clause | measured |
|---|---|
| workload | 2,500 devices, ~1,000 eps sustained, 15-minute burst, **900,001** events |
| gates | **9/9 PASS** |
| completion | **94.8 s** engine completion (23 m 41 s total after burst end, drain included) — against a 2,700 s budget |
| losslessness | **900,001 == 900,001**, **0 DLQ**, 0 counted rejections; 2,500/2,500 devices covered |
| memory | memflat PASS on all 9 key containers; correlation carrier ×1.011 **flat** at 82.5 % of its cap |
| accuracy | **345/345 = 100.00 %**, `scorer_version: 2` |
| T1 p95 (published, never gated) | **876 s** (p50 80 s, p99 1,363 s) |
| stability | 0 CommitFailed / 0 UnknownMember / 0 restarts / 0 rebalances over 2,803 s |
| cleanup | 2,500 devices deleted + whole-namespace verified; residue 0 |

Two honesty notes that belong in the same breath:

- **T1 is published, never gated**, and T1 is *time to first correlated version*
  — an engineering lifecycle metric, not time-to-useful-RCA. Do not quote it as
  the latter.
- A graded leg additionally requires a **quiet host** and ≥ 10 GiB root-fs free.
  A leg run under concurrent load is **excluded from qualification**, not
  quietly averaged in — one was (`storm-s10`), and it is on the record as
  excluded.

**Rerunnable on demand.** `scripts/release-qualify.py` reruns the whole V1
qualification against the currently deployed build and grades every clause with
the instrument V1 already names, diffing against the machine-readable `storm-s11`
baseline. It reports **PASS / FAIL / SKIPPED / INVALID** — "we did not measure
it" stays distinct from "it passed", and an untrustworthy measurement (unquiet
host, a replica that restarted mid-run) is INVALID, never a PASS.

---

## 4. What "qualified accuracy" means

**345/345 = 100.00 %** is a real number with a precise and *narrow* meaning.
Say all four of these together or none of them:

1. **Scorer v2.** Accuracy is graded by the twin scorer at version 2
   (`affected_includes` over the union of objects touching the story, plus a
   deterministic `best` selection). The v1 scorer's coin-flip clause is retired.
   **Any accuracy number quoted for a V1 rerun must state `scorer_version: 2`.**
2. **Against seeded ground truth.** The workload is a pure function of
   (profile, seed, device list): same seed ⇒ same digest ⇒ the same stream. Each
   run writes its own `ground-truth.json` naming exactly what was injected, and
   the score is computed against that file — not against a human reading of the
   output.
3. **It measures correct-cause naming.** For 345 labelled incidents across five
   fault templates, the engine named the right cause and the right affected set.
   Detection 1.000, specificity 1.000 — no false positives, no missed stories.
4. **It does NOT measure "useful".** This is the caveat that must never be
   dropped.

### The single-modality caveat — say this unprompted

**`time_to_useful` is not yet measurable, and V1 can never measure it.**

*Useful RCA* is defined as a verdict that is correct **and** operationally
actionable: correct seam, correct ownership domain, blast radius covering the
truth, **at least two independent evidence sources**, and no ignored
contradiction. Every story in the V1 reference workload is **single-modality**
(syslog only). The ≥ 2-independent-source clause therefore cannot be satisfied
by construction, so when the metric was first computed it came back **100 %
censored** — a structural result, not an engine result.

Two things follow, and both are the honest thing to say:

- **The fix is a better benchmark, not a lower bar.** A multi-modality
  qualification workload (a V2 profile, or a separate accuracy bench) is a
  prerequisite. Lowering the two-source requirement is not an option — the
  engine prefers *"still analyzing"* to an unsupported cause, and that
  preference is the product.
- **A pilot is where this first becomes measurable.** Real networks emit syslog
  *and* traps *and* flows *and* probe results about the same fault. A design
  partner's real incidents are the first workload on which
  `time_to_useful` can produce a number at all.

Until then, the honest status line is: **time to useful RCA — not yet measured;
instrument is `scripts/scale-rca-latency.py --ground-truth <run_dir>` on a
qualification leg, and `/api/correlations/{id}/time-metrics` per live case.**

---

## 5. What to hand a prospect, and what to hold back

| hand over | hold back |
|---|---|
| §1's verbatim sentence | Any device number without its tier label |
| The four tier labels and what they mean | The 5K / 10K results as capacity claims — they are refusal evidence |
| The `storm-s11` table in §3, unedited | T1 p95 restated as "time to root cause" |
| §4 in full, including the caveat | An accuracy number without `scorer_version: 2` |
| "Overload is queueing, never loss" | Any figure this page marks *not yet measured* |

---

## Cross-references

- [`../HOSTING_SIZING_GUIDE.md`](../HOSTING_SIZING_GUIDE.md) — the four operating zones and the tier vocabulary
- [`../scale/CORRELIX_REFERENCE_CAPACITY_V1.md`](../scale/CORRELIX_REFERENCE_CAPACITY_V1.md) — the frozen profile, in full
- [`../runbooks/release-qualification.md`](../runbooks/release-qualification.md) — how a V1 rerun is executed and graded
- [`../runbooks/pilot-playbook.md`](../runbooks/pilot-playbook.md) — the pilot this page supports
- [`prospect-meeting-script.md`](prospect-meeting-script.md) — the first-meeting narrative
