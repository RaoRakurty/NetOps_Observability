# Correlix Hosting & Sizing Guide (qualitative)

**Filed 2026-09-01 on owner directive (post-Project-1).** This guide translates
the measured single-host capacity work (`docs/scale/HOST_CEILING_2026-08-31.md`
§3, the 5k/10k over-ceiling rungs, and `docs/scale/PROJECT1_DONE_2026-09-01.md`
§6) into the qualitative sizing language to use with customers and in hosting
specs. The quantitative authority remains the host-ceiling document and the
versioned qualification profile
(`docs/scale/CORRELIX_REFERENCE_CAPACITY_V1.md`); nothing here overrides a
measured number.

---

## 1. Device count is a PROXY — say so everywhere

**What the host actually constrains is events per second.** Devices are the
billable proxy, and the proxy holds only at an assumed per-device event rate.
Actual capacity on any given host depends on:

- **event rate** (the axis that binds first on the reference box),
- **topology density** (signals per incident — the engine's per-cohort cost
  scales superlinearly in *signal density*, not device count),
- **incident cardinality** (how many concurrent stories the workload carries),
- **evidence workload** (versions per incident, blast radius, history size),
- **tenant distribution** (a tenant's whole stream lands on ONE partition →
  one correlation replica; the per-tenant cap binds before the host cap, and
  adding replicas adds tenant capacity, not per-tenant capacity).

**Owner-recommended wording, to be used verbatim in capacity conversations:**

> *"Validated on the reference configuration at 2,500 devices and ~1,000 eps;
> actual device capacity depends on event rate, topology density, incident
> cardinality, evidence workload, and tenant distribution."*

## 2. The four operating zones

Qualitative shape, from the measured ladder (2.5k → 3.5k → 5k → 10k). The
boundary numbers belong to the reference box only; the *shape* is the product
property.

### Zone 1 — Within envelope
*(reference box: ≤ ~1,000 eps; 2,500 devices @ 0.4 eps/device, stretching to
~3,500 @ ~0.29 on one measured leg)*

- Full SLO: whole workload evaluated within budget, lossless exact accounting,
  memory bounded and flat, RCA accuracy at the qualification bar.
- Correlation is **current** — pending returns to zero, verdicts converge, the
  latency band is stable run to run.

### Zone 2 — Approaching ceiling
- Latency grows first: T1 percentiles and completion time consume more of
  their budget while every gate still passes.
- Backlog grows: consumer lag and pending peaks rise; drain takes longer.
- Completion margin shrinks — the run still finishes, with visibly less slack.
- Nothing is lost, nothing is refused; the early-warning signal is *margin*,
  not failure.

### Zone 3 — Beyond ceiling
*(measured at 2× the reference envelope: 5,000 devices, both profiles)*

- The queue grows faster than the engine drains it; **completion fails** (the
  run ends with work still pending) while ingestion stays lossless and the
  consumer group stays stable — 0 restarts, 0 rebalances, 0 shed events.
- Frontier services run near their memory caps (the correlation carrier reached
  94.1 % of its cap with no pending-zero anchor).
- Accuracy degrades by **recall only**: windows that never evaluated and
  starved-`undetermined` objects — **zero false positives, the engine never
  guesses**. Verdicts arrive late or not yet; they do not arrive wrong.
- **Overload on this platform is queueing, never loss.** Past the ceiling the
  customer waits longer for an RCA verdict; they do not lose an event, a
  device, or a consumer.

### Zone 4 — Severe saturation
*(the 10k documentation rung: 4× the ceiling, designed-to-fail, run so the
hosting spec can refuse the configuration with evidence)*

- Pressure spreads to **peripheral services**: the saturation cascade reaches
  paths outside the core pipeline (e.g. the archive lane's fire-and-forget
  writes lost batches under ClickHouse memory pressure — tracker 189's first
  live evidence; api auth latency cascaded under memory pressure).
- **Ingestion may continue lossless while downstream degrades** — the 10k rung
  still accounted 3,600,001 == 3,600,001 injected/persisted while correlation
  was pinned at its `CORR_WINDOW_BUFFER` bound and completion failed by design.
- This zone exists in the record to be **refused** in hosting specs, not
  provisioned for.

## 3. Capacity language tiers — use these terms everywhere

| tier | meaning | example |
|---|---|---|
| **VALIDATED** | met the full SLO on multiple graded legs at the qualification profile | 2,500 devices @ 0.4 eps/device, ~1,000 eps (four+ legs, 345/345 accuracy each) |
| **MEASURED STRETCH** | one clean graded leg, engine-owned clauses green; not the planning number | ~3,500 devices @ ~0.29 eps/device at the same ~1,000 eps |
| **OUTSIDE ENVELOPE** | run to a graded verdict and FAILED completion; lossless, stable, recall-only accuracy loss | 5,000 devices (both profiles INCOMPLETE) |
| **SATURATION CHARACTERIZATION** | designed-to-fail documentation rung; exists to refuse the configuration with evidence | 10,000 devices at 4× the ceiling |

A capacity claim without one of these labels is unbacked. Never promote a
lower tier's number into a higher tier's sentence.

## 4. The negative results are KEPT — engineering documentation, not marketing

The 5K and 10K results (INCOMPLETE runs, the cohort-cost wall bracketed to
(3,500, 5,000] devices at storm density, the saturation-cascade order) are
retained deliberately for **sizing, hosting, and capacity protection**: they
are what lets a hosting spec refuse an oversized configuration with evidence
rather than by assertion, and what defines the degradation story of §2. They
are engineering documentation. They are **not headline marketing material**,
and no marketing claim may cite them as capacity.
