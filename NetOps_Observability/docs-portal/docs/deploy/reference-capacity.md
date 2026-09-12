---
title: Reference capacity
description: The ratified Correlix capacity SLO, the reference box it was measured on, the workload shape behind it, and how to read a capacity claim.
page_type: reference
sidebar_position: 4
---

# Reference capacity

Correlix Reference Capacity V1 is the versioned qualification profile for the single-host reference configuration. It pins the hardware, the workload and the pass bar, so any future build can rerun the same qualification and be compared against the same baseline.

## The SLO

This is the ratified statement, quoted in full. V1 qualifies against this statement and no other.

> Under a 15-minute 1,000-eps storm on 2,500 devices, the platform MUST evaluate the whole workload within 45 minutes of burst end, lose nothing (injected == persisted, 0 DLQ), stay within memory caps, and keep RCA accuracy >= 93 %. T1 p95 is measured and published every run but is not a pass/fail gate.

Four clauses are pass or fail: completion inside the budget, exact accounting with no dead-lettered events, memory inside the per-container caps, and RCA accuracy at or above the bar. Latency is measured and published on every run and is deliberately not a gate.

## The reference box

| Item | Value |
|---|---|
| CPU | 4 cores |
| RAM | 15 GiB |
| Disk | 77 GB |
| Deployment | The full Docker Compose stack on one host |

Every V1 number was measured on this configuration. A rerun on different hardware is a different measurement and must say so. It does not re-baseline V1.

## The workload

| Parameter | Value |
|---|---|
| Device count | 2,500 |
| Event rate | About 1,000 events per second, sustained |
| Burst duration | 15 minutes |
| Correlation replicas | 2, of which one carries the whole single-tenant stream |
| Partitioning | Tenant-keyed, so one tenant's stream lands on one partition |

The last row is the one that shapes a real deployment: a tenant's whole stream is carried by a single correlation replica. Adding replicas adds tenant capacity, not per-tenant capacity.

## Baseline run of record

| Item | Value |
|---|---|
| Leg | `storm-s11` |
| Gates passed | 9 of 9 |
| SLO clauses | 4 of 4 met |

The nine graded gates cover stack preflight, device onboarding, the burst itself, consumer drain, correlation completion, exact accounting, memory flatness, consumer-group stability, and cleanup with zero residue.

## Capacity language

Use one of these four tiers for every capacity claim. A claim without a tier is unbacked, and a lower tier's number is never promoted into a higher tier's sentence.

| Tier | Meaning | Example |
|---|---|---|
| **Validated** | Met the full SLO on multiple graded legs at the qualification profile | 2,500 devices at 0.4 events per second per device, about 1,000 eps total |
| **Measured stretch** | One clean graded leg with the engine-owned clauses green; not a planning number | About 3,500 devices at about 0.29 events per second per device, same total rate |
| **Outside envelope** | Run to a graded verdict and failed completion; still lossless and stable | 5,000 devices |
| **Saturation characterization** | A designed-to-fail rung that exists so a hosting specification can refuse a configuration with evidence | 10,000 devices |

The sentence to use in a capacity conversation:

> Validated on the reference configuration at 2,500 devices and ~1,000 eps; actual device capacity depends on event rate, topology density, incident cardinality, evidence workload, and tenant distribution.

## Device count is a proxy

What the host constrains is events per second. Device count is the billable proxy, and the proxy holds only at an assumed per-device event rate. Actual capacity on a given host depends on five inputs:

| Input | Why it moves capacity |
|---|---|
| Event rate | The axis that binds first on the reference box. |
| Topology density | Per-cohort cost scales superlinearly in how much evidence a cohort carries, not in device count. |
| Incident cardinality | How many concurrent stories the workload carries. |
| Evidence workload | Versions per incident, blast radius, history size. |
| Tenant distribution | One tenant's stream lands on one partition, so the per-tenant cap binds before the host cap. |

## Operating zones

The boundary numbers belong to the reference box. The shape is a property of the product.

| Zone | What it looks like |
|---|---|
| **Within envelope** | The full SLO holds. Correlation is current, pending returns to zero, and the latency band is stable run to run. |
| **Approaching ceiling** | Latency grows first and backlog grows with it. Every gate still passes with visibly less slack. Nothing is lost and nothing is refused; the early warning is margin, not failure. |
| **Beyond ceiling** | The queue grows faster than the engine drains it, so completion fails while ingestion stays lossless and the consumer group stays stable. Accuracy degrades by recall only: windows that never evaluated, and objects left undetermined. There are zero false positives, because the engine never guesses. |
| **Severe saturation** | Pressure spreads to services outside the core pipeline. Ingestion can stay lossless while downstream work degrades. This zone exists in the record to be refused in a hosting specification, not to be provisioned for. |

Overload on this platform is queueing, never loss. Past the ceiling an operator waits longer for an RCA verdict; they do not lose an event, a device, or a consumer.

## What to conclude from V1

| Question | Answer |
|---|---|
| Can one 4-core, 15 GiB host carry 2,500 devices at about 1,000 eps? | Yes, against the full SLO, on repeated graded legs. |
| Is 2,500 devices a universal number? | No. It is 2,500 devices at 0.4 events per second each. Halve the per-device rate and the device count moves; double the evidence each device produces and it moves the other way. |
| What happens if a deployment exceeds the envelope? | Verdicts arrive late, not wrong. Nothing is dropped, and the consumer group does not thrash. |
| Does a rerun on your own hardware re-baseline V1? | No. It is a separate measurement against the same SLO, and it must be reported as such. |
| Should sizing come from this page or from the planner? | From the planner. This page bounds what one reference host was proven to carry; [Plan host resources](/deploy/sizing) turns your own workload into container limits. |

## Related

- [Plan host resources](/deploy/sizing) - turn a declared workload into per-container limits.
- [Deployment requirements](/deploy/requirements) - the floors below which the installer refuses.
- [Verify a deployment is doing work](/deploy/verify-deployment) - prove a deployed stack is consuming and producing.
