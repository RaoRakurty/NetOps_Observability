---
title: Incident timing and recovery
sidebar_label: Incident timing and recovery
description: How Correlix derives each lifecycle stamp on an incident, which ones are observed rather than inferred, and why a phase reads incomplete instead of zero.
page_type: concept
sidebar_position: 5
---

# Incident timing and recovery

Incident timing decomposes one incident's clock into phases and attributes every
timestamp to its source, so the console never reads an approximation as ground
truth. It is what the Time Impact card renders, and what the reliability rollups
aggregate.

## How it works

### The lifecycle stamps

Correlix derives the lifecycle from facts it already records. The engine supplies
the analysis side, and a linked ticket supplies the human side.

| Event | Derived from | Source |
|---|---|---|
| `first_signal` | The correlation window start, which is the earliest observation onset. | observed |
| `detected` | The earliest observation ingest time. | observed |
| `correlation_completed` | The instant the case was persisted. | observed |
| `root_domain_identified` | The persist instant, once the verdict is `suspected` or `confirmed`. | observed |
| `owner_identified` | The same instant. The owner is intrinsic to the grounded hypothesis and has no timestamp of its own. | inferred |
| `evidence_ready` | The persist instant, once nothing is missing from the evidence policy. | observed |
| `ticket_created`, `acknowledged`, `mitigation_started`, `mitigated`, `resolved`, `closed` | The linked ticket's own timestamps. | itsm |

`impact_started` is left absent on purpose. The true onset of customer impact is
unobservable, so the calculator stands in `first_signal` for it and flags the
metric as inferred rather than pretending it measured the onset.

`detected` never precedes the onset. Where clock skew would put it earlier, it is
clamped to the onset.

### Recovery

Recovery used to come from ticket facts alone. A deployment that linked no ticket
read "not measured" forever, which is accurate and useless.

Recovery now resolves in this order:

1. **A linked ticket wins outright.** Its recovery timestamp is used, with source
   `itsm` and confidence 1. A proxy can never overwrite a ticket fact.
2. **Otherwise, a closed case with a window end yields a stamp.** Recovery is set
   to the window end, with source `INFERRED` and confidence capped at **0.7**.
3. **A merged case yields no recovery, ever.** It was folded into another case,
   which carries the real lifecycle. A merged child recovers only in its parent.
4. **An open case yields nothing.** The incident is still live.

The window end is the last written evidence time of the case, and the engine
closes a window after a quiet period. "Closed at the window end" therefore means
the engine saw no further symptoms. That is a proxy for service recovery, not a
measurement of it.

The stamp is still the earliest defensible estimate, because true recovery lies
at or after the window end. The inferred source and the 0.7 cap are what stop the
console reading a proxy as ground truth. A stamp that would precede the onset is
clamped to the onset.

Where the case reports no confidence at all, confidence floors at 0.5, so a
grounded verdict never claims certainty it did not have.

### The phase metrics

Eight metrics are computed from the stamps: time to detect, to correlate, to
isolate, to evidence, to acknowledge, to mitigate, to recover, and to resolve.

A metric with a missing start or end is reported **incomplete**, naming the event
that is missing. It is never reported as a duration of zero. Where clock skew
produces a negative interval, the duration clamps to zero and the metric stays
complete, with the uncertainty carried by its source and confidence rather than
by a nonsensical number.

Each metric also carries the minimum confidence of its two constituent stamps,
and is flagged inferred when either end was inferred.

### The current bottleneck

The bottleneck is the earliest incomplete phase, and it is phase-consistent.
Provider repair is reported only once the seam is isolated, the evidence is
ready, the ticket exists and it has been acknowledged.

A missing ITSM workflow is a measurement gap, not a bottleneck. When no workflow
is connected, the downstream phases read **Not measured**, never "workflow
required", because Correlix finished the RCA and the gap is not a NOC failure.

## Read the trend

**Analytics → Recovery Scorecard** carries **Detection and repair trend**, which
plots MTTD and MTTR over time. It charts the persisted phase-metric snapshots
rather than a live scan, so a chart point and the stat card above it are the same
number computed the same way.

- The statistic is the median, taken by nearest rank, which is the method the
  rollups use for their own p50. A point on this chart therefore agrees with the
  p50 cards beside it.
- Buckets align to the window and bucket size the page already carries. There is
  no second time picker.
- Only a phase marked complete becomes a measurement. A bucket where nothing
  completed is drawn as a gap, never as a zero, and the legend names the event
  the incomplete incidents are waiting for.
- Below the chart the panel states how many incidents in the window have an
  incomplete lifecycle, and what they are waiting on.
- One snapshot counts per incident. Where a calculation-version bump produced a
  second snapshot for the same case, the freshest one wins and the incident is
  counted once.
- Platform self-monitoring is excluded unless you include it, which matches the
  rest of the page.

## Honest limits

- **Detection latency is a per-incident figure only.** The reliability rollups
  exclude it, because the batch path does not run the per-case earliest-ingest
  query and detection would fall back to the onset, producing a misleading zero.
  It is shown on the Time Impact card, where that query does run. Every other
  metric rolls up.
- **A failed earliest-ingest read is loud.** The store failing to answer is a
  different fact from a case with no archived observations, and the failure is
  logged rather than silently blended into the second case.
- **Planned work is separated, not hidden.** An incident whose onset fell inside
  a covering [maintenance window](/monitoring/maintenance-windows) is stamped as
  maintenance and excluded from the mean-time and chronic-offender rollups, so
  planned work does not pollute the figures.
- **A merged case contributes nothing.** Merged children are excluded from the
  rollups, so one event is counted once.
- **A stamp is never invented to fill a gap.** Where nothing was recorded, the
  phase stays incomplete and says which event it is waiting for.
- **The trend reads the most recent snapshots.** The read is bounded, and where a
  tenant's incident volume exceeds that bound the panel says the chart covers the
  most recent snapshots rather than narrowing the window without saying so.

## Related

- [Read an incident](/incidents/reading-an-incident#step-4--read-the-time-impact-card)
- [Open tickets automatically from RCA](/incident-response/rca-ticketing)
- [Schedule a maintenance window](/monitoring/maintenance-windows)
- [Honest states](/reference/honest-states)
