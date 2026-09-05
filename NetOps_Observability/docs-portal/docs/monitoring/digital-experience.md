---
title: Monitor digital experience
sidebar_label: Monitor digital experience
description: Track whether users are completing the workflows that matter, read the published experience score and its bands, and tell an absent measurement from a failure.
page_type: task
sidebar_position: 7
---

# Monitor digital experience

Digital Experience answers one question about every application your users
depend on. Are people succeeding, and if not, which part of the path owns the
fix.

The board sits at **Operations → Digital Experience** and has seven views:
**Experience**, **Incidents**, **Journeys**, **Service Paths**, **Synthetics**,
**Changes** and **Data Health**.

Use it when a user reports that an application is slow and you need to separate
the network, the provider and the application before you escalate to anyone.

## Before you begin

- `infrastructure:read` to view the board, `infrastructure:write` to declare a
  workflow or record a change. Digital Experience is per-tenant data, scoped to
  the tenant you are acting as. A cross-tenant account has to select one tenant
  first.
- `FEATURE_DEM=true` in the deployment. With the flag off, every view states
  that collection is off rather than showing an empty table.
- At least one experience target in the catalogue, measured by the prober. See
  [create a monitor](/monitoring/create-a-monitor) for the alerting side and
  [verify monitoring](/onboard-devices/verify-monitoring) for the collection
  side.
- The name of the workflow you want to measure, and the steps a user takes
  through it.

## Steps

To declare a workflow and bind its steps:

1. Go to **Operations → Digital Experience** and select **Journeys**.
2. Select **Declare**. Enter the name, the application it belongs to, and the
   business importance. Importance drives triage order, so a checkout workflow
   is `critical` and an internal report is `normal`.
3. Add one step per user action, in the order a person takes them. Give each
   step an id and a label.
4. Connect the steps. Each step names the steps that may follow it. A step may
   name more than one, and a step may name an earlier step, which is how a retry
   is recorded. At least one step has to be marked as a success terminal, or the
   workflow has no way to succeed and no success rate.
5. Bind each step to a synthetic target from the catalogue. The target is what
   measures the step. A step with no target is declared but not measured, and it
   is reported as a coverage gap.
6. Set the objective. `success_pct` is the share of attempts that has to
   succeed, and `latency_ms` is the p95 objective. A step may override either
   value; a step that sets neither inherits the workflow's.
7. Optionally set a value per success and its currency. Correlix reports
   business impact only when you declare a value. It never invents one. If the
   window contains values in more than one currency, no combined total is shown
   and the panel states why. The per-incident figures stay correct.
8. Save. The definition takes version 1, and every later edit increments the
   version.

To read the result, open **Experience**.

## What you see

### The experience score

The score is a single number from 0 to 100 for the tenant, over a 1-hour or
24-hour window, built from six dimensions.

| Dimension | What it measures |
|---|---|
| `journey_success` | Whether the declared workflows complete |
| `availability` | Whether the targets could be reached at all |
| `responsiveness` | p95 latency against the declared budget |
| `error_free_interaction` | Whether interactions worked once reached |
| `network_quality` | Loss, jitter and path stability underneath |
| `user_friction` | Retries, re-authentication, roaming and abandonment |

Each dimension carries a weight, and the weights depend on the application
class. A voice class weights `network_quality` at 0.35, because for a call the
network quality is the experience. An infrastructure class such as DNS or
authentication does not score `journey_success` at all, because there is no
workflow to complete.

Each dimension is measured across many subjects, one figure per declared
workflow or one per target. Correlix folds them so that the worst subject
carries 40 percent of the weight. Nine healthy targets and one dead one scores
54, not the plain average of 90. The panel names the fold as `worst_weighted`,
because a plain average is how one dead target disappears into a green tile.

Three bands, fixed, and they never move.

| Band | Score |
|---|---|
| Good | 70 and above |
| Fair | 31 to 69 |
| Poor | 30 and below |

The score always shows the version of the weight set that produced it, and the
contribution of each dimension. When the score falls, the panel names the
dimension responsible and by how many points. A weight change increments the
version, so a number from last week is still reconstructible.

`error_free_interaction` and `user_friction` are measured from first-party
real-user telemetry, which Correlix does not collect yet. Both report as not
measured, their weight is redistributed across the dimensions that were
measured, and the panel says so.

### What "not measured" means

Not measured is a third answer, alongside good and bad, and it is never
rendered as either.

- A dimension nothing produced contributes nothing to the score. Its weight is
  shared out among the dimensions that were measured, and the dimension is
  listed with the reason it is absent.
- Below two measured dimensions, no score is published at all. The panel reads
  `below_evidence_minimum` and explains that one dimension is a metric rather
  than an experience. It does not read 0, and it does not read 100.
- A step with no bound target reads `step_not_bound`. Nothing observes it, so it
  is neither passing nor failing.
- A workflow with no measured required step reads `journey_not_measured`. That
  is an absent result, not a healthy one.
- Path stability is absent unless a forward path was observed in the window. An
  absent path never reads as a stable path.
- Affected user and session counts are absent on every incident, because they
  can only be counted from real-user telemetry. A zero there would claim that
  nobody is affected, which is a different statement.

Not measured is not a failure of the product. It is the product refusing to
report a number nothing produced. The full table of blank results across
Correlix is in
[what an empty result means](/reference/honest-states).

### Confidence on an incident

An experience incident carries ranked explanations, and each one carries a
confidence between 0 and 1. The number is always decomposed into six factors,
each with a sentence.

| Factor | What raises it |
|---|---|
| Support | More fresh, reliable observation, up to the point where more stops counting |
| Independence | More kinds of instrument, from more vantages, agreeing |
| Alignment | Evidence falling inside the incident window, and a change preceding the first impact |
| Specificity | Naming a concrete cause and the seam that owns it |
| Contradiction | Fewer observations pointing the other way |
| Completeness | Fewer sources that were expected and reported nothing |

Confidence is a claim about evidence, not a feeling about a conclusion. Five
copies of one check are one opinion, so repeating a source raises support and
never raises independence.

An explanation reaches **Confirmed** only when two different kinds of instrument
from two different vantages agree, nothing required is missing, and nothing
contradicts it. Anything short of that reads **Supported** or **Suspected**, and
the panel lists the exact reasons the gate stayed shut. An explanation that a
measurement refutes outright reads **Rejected**, and it stays on the page with
the observation that refuted it. Ruling a deployment out is a result worth
keeping.

### The telemetry-confidence panel

The panel on the **Experience** view lists every source of experience evidence
and its real state. States are read from the running system and are never
hard-coded.

| State | Meaning |
|---|---|
| `flowing` | The source is reporting. This is the only healthy state. |
| `stale` | It reported, but not recently enough to count. |
| `no_data` | It is configured and produced nothing in the window. |
| `off` | No producer is deployed. |
| `permission_denied` | Correlix has no access to it. |
| `misconfigured` | It is wired incorrectly. |
| `not_supported` | The platform cannot read it here. |

Each row shows when the source was last seen, how many events it produced, its
coverage, and whether it can anchor a confirmed conclusion. Sources with no
producer are listed rather than hidden, because a source missing from the list
is a source nobody notices is absent.

Above the list, one sentence states whether a cause can be confirmed at all. On
a deployment where only one kind of instrument is reporting, it reads that
Correlix can suspect a cause but cannot confirm one, because confirmation
requires two independent observations. That is a property of the evidence
available, not a limit on the analysis.

### The synthetic coverage view

**Synthetics** reports protection rather than a list of tests. Each declared
step is `protected`, `thin`, `untested`, `stale` or `broken`. A step protected
from a single vantage is thin, because one vantage cannot be its own second
opinion. Zero declared steps is not 100 percent coverage, and the view says so.

Per-check reliability reads `unknown` until the prober records per-run results.
A check nobody has graded is not a check that passed.

## Related

- [What an empty result means](/reference/honest-states)
- [Reading an incident](/incidents/reading-an-incident)
- [Track link quality](/monitoring/link-quality)
- [Paths and tunnels](/infrastructure/paths-and-tunnels)
