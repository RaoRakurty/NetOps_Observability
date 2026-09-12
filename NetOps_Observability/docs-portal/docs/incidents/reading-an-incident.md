---
title: Read an incident
sidebar_label: Read an incident
description: "Read one RCA case end to end: the verdict header, the evidence summary, the blast radius, the time impact card and the ticket."
page_type: task
sidebar_position: 2
---

# Read an incident

An RCA case answers six questions above the fold: what happened, how certain
Correlix is, what is affected, when it started, which evidence supports it, and
which case this is. Read them in that order and the rest of the workspace is
supporting detail.

Use this page the first time you open a case, and any time a verdict does not
match what you expected.

## Before you begin

- `alerts:read`, and a case to open. The RCA candidate list is at
  **Investigate → RCA**.
- The Problem ID if you were handed one. It has the form `P-XXXXXX` and is the
  first column of the candidate list.

## Steps

### Step 1: open the case

1. Go to **Investigate → RCA**.
2. Select a row. The Problem ID opens the same case from the Command Center
   queue and from a notification.

### Step 2: read the header pills

Four pills sit under the title, and they are four independent dimensions. The
verdict pill carries the analysis. The incident pill carries the lifecycle.

| Pill | Values |
|---|---|
| Verdict | **CONFIRMED**, **RECOVERED**, **RULED OUT**, or **NOT CONFIRMED**. Each carries a glyph in the console. |
| Confidence | The confidence label in words. |
| Incident | **Active**, **Recovering** or **Recovered**. |
| Analysis | **Confirmed**, **Suspected**, **Inconclusive** or **Detected**. |

"Recovered" is an incident state and never an analysis state. A case can be
recovered and still not have a confirmed cause, and the header says both.

Below the pills, the line **Detected at** carries the window start in UTC, and
**RCA ID** carries the case identity.

### Step 3: read the aside

The right-hand column answers "what is affected" without you scrolling.

| Row | What it says |
|---|---|
| **Root cause** | The object, when the verdict is confirmed. Otherwise `Not confirmed — possibly because of X`, or `Not identified — no cause hypothesis has supporting evidence yet`. |
| **Evidence state** | On an unconfirmed case, what the evidence currently amounts to. |
| **Evidence localizes to** | The device or adjacency the evidence points at, even when the cause is not confirmed. |
| **Owner** or **Possible owner** | The party that owns the seam. Unconfirmed cases append `unconfirmed`, and a case with no attribution reads `Not yet narrowed — NOC triage`. |
| **Affected** | The blast radius, or **Not yet determined**. |
| **Evidence** | Distinct symptoms, independent sources and duration. |
| **Suggested ticket** | `Open P2`, or `Hold — policy threshold not met`. |
| **Observations** | The raw observation total, de-emphasised on purpose. |

**Affected** is never `0 devices`. Unknown is not zero, and the panel refuses to
say "no impact" when no impact telemetry existed.

The **Observations** row is the count of raw rows collected. Repetition shows
persistence, not additional evidence, which is why the evidence row above it
counts symptoms and independent sources instead.

### Step 4: read the time impact card {#step-4--read-the-time-impact-card}

The Time Impact card breaks the incident clock into two zones.

The RCA evidence zone is what Correlix proved or inferred on its own:

| Phase | What it marks |
|---|---|
| **Detected** | Correlix first ingested the onset. |
| **Correlated** | Related observations were grouped into one case. |
| **Root / seam isolated** | The likely root domain or seam was isolated with evidence. This is the phase the card treats as the hero. |
| **Owner assigned** | The responsible owner domain was assigned. |
| **Evidence bundle ready** | The evidence package is ready for escalation. |

The workflow and recovery zone needs evidence Correlix does not produce alone:

| Phase | What it marks |
|---|---|
| **Ticket created** | An ITSM or provider ticket exists. |
| **Acknowledged** | The owner acknowledged it. |
| **Mitigated** | A mitigation action was recorded. |
| **Service recovered** | Service recovery was observed or inferred. |
| **Ticket closed** | The workflow closed. |

Each phase reads as observed, inferred, completed, pending, current or **Not
measured**. A phase with no timestamp is reported incomplete, naming the event
that is missing, rather than as a duration of zero.

A missing workflow is a measurement gap, not a bottleneck. When no ITSM workflow
is connected, the downstream phases read **Not measured**, never "workflow
required", because Correlix finished the RCA and the failure is not the
operator's.

[Incident timing and recovery](/incident-response/rca-time-intelligence) explains
how each stamp is derived and what confidence it carries.

### Step 5: read the evidence summary

Under the header, one row per distinct symptom shows a time-density bar across
the case window, the evidence class that saw it, the parser fidelity behind it,
and the time it was first seen.

The verdict reason sits above those rows, in words. For example, a case with a
single evidence class reads that only that source saw it and a second
independent source is needed to confirm. A ruled-out case reads that the leading
cause was ruled out by the evidence.

Density is rendered as ink rather than as a number, so a symptom that repeated
200 times does not read as 200 pieces of evidence.

### Step 6: read the panels below

| Panel | What it holds |
|---|---|
| **Executive RCA summary** | The case in plain language. |
| **Impact & blast radius** | Affected device, peer, scope type, service and path impact. Unconfirmed rows read `Not confirmed` rather than a number. |
| **Hypothesis ranking** | Each candidate cause with its confidence label and the reason for it. |
| **Ticket & escalation decision** | Whether the case meets the ticketing policy, and why not when it does not. |
| **Next actions** | The specific checks to run next. |
| **Evidence accounting** | Which observations were used, and why. |
| **Promotion logic** | Whether this case qualifies as a promoted real outage. |
| **Correlation data model** | The raw object behind the case. |

## Result

You can state, without opening anything else, what happened, how certain
Correlix is, who owns the seam, what is affected, and which clock phase the
incident is currently sitting in.

If the case is confirmed and customer-impacting, continue to
[open a ticket from it](/incidents/working-incidents#from-incident-to-ticket).
If it is not confirmed, the aside already names what is missing, and the
[symptom workspace](/investigate/investigate-a-symptom) is where you go looking
for the source that would confirm it.

## Related

- [Work the incident queue](/incidents/working-incidents)
- [How RCA works](/investigate/rca-explained)
- [Rate an RCA case](/investigate/rate-an-rca-case)
- [Incident timing and recovery](/incident-response/rca-time-intelligence)
