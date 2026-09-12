---
title: Read an RCA case
description: Open a case and answer the six operator questions from the header, then read the panels that support them.
page_type: task
sidebar_position: 3
---

# Read an RCA case

The RCA case header answers six questions above the fold: what broke, why
Correlix believes that, what is affected, when it started, which evidence backs
it, and which RCA id to quote. Read the header question by question, then the
panels underneath it.

## Before you begin

- Read access to the **Investigate** section (`infrastructure:read`).
- One open or recent correlation case. The queue is empty on a deployment where
  nothing has correlated yet, which is not the same as a healthy network.
- The vocabulary in [How root-cause analysis works](/investigate/rca-explained):
  the verdict ladder and the evidence fidelity ladder are used throughout.

## Steps

### Step 1 - Open the candidate queue

1. Go to **Investigate → RCA**. The page is titled **RCA Candidates**.
2. Read the tier chips above the **Candidate queue**: **Confirmed**,
   **Suspected**, **Not confirmed**, and **Promoted** for the cases whose report
   is in the RCA Reports library.
3. Select a row. Each row carries the short problem handle (for example
   `P-7B32F8`), the status badge, the grounding, and the raw observation count.

The list behind the queue is the same one the API serves:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/correlations?limit=1"
```

```json
{"data":[{"correlation_id":"7b32f8ef-496a-5ccd-82d5-bb3cfae66b27",
  "affected":"{\"devices\":[\"leak-probe\"]}","grounding":"topo",
  "owner":"netops","plane_count":1,"signal_count":64,"state":"open",
  "top_hypothesis":"sig.ent.security.exposure-story","verdict_tier":"suspected",
  "version":2,"window_start":"2026-09-03T03:27:29.248Z",
  "window_end":"2026-09-03T03:27:29.316Z"}],"next_cursor":"MTc4ODQwODk4OTU2MHw3YjMyZjhlZi00OTZhLTVjY2QtODJkNS1iYjNjZmFlNjZiMjc"}
```

The case opens in the workspace, titled **Root cause analysis** with the problem
handle beside it. The view switch at the top right offers **Operator View** and
**Evidence detail**; **Export PDF** downloads the report as rendered.

### Step 2 - What broke

The case title states what was observed, in NOC language rather than in engine
identifiers. The status line under it carries four independent facts, so a
lifecycle state can never be mistaken for an analysis state:

- The **verdict** pill: `CONFIRMED`, `NOT CONFIRMED`, `RULED OUT` for a
  contradicted case, or `RECOVERED`.
- **Confidence**, the engine's own grade of its leading hypothesis.
- **Incident**, the lifecycle: Active, Recovering or Recovered.
- **Analysis**, the engine tier: Confirmed, Suspected, Inconclusive or Detected.

The **Decision** callout below the pills states the recommended action in one
line.

### Step 3 - Why Correlix believes it

The evidence summary under the header states the verdict reason in words. A
confirmed case names the number of independent sources that cross-checked it. A
single-source case names that source and states that a second independent source
is needed. A case with no supported cause states that no cause has enough
supporting evidence yet. No reason is expressed as a percentage.

Each row below the reason is one symptom, with a density bar showing when it was
observed and a fidelity badge showing the weakest parser tier behind it. A row
with no badge declared no fidelity, which is not the same as a low one.

### Step 4 - What is affected

The **Affected** row in the aside states the blast radius in the units the
engine actually measured: affected devices, an adjacency peer, and named
applications. Where nothing measured impact, it reads `Not yet determined`
rather than `0`.

### Step 5 - When, which evidence, which id

- **Detected at** is the start of the correlation window, in UTC.
- **RCA ID** is the case handle to quote in a ticket or a hand-off.
- **Evidence** counts distinct symptoms, independent sources and the duration.
  The raw observation total trails it as **Observations**, deliberately
  de-emphasised: volume is not evidence.
- **Root cause** names the object only when the case is confirmed. Otherwise it
  reads `Not confirmed - possibly because of X`, or states that no cause
  hypothesis has supporting evidence yet.
- **Owner** appears on a confirmed case; **Possible owner** on an unconfirmed
  one, marked unconfirmed. Where the seam has not been narrowed, the row says
  the owner is not yet narrowed.

### Step 6 - Read the panels

**Operator View** renders these panels, in this order, and only where the case
has the data for them.

**Network path and causality**. **Executive RCA summary**. **Impact and blast
radius**. **Event timeline**. **Time impact**. **External ticket**. **Cloud
application and resources**. **Application impact**. **Evidence matrix**.
**Confidence ladder**. **Evidence timeline**. **How the failure propagated**.
**Hypothesis ranking**. **Ticket and escalation decision**. **Next actions**.

**Evidence detail** adds **Evidence accounting** (which observation was used and
why), **Promotion logic** and the **Correlation data model**.

## Result

You can state, from the top of the case alone: what broke, how strongly it is
believed and on what basis, what is affected, when it started, which evidence
supports it, and the id to quote. Panels below the fold explain each of those
claims, and any claim the evidence does not support is stated as unconfirmed
rather than omitted.

## Related

- [How root-cause analysis works](/investigate/rca-explained)
- [Review and rate an RCA verdict](/investigate/rate-an-rca-case)
- [Investigate a symptom](/investigate/investigate-a-symptom)
- [Ask Iris about an incident](/iris-ai/ask-iris)
