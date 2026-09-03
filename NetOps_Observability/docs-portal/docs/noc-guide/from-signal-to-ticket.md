---
title: From observation to ticket
sidebar_label: From observation to ticket
description: How one observation becomes an event, a finding, a correlated group, a graded RCA case, a notification and exactly one ticket.
page_type: concept
sidebar_position: 4
---

# From observation to ticket

One fault produces many observations. Correlix moves those observations through a fixed
sequence of stages, and each stage adds one thing the previous stage could not
claim. Knowing the sequence tells you which console surface answers the question
you have, and how much a given surface is entitled to assert.

## How it works

| Stage | Where you see it | What it adds |
|---|---|---|
| Collection | Nowhere directly. Inspect the planes on **Explore → Metrics**, **Explore → Logs** and **Explore → Flows**. | The measurements. Everything downstream cites these. |
| Events | **Explore → Events** | One time-sorted stream of syslog, SNMP traps and firing alerts, with Time, Type, Severity, Source and Event. Nothing is judged here. |
| Findings | **Investigate → Findings** | A judgement against the device's own baseline. A row carries a severity, a kind, a device, a component, a summary and a score. |
| Correlation | **Investigate → RCA** | The grouping. Related findings and events become one candidate with a **Linked by** relationship, a count of evidence types and an observation count. |
| The RCA case | The RCA workspace, opened from a candidate | The verdict, the ranked hypotheses, the evidence matrix, the confidence ladder and the causal path. |
| Triage | **Overview → Home**, then **Operations → Incidents** | An owner, a next action and a tracked lifecycle. |
| Delivery | **Administration → Notifications** and **Administration → Ticketing & Automation** | The people who need to know, and one record per root cause. |

### The grouping is the point

A finding is a clue. The correlation stage decides whether several clues belong
together, using time proximity and a network relationship, and the **Linked by**
column names which relationship it used. Grouping is what turns fifty alerts
into one incident, and it is why a notification pages once rather than fifty
times.

### The verdict is graded, and the grade is earned

The RCA case reports one of three tiers. `confirmed` requires at least two
measurement classes to agree, seen by at least two observers that share no
measurement authority. `suspected` means supporting observations exist without that
independence. `undetermined`, shown as **Not confirmed**, means the evidence
does not place a cause.

The workspace shows how the grade was reached. The confidence ladder runs
Detected, Suspected, Probable, Confirmed, with the rungs still locked stating
what each one requires. The evidence matrix carries cards for evidence that is
missing or conflicting, not only for evidence that supports the case. The
hypothesis ranking lists every cause considered and why each was kept or
dropped.

### One ticket per root cause

Ticketing policies decide when a case opens a record, gated on the minimum
verdict, on whether the impact is customer-facing, and on persistence and
flap-suppression windows. A tenant with no policy gets a safe default:
customer-facing confirmed faults open a record, and internal, probe-only and
undetermined cases are held. **Simulate a decision** on the policy page answers
*Would open a ticket* or *Held*, with the reason.

Because the record is opened against the case rather than against an alert, the
same fault cannot produce a second ticket while the first is open.

## Where the sequence stops short, and says so

- **A case can stop at `suspected` for a structural reason.** A case supported
  only by controller intelligence, or only by security findings, cannot reach
  `confirmed`, because neither class measures the path. The case says which
  class is missing rather than promoting itself.
- **An empty Action Queue means nothing has correlated.** It is not a statement
  that the network is healthy. Alerts firing without a group are on
  **Operations → Active Alerts**.
- **A path that cannot be placed is reported as unplaced.** The causal topology
  says the fault has not been located rather than drawing a guess.
- **An unattributed seam is named as unattributed.** The case reads
  *Not yet narrowed* rather than assigning a party the evidence does not
  support.
- **Confidence is a rank, not a probability.** It orders hypotheses against each
  other and nothing more.

## Related

- [Start a shift](/noc-guide/where-to-start)
- [Read device logs during an incident](/noc-guide/reading-logs)
- [How correlation works](/investigate/rca-explained)
- [Read an RCA case](/investigate/read-an-rca-case)
- [Notifications](/incident-response/notifications)
- [RCA ticketing](/incident-response/rca-ticketing)
- [Honest states](/reference/honest-states)
