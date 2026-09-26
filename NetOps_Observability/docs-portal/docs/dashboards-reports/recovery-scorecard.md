---
title: Review the Recovery Scorecard
sidebar_label: Recovery Scorecard
description: Find where incident time is lost, which owner domain carries it, what keeps recurring and what evidence is missing, over 7, 30 or 90 days.
page_type: task
sidebar_position: 4
---

# Review the Recovery Scorecard

**Analytics → Recovery Scorecard** answers a manager's questions about incident
time: where it is lost, which owner domain owns the pain, what evidence is
missing, what keeps recurring, and what to fix next. It counts
customer-impacting incidents by default and reports percentiles rather than
averages. A metric Correlix cannot measure says so. It is never shown as a
made-up time or as `0`.

## Before you begin

- `infrastructure:read`. The scorecard is per tenant: it counts your own
  tenant's incidents only.
- Some incident history. With too few isolated incidents the panels say
  **Not enough isolated incidents yet.** and offer a wider window.

## Steps

1. Go to **Analytics → Recovery Scorecard**.
2. Choose the window: **7d**, **30d** or **90d**.
3. Optionally filter by owner domain, and select **Include internal/platform
   events** to add Correlix's own self-monitoring incidents, which are left out
   by default.
4. Read **Evidence coverage** first: **Correlation**, **Isolation**,
   **Recovery** and **ITSM / closure**. A lane that is not connected explains
   the empty cards below it.
5. Read the cards, then the panels.

## What you see

| Card | What it measures |
|---|---|
| **Customer-impacting incidents** | Incidents in the window. |
| **Median root-domain isolation time** and **P90 root-domain isolation time** | MTTI: how long it took to isolate the fault to its domain. The P90 shows the slow cases a median hides. |
| **Median correlation time** | MTTC: how long the engine took to group the observations into one case. |
| **Median recovery time** | Recovery p50. Reads **Not measured** when no recovery evidence is connected. |
| **Median ticket closure time** | Resolution p50. Reads **Not available** without an ITSM workflow. |
| **Repeat failure interval** | MTBF across repeating failures, or **No repeats yet**. |
| **Repeat-affected incidents** | The share of incidents on an object that failed before. |
| **Top time-loss driver** | The lifecycle phase where the most time goes. |

The panels below the cards:

- **Owner domains**: incidents, MTTI p90, recovery p90, repeat count and the top
  time-loss driver per owner domain. Filtered to the ISP owner, it is the view
  for carrier escalation and SLA review.
- **Lifecycle time breakdown**: time per lifecycle phase.
- **Recurring failure sources**: the objects that fail again and again, with
  their owner, incident count, MTBF and a recommended action.
- **Isolation trend** and **Detection and repair trend**: MTTI, MTTD and MTTR
  over the window. A bucket where nothing completed is a gap, never a zero.

## Related

- [Incident timing and recovery](/incident-response/rca-time-intelligence)
- [Review and rate an RCA verdict](/investigate/rate-an-rca-case)
- [Dashboards and reports](/dashboards-reports/overview)
