---
title: RCA Auto-Ticketing
sidebar_label: RCA Auto-Ticketing
sidebar_position: 4
description: Automatically file one ticket per incident, carrying the root-cause diagnosis and evidence.
---

# RCA Auto-Ticketing

RCA Auto-Ticketing closes the loop: when correlation produces an incident with a root-cause verdict, Correlix files **one ticket per root cause — never per raw alert** — in your connected ITSM (ServiceNow today), carrying the diagnosis, evidence, affected scope, and a deep link back to the incident. **Incident policies**, configured at <kbd>Incident Response → RCA Auto-Ticketing</kbd>, decide *which* incidents qualify.

This is different from the per-alert ticketing threshold on the [Integrations](/incident-response/integrations) page: that files a ticket per qualifying alert; this files one ticket per *correlated incident*, after the RCA verdict is known.

## Prerequisites

- A connected **ServiceNow** integration ([set it up first](/incident-response/integrations#servicenow)) — the policy decides *when* to ticket; the connection decides *where*.
- Auto-ticketing enabled on your deployment (a platform operator setting). Manual **Create ticket** from the incident's ticket card works whenever the connection is up.

:::note Roles required
Viewing policies needs administration read access; creating, editing, or deleting them needs administration write access (read-only users see the list with a "Read-only" notice). Manual ticket actions on an incident need infrastructure write access. Policies are scoped to your tenant.
:::

## The default policy

With no policy configured, a safe default applies: **customer-facing confirmed faults open a ServiceNow incident** (a *suspected* verdict also qualifies, but only at critical severity); internal-monitoring, probe-only, and undetermined objects are held. Create a policy only when you want to tune those gates.

## Create a ticketing policy

1. Go to <kbd>Incident Response → RCA Auto-Ticketing</kbd>.
2. Click **+ New policy**.
3. Fill in the policy fields:

   | Field | Required | What it is | Example / default |
   | --- | --- | --- | --- |
   | **Policy name** | Yes | A label for this policy; shown in the list and audit | `Customer-impacting outages` |
   | **External system** | Yes | The ticketing system tickets open in — ServiceNow today | `servicenow` |
   | **Minimum verdict** | Yes | The lowest RCA verdict that may open a ticket: `suspected` or `confirmed` | `suspected` |
   | **Assignment group** | No | Routes the incident to a ServiceNow assignment group | `Network Operations` |
   | **Default impact (1–4)** | Yes | ServiceNow impact stamped on new incidents (1 = highest) | `2` |
   | **Default urgency (1–4)** | Yes | ServiceNow urgency stamped on new incidents (1 = highest) | `2` |
   | **Min persistence (seconds)** | Yes | Hold a fault this long before ticketing — flap suppression on the way in. `0` = off | `120` |
   | **Flap suppression (seconds)** | Yes | After a ticket resolves, suppress re-opening within this window. `0` = off | `600` |

4. Set the gate checkboxes:

   | Gate | Default | What it does |
   | --- | --- | --- |
   | **Enabled** | on | When off, this policy never opens tickets (a tenant opt-out) |
   | **Require customer-facing** | on | Only ticket incidents with a meaningful affected device, path, or application |
   | **Suspected needs critical** | on | A suspected (not yet confirmed) verdict only tickets at critical severity |
   | **Allow probe-only** | off | Allow ticketing when the only evidence is an active probe (overrides the two-independent-streams rule) |
   | **Allow internal monitoring** | off | Allow ticketing internal/debug-only monitoring; off keeps non-customer noise out |

5. Click **Save policy**. The policy appears in the list with its status, gate summary (e.g. `≥ suspected · suspected needs critical · customer-facing`), and routing group.

### Dry-run it with the Simulator

Before trusting a policy, test it against hypothetical incidents — **no ticket is created**:

1. Open the saved policy (click its row) and scroll to **Simulate a decision**. The Simulate button is disabled until the policy is saved.
2. Describe a hypothetical RCA object: **Verdict** (`undetermined` / `suspected` / `confirmed`), **Peak severity** (`info` / `warn` / `high` / `crit`), **Persistence (seconds)**, and the flags **Internal monitoring**, **Probe-only**, **Low-authority probe**, **Has affected entity**.
3. Click **Simulate**. The result badge shows **Would open a ticket** or **Held**, with the exact reason — the same operator-readable reason the live decision records.

Run at least three cases: your typical confirmed outage (expect a ticket), a suspected fault at `warn` (expect held if *Suspected needs critical* is on), and an internal-only object (expect held).

## How it runs, and how dedup behaves

- A background sweep periodically evaluates **recently active incidents** against the owning tenant's policy. Qualifying incidents get a ticket **create** queued; ticketing runs through a reliable queue with retries, so it never delays detection or correlation.
- **One incident → one ticket.** The link is keyed per incident per external system. While a ticket is open, the sweep enqueues **updates** only when the incident's RCA state actually changes (new verdict, evidence, or scope) — an unchanged incident is a no-op, and a second ticket is never opened.
- A **failed** create is retried (with backoff) rather than treated as an open ticket; permanently failing actions land in the ticket history with their error.
- **Flap suppression** works on both edges: *Min persistence* delays ticketing until a fault has lasted long enough, and *Flap suppression* blocks re-opening for a window after a ticket resolves.

## The ticket card on an incident

Every incident's detail view carries an **External ticket** panel (open an incident from <kbd>Monitoring → Correlations</kbd>, the <kbd>Incident Response → Command Center</kbd> queue, or <kbd>Monitoring → Incidents</kbd> — see [Working incidents](/incidents/working-incidents)). It shows:

- **Status pill** — the ticket state:

  | State | Meaning |
  | --- | --- |
  | *No ticket* | Nothing filed for this incident yet |
  | *Pending* | A create is queued, mid-flight |
  | *Open* / *Updated* | A live ticket exists (updated = re-synced since creation) |
  | *Resolved* | The ticket was resolved |
  | *Failed* | The last action failed; it will retry, or you can **Retry create** |

- The **ticket number** as a deep link into ServiceNow, plus **Last synced** and the **verdict at sync**.
- **Actions** (infrastructure write access required): **Create ticket** when none exists, **Sync ticket** to push the current RCA state onto an open ticket, **Retry create** after a failure. Actions are queued — you'll see "Ticket creation queued — the worker will open it shortly," and the card refreshes on its own.
- **History** — the audit trail of every action (Created, Updated, Work note, Resolved, Reopened) with timestamp, result, and any error. These timestamps also feed the incident's time decomposition (ticket filed → resolved).

## What gets filed

Each ticket carries the incident's root-cause **title and summary**, the **verdict** and confidence, the **affected scope** (devices, paths, impacted applications), the recommended **next action**, the policy's **assignment group / impact / urgency**, and a **deep link** back to the incident in Correlix — so the NOC and the ITSM share one handle on the same problem.

## Verify it end-to-end

1. Confirm the ServiceNow tile under <kbd>Incident Response → Integrations</kbd> shows **Connected**.
2. Save a policy and **Simulate** your standard outage case — it must read **Would open a ticket**.
3. When a real qualifying incident occurs (or you stage a fault in a lab), open the incident and watch the **External ticket** panel go *Pending → Open* with a ticket number.
4. Follow the deep link into ServiceNow and confirm the diagnosis, scope, and link back to Correlix are in the incident body.
5. Confirm no *second* ticket appears while the incident stays open, even as it re-syncs.

## Troubleshooting

- **Nothing tickets, ever.** Check, in order: the ServiceNow connection is **Connected**; the policy (or the default) is **Enabled**; the incident actually passes the gates — run the **Simulator** with the incident's real verdict/severity/flags and read the **Held** reason.
- **"You need administration access to manage incident policies."** Your role lacks administration rights for this tenant — ask an administrator.
- **Ticket stuck in *Pending*.** The queue retries automatically; a connection problem shows up as *Failed* with the error in **History**. Fix the connection under Integrations, then **Retry create**.
- **Expected a ticket for a suspected fault, got none.** *Suspected needs critical* is on by default — a suspected verdict below critical severity is held. Turn the gate off, or wait for the verdict to confirm.
- **Too many tickets from a flapping fault.** Raise **Min persistence** and **Flap suppression** on the policy.

## The result

A measurable, evidence-backed loop — detect → correlate (root cause) → auto-file ticket → measured recovery time — visible on the [Recovery Scorecard](/incidents/overview).
