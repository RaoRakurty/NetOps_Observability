---
title: Integrations (ServiceNow, Jira, and others)
sidebar_label: Integrations
sidebar_position: 3
description: Connect Correlix to your ITSM systems of record — ServiceNow and Jira — with a guided connect → routing → sync setup.
---

# Integrations (ServiceNow, Jira, and others)

Integrations connect Correlix to your **systems of record** — the ITSM tools where tickets live. Configure them at <kbd>Incident Response → Integrations</kbd>, a connector gallery where each tile opens a four-step guided setup: **Connect → Routing → Sync → Review**.

- **ServiceNow** and **Jira** are ITSM connectors — configured here.
- **PagerDuty**, **Slack**, **email**, and **SMS/push** are real-time notification channels — configured under **[Notifications](/incident-response/notifications)**.

The page's stat strip shows **Connectors**, **Configured**, **Connected**, and live **Open tickets** across both systems. Each tile reads **Not connected**, **Connected**, or **Disabled** (configured but switched off), and a connected tile shows its open-ticket count and ticketing threshold.

:::note Administrator required
Configuring integrations requires administrator access. Credentials and tokens are **stored encrypted and are write-only** — they are never shown again after saving, and re-saving with a blank secret keeps the stored value.
:::

## What a connected integration does

1. **Per-alert auto-ticketing.** Any alert at or above the connector's **Min severity to ticket** opens a ticket. Tickets are de-duplicated per alert, so a flapping alert never spawns duplicates, and when the alert clears the **same ticket is auto-resolved** — in ServiceNow the incident moves to Resolved with close notes; in Jira the issue is closed via your configured **Resolve transition**.
2. **Live open-ticket visibility.** The Integrations page lists each system's open tickets (number/key, severity, device, summary, opened time) so you can see the outstanding queue without leaving Correlix.
3. **RCA-driven ticketing.** With the connection in place, **[RCA Auto-Ticketing](/incident-response/rca-ticketing)** policies can file **one ticket per root cause** carrying the full diagnosis (ServiceNow today).
4. **Optional two-way sync.** In `bidirectional` mode with an inbound webhook registered, ticket state changes made in the ITSM (close, reassign) flow back toward the Correlix incident.

## ServiceNow

**Before you begin,** you need your instance URL and a service account permitted to create and update incidents via the ServiceNow Table API (Correlix authenticates with HTTP basic auth).

1. Go to <kbd>Incident Response → Integrations</kbd> and click the **ServiceNow** tile (**Set up →**, or **Manage →** if already configured).
2. **Step 1 — Connect.** Check **Enable this connector** and fill in:

   | Field | Required | What it is | Example |
   | --- | --- | --- | --- |
   | **Instance URL** | Yes | Your ServiceNow instance base URL; incidents are created here via the Table API | `https://dev12345.service-now.com` |
   | **User** | No | ServiceNow account used to authenticate the REST calls (HTTP basic auth) | `correlix.svc` |
   | **Password** | No | Password for that user (write-only — blank keeps the stored value) | — |

3. **Step 2 — Routing.** Decide which alerts cut a ticket, and where they land:

   | Field | Required | What it is | Example |
   | --- | --- | --- | --- |
   | **Min severity to ticket** | Yes | Only alerts at or above this severity open a ServiceNow incident. Levels: `info`, `low`, `medium`, `high`, `critical` | `critical` |
   | **Assignment group (optional)** | No | ServiceNow assignment group new incidents are routed to; blank uses the instance default | `Network Operations` |

4. **Step 3 — Sync.** Choose the direction (see [Two-way sync](#two-way-sync-and-webhook-secrets) below). `outbound` is the safe default.
5. **Step 4 — Review.** Confirm the summary — status, instance, ticketing threshold, sync mode — and click **Save &amp; connect**. Saving hot-swaps the connector live; no restart is needed.

**Verify it worked**

1. The ServiceNow tile now shows **Connected**, with `0 open incidents · tickets ≥ <severity>` beneath it.
2. Trigger (or wait for) an alert at or above your threshold, then confirm a *ServiceNow — open incidents* table appears on the Integrations page with the new incident number, and that the incident exists in your instance.
3. Clear the alert condition and confirm the same incident auto-resolves in ServiceNow.

**Troubleshooting**

- **Tile says Disabled** — the connector is configured but **Enable this connector** is unchecked. Re-open setup and re-save with it checked.
- **No tickets appear** — the alert's severity is below **Min severity to ticket**, or the service account lacks create rights on the incident table. Test the account with a manual Table API call from your side.
- **Duplicates for one problem** — per-alert tickets are deduped per alert; several *distinct* alerts each get their own ticket. To collapse a whole root cause into one ticket, use [RCA Auto-Ticketing](/incident-response/rca-ticketing).

## Jira

**Before you begin,** you need your Jira Cloud site URL, the project key to file into, and an Atlassian account email + API token (created at id.atlassian.com → Security → API tokens).

1. Go to <kbd>Incident Response → Integrations</kbd> and click the **Jira** tile.
2. **Step 1 — Connect.** Check **Enable this connector** and fill in:

   | Field | Required | What it is | Example |
   | --- | --- | --- | --- |
   | **Base URL** | Yes | Your Jira Cloud site URL; issues are created via the Jira REST API | `https://your-org.atlassian.net` |
   | **Project key** | Yes | The short project key new issues are filed under | `NOC` |
   | **Email** | No | Atlassian account email paired with the API token | `svc@your-org.com` |
   | **API token** | No | Atlassian API token for that account (write-only — blank keeps stored) | — |

3. **Step 2 — Routing.**

   | Field | Required | What it is | Example |
   | --- | --- | --- | --- |
   | **Min severity to ticket** | Yes | Only alerts at or above this severity open a Jira issue (`info`, `low`, `medium`, `high`, `critical`) | `high` |
   | **Issue type (optional)** | No | Issue type created for new alerts; defaults to the project's standard type | `Incident` |
   | **Resolve transition (optional)** | No | Workflow transition used to close the issue when the alert clears | `Done` |

4. **Step 3 — Sync** and **Step 4 — Review**, then **Save &amp; connect** — same as ServiceNow; the change applies live.

**Verify it worked:** the Jira tile shows **Connected**; an alert at or above the threshold produces a row in the *Jira — open issues* table and an issue in your project; clearing the alert transitions the issue through your **Resolve transition**.

**Troubleshooting**

- **Issues created but never close** — the **Resolve transition** name must match a transition available from the issue's current workflow state (e.g. `Done`, `Resolve`). Check the project's workflow.
- **Auth failures** — Jira Cloud needs the *email + API token* pair; a password will not work. Regenerate the token and re-save.
- **Wrong issue type** — if the type you entered doesn't exist in that project, issue creation fails; leave **Issue type** blank to use the project default.

## Two-way sync and webhook secrets

The **Sync** step (identical for both connectors, and also present under Slack/PagerDuty in Notifications) controls direction:

| Field | Required | What it is |
| --- | --- | --- |
| **Sync mode** | Yes | `outbound` promotes incidents to tickets. `bidirectional` also applies inbound state changes (close, reassign) back onto the incident |
| **Inbound webhook** (*Accept inbound state changes*) | No | Only selectable in `bidirectional` mode — lets the provider push state changes back via a registered, HMAC-signed webhook |
| **Webhook signing secret** | Yes, when the inbound webhook is on | Shared secret used to verify inbound webhooks. Write-only; the wizard blocks saving inbound mode without one |

To enable inbound sync: set **Sync mode** to `bidirectional`, check **Accept inbound state changes**, enter a strong **Webhook signing secret**, **Copy** the displayed **Inbound webhook URL** and register it with the provider as its outbound webhook target, then finish the wizard with **Save &amp; connect**. Inbound calls that fail signature verification are rejected. If the panel notes that inbound webhooks are "recorded but not yet driving incident state — pending platform enablement," events are received and stored but not yet applied to incident state on your deployment — ask your platform operator.

:::info Secrets are write-only
Passwords, API tokens, and webhook signing secrets are encrypted at rest and never displayed again. A field showing `•••••• (unchanged)` has a stored value; leave it blank to keep it, or type a new value to rotate it.
:::

## Per-alert vs. per-root-cause ticketing

The **Routing** threshold here files a ticket per qualifying *alert* — simple and immediate, but a multi-symptom outage can open several tickets. **[RCA Auto-Ticketing](/incident-response/rca-ticketing)** instead files **one ticket per correlated root cause**, with the diagnosis and evidence in the ticket body. They can run together; teams that adopt RCA ticketing usually raise the per-alert threshold to `critical` or disable it.

## Next

- **[RCA Auto-Ticketing](/incident-response/rca-ticketing)** — policy-driven, one ticket per incident
- **[Working incidents](/incidents/working-incidents)** — the ticket card on an incident
