---
title: Integrations (ServiceNow, Jira, and others)
sidebar_label: Integrations
sidebar_position: 3
description: Connect Correlix to your ITSM systems of record — ServiceNow and Jira — and understand where PagerDuty, Slack, and other connectors live.
---

# Integrations (ServiceNow, Jira, and others)

Integrations connect Correlix to your **systems of record** — the ITSM tools where tickets live. Configure them at <kbd>Incident Response → Integrations</kbd>, a guided connector gallery.

- **ServiceNow** and **Jira** are ITSM integrations — configured here.
- **PagerDuty**, **Slack**, **email**, **SMS**, and **SNS** are real‑time notification channels — configured under **[Notifications](/incident-response/notifications)**.

Once an ITSM integration is connected, **[RCA Auto‑Ticketing](/incident-response/rca-ticketing)** can file one ticket per incident automatically.

## ServiceNow

Correlix creates and updates **incident** records in ServiceNow via the Table API, keyed so it never double‑files.

**What you need**

- A ServiceNow instance URL (e.g. `https://yourinstance.service-now.com`).
- A **service account** with permission to create/update the target table (typically `incident`).
- Credentials (basic auth or OAuth, per your instance policy).

**Connect it**

1. Go to <kbd>Incident Response → Integrations</kbd> and choose **ServiceNow**.
2. Enter the **instance URL** and **service‑account credentials**.
3. (Optional) Map fields — Correlix stamps the incident with the RCA summary, evidence, recommended owner, a link back to Correlix, and a **correlation id** used for de‑duplication.
4. **Test** the connection, then **save**.

**How tickets flow**

- One ticket is filed **per incident** (per correlation), not per raw alert.
- The friendly Correlix problem id (e.g. `P‑CCE567`) is carried into the ticket so NOC and ServiceNow share one handle.
- Re‑syncs **update** the existing ticket rather than creating duplicates (the correlation id is the dedupe anchor).

Enable automatic filing in **[RCA Auto‑Ticketing](/incident-response/rca-ticketing)**.

## Jira

Correlix creates and updates **Jira issues** for incidents.

**What you need**

- Your Jira base URL (Cloud or Data Center).
- An **API token** (Jira Cloud) or account credentials (Data Center).
- The target **project key** and **issue type** (e.g. `Incident` or `Bug`).

**Connect it**

1. Go to <kbd>Incident Response → Integrations</kbd> and choose **Jira**.
2. Enter the **base URL**, **auth token / credentials**, **project key**, and **issue type**.
3. **Test** and **save**.

Issues carry the same RCA payload and Correlix link, and are de‑duplicated per incident.

## Other connectors

- **PagerDuty** — for paging the on‑call, set up under **[Notifications](/incident-response/notifications#pagerduty)**.
- **Slack** — for chat notifications, under **[Notifications](/incident-response/notifications#slack)**.

:::info Secrets are write‑only
Instance credentials and API tokens are encrypted at rest and never shown again after saving.
:::

## Next

- **[RCA Auto‑Ticketing](/incident-response/rca-ticketing)** — file tickets automatically per incident.
