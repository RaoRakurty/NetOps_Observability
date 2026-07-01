---
title: Incident Response overview
sidebar_label: Overview
sidebar_position: 1
description: Route incidents to the right people and tools — notifications, integrations, and auto-ticketing.
---

# Incident Response

Detection is only half the job. Once Correlix finds a problem, the Incident Response section gets it to the right people (notifications), into your system of record (integrations), and — if you want — files the ticket for you (RCA Auto-Ticketing). This page explains how the pieces fit together and the order to configure them in.

## What's in this section

| Feature | Console path | What it's for |
| --- | --- | --- |
| **Command Center** | <kbd>Incident Response → Command Center</kbd> | The live operational picture — an action queue of incidents that need a human |
| **Notifications** | <kbd>Incident Response → Notifications</kbd> | Real-time delivery channels: Email, SMS &amp; Push, Slack, PagerDuty |
| **Integrations** | <kbd>Incident Response → Integrations</kbd> | ITSM connectors: ServiceNow and Jira |
| **RCA Auto-Ticketing** | <kbd>Incident Response → RCA Auto-Ticketing</kbd> | Policies that file **one ticket per root cause** automatically |

## The response pipeline

An event flows through three stages, each configured on its own page:

1. **Alert → notification.** A [monitor](/monitoring/overview) breaches and fires an alert. The alert is dispatched **once, when it first starts firing** — a three-hour breach produces one notification, not hundreds. Every enabled notification channel receives it, subject to that channel's own **Send on severity ≥** threshold. So you can send everything to Slack but only `critical` to SMS. See [Notifications](/incident-response/notifications).

2. **Alert → ticket (per alert).** Independently of notifications, a connected ServiceNow or Jira integration can open a ticket for any alert at or above the connector's **Min severity to ticket** threshold. Tickets are de-duplicated per alert — a flapping alert never spawns duplicates — and are **auto-resolved when the alert clears**. See [Integrations](/incident-response/integrations).

3. **Root cause → ticket (per incident).** Correlation folds related alerts, logs, and events into a single incident with a root-cause verdict (see [How incidents work](/incidents/overview)). **RCA Auto-Ticketing** policies decide when such an incident opens a ticket — one ticket per root cause, never per raw alert, carrying the diagnosis, evidence, scope, and a deep link back to Correlix. See [RCA Auto-Ticketing](/incident-response/rca-ticketing).

Stages 2 and 3 are both optional and can coexist: many teams start with per-alert ticketing at a high severity threshold, then move to policy-driven RCA ticketing once they trust the verdicts, so the ITSM queue holds diagnoses instead of symptoms.

## Recommended setup order

Work top to bottom — each step is verifiable on its own before you add the next.

1. **Add one notification channel and test it.** Open <kbd>Incident Response → Notifications</kbd>, set up Slack or Email, and click **Send test**. Do not move on until the test message arrives — this proves outbound delivery works from your deployment.
2. **Set severity thresholds per channel.** Route noisy-but-useful severities to chat, and reserve paging channels (PagerDuty, SMS) for `critical`. Each channel has its own **Send on severity ≥** selector.
3. **Connect your ITSM.** Open <kbd>Incident Response → Integrations</kbd> and run the guided setup for **ServiceNow** or **Jira**. Choose the **Min severity to ticket** carefully — this controls per-alert ticket volume.
4. **Add an RCA Auto-Ticketing policy (optional but recommended).** Open <kbd>Incident Response → RCA Auto-Ticketing</kbd>, create a policy, and use the built-in **Simulate a decision** dry-run before relying on it. Until you create one, a safe default applies: only customer-facing confirmed faults (and suspected faults at critical severity) file a ticket.
5. **Verify end-to-end with a real alert.** Trigger a test condition via a monitor (see [Create a monitor](/monitoring/create-a-monitor)), then confirm: the notification arrived, the ticket exists in your ITSM, and the incident's ticket card shows the ticket number.

## The Command Center

<kbd>Incident Response → Command Center</kbd> is the NOC operational control plane — an **action queue** of incidents ordered by severity and age, not a raw event feed. Each row carries the incident's RCA state, severity, fault domain, evidence completeness, owner, and ticket state, and the filter bar narrows the queue by exactly those facets:

- **RCA** — Confirmed, Suspected, Blocked, Correlated, RCA running, Resolved
- **Severity**, **Fault domain** (LAN, SD-WAN, Data Center, ISP / Carrier, Cloud Provider, Application, Security, Unknown), **Evidence** (Complete, Partial, Single-stream), **Owner** (Missing, Recommended, Assigned, Escalated)
- **Needs action** — a one-click chip for rows that are missing an owner, have an unticketed confirmed incident, or are blocked on evidence

Use it as the shift-start view: anything surfaced by **Needs action** is a response-pipeline gap — an incident that never reached a person or a ticket.

## Who can configure what

:::note Roles required
- **Notification channels** (Email, SMS &amp; Push, Slack, PagerDuty) are platform-wide delivery plumbing and require a **platform administrator**.
- **Integrations** (ServiceNow, Jira) require an **administrator**.
- **RCA Auto-Ticketing policies** are per-tenant: viewing needs administration read access; creating or editing needs administration write access. Manual ticket actions on an incident (Create / Sync on the ticket card) need infrastructure write access.
:::

## Verify the whole path

After initial setup, run this five-minute check:

1. In <kbd>Incident Response → Notifications</kbd>, every channel you rely on shows **On** and a **Send test** succeeds.
2. In <kbd>Incident Response → Integrations</kbd>, your connector tile shows **Connected** (not **Disabled** or **Not connected**).
3. In <kbd>Incident Response → RCA Auto-Ticketing</kbd>, at least one policy shows **Enabled** — or you are deliberately relying on the default.
4. In the **Command Center**, filter by **Needs action**: a confirmed incident with no ticket and no owner means a gap in steps 2–3.

## Troubleshooting

- **A monitor fired but nothing arrived.** Notifications dispatch only on the *first* fire of an alert — a long-running alert will not re-notify. Check the channel is enabled, its **Send on severity ≥** threshold admits the alert's severity, and **Send test** works. See [Manage alerts](/monitoring/manage-alerts) for alert lifecycle details.
- **Notification arrived, no ticket.** Per-alert ticketing follows the connector's own **Min severity to ticket** threshold, which is separate from the notification thresholds. RCA ticketing follows its policy gates — use the policy **Simulator** to see why an incident was held.
- **Everything is configured but tiles show "Not connected."** Secrets are write-only: re-saving a form with a blank secret keeps the stored value, but a never-saved secret leaves the connector unconfigured. Re-open the setup and complete the required fields.

## Next

- **[Notifications](/incident-response/notifications)** — per-channel setup, field by field
- **[Integrations](/incident-response/integrations)** — ServiceNow and Jira guided setup
- **[RCA Auto-Ticketing](/incident-response/rca-ticketing)** — policy-driven, one ticket per root cause
