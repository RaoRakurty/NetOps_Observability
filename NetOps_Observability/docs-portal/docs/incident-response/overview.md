---
title: Incident Response overview
sidebar_label: Overview
sidebar_position: 1
description: Route incidents to the right people and tools — notifications, integrations, and auto-ticketing.
---

# Incident Response

Once Correlix finds a problem, this section gets it to the right people and systems.

## What's in it

| Feature | Console path | What it's for |
| --- | --- | --- |
| **Command Center** | <kbd>Incident Response → Command Center</kbd> | The live operational picture |
| **Notifications** | <kbd>Incident Response → Notifications</kbd> | Channels: Slack, PagerDuty, email, SMS, SNS |
| **Integrations** | <kbd>Incident Response → Integrations</kbd> | Connectors: ServiceNow, Jira |
| **RCA Auto‑Ticketing** | <kbd>Incident Response → RCA Auto‑Ticketing</kbd> | Auto‑file one ticket per incident |

## Configure notifications

1. Open <kbd>Incident Response → Notifications</kbd>.
2. Add a channel (e.g. Slack webhook, PagerDuty routing key, email/SMTP, Twilio SMS, AWS SNS).
3. Choose which alerts/incidents route to it.

## Connect ITSM

1. Open <kbd>Incident Response → Integrations</kbd> and connect **ServiceNow** or **Jira** (guided setup).
2. In **RCA Auto‑Ticketing**, define a policy so Correlix files **one ticket per incident** (not per raw alert), carrying the RCA diagnosis, evidence, owner, and a link back.

This closes the loop: detect → correlate → **ticket** → measured recovery time.
