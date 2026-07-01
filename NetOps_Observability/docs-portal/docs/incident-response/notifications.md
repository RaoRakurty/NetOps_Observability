---
title: Notifications (Slack, PagerDuty, Email, SMS, SNS)
sidebar_label: Notifications
sidebar_position: 2
description: Route alerts and incidents to your team's channels — Slack, PagerDuty, email, SMS (Twilio), and AWS SNS.
---

# Notifications

Notification channels deliver alerts and incidents to where your team already works. Configure them at <kbd>Incident Response → Notifications</kbd>.

Correlix separates **Notifications** (real‑time channels — Slack, PagerDuty, email, SMS, SNS) from **[Integrations](/incident-response/integrations)** (ITSM systems of record — ServiceNow, Jira). Use both together: page the on‑call *and* file the ticket.

## Add a channel

1. Go to <kbd>Incident Response → Notifications</kbd>.
2. Choose the channel type and enter its credentials (below).
3. Choose **what routes to it** — which severities, monitors, or incident types.
4. Save, then send a **test** to confirm delivery.

## Channel setup

### Slack

1. In Slack, create an **Incoming Webhook** for the target channel (Slack → *Apps → Incoming Webhooks*), and copy the webhook URL.
2. In Correlix, add a **Slack** channel and paste the **webhook URL**.
3. Route the alerts you want and send a test — a message should appear in the Slack channel.

### PagerDuty

1. In PagerDuty, create a service with an **Events API v2** integration and copy the **Integration/Routing Key**.
2. In Correlix, add a **PagerDuty** channel and paste the **routing key**.
3. Correlix triggers a PagerDuty incident when a routed alert fires (and can resolve it when the condition clears). Send a test to verify it pages.

### Email (SMTP)

1. Add an **Email** channel.
2. Provide your **SMTP** server, port, and (if required) username/password and TLS setting.
3. Set the **from** address and **recipient** list.
4. Send a test email.

### SMS (Twilio)

1. In Twilio, note your **Account SID**, **Auth Token**, and a **sending phone number**.
2. In Correlix, add a **Twilio SMS** channel and enter those, plus the **recipient number(s)**.
3. Send a test SMS.

### AWS SNS

1. Create (or choose) an **SNS topic** and note its ARN, plus an IAM identity allowed to `sns:Publish`.
2. In Correlix, add an **SNS** channel with the **topic ARN**, **region**, and credentials.
3. Send a test — subscribers to the topic receive it.

:::info Secrets are stored encrypted
Webhook URLs, routing keys, SMTP passwords, and API tokens are encrypted at rest and never displayed again. Re‑saving with a blank secret keeps the stored value.
:::

## Route alerts to channels

Notifications are tied to your **[monitors](/monitoring/overview)** and incidents. When you create or edit a monitor, choose the channel(s) it notifies. Incidents can additionally file a ticket via **[Integrations](/incident-response/integrations)** and **[RCA Auto‑Ticketing](/incident-response/rca-ticketing)**.

## Next

- **[Integrations (ServiceNow, Jira)](/incident-response/integrations)**
- **[RCA Auto‑Ticketing](/incident-response/rca-ticketing)**
