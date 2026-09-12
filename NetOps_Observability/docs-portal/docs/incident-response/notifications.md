---
title: Configure a notification channel
sidebar_label: Configure a notification channel
description: Configure email, Slack, PagerDuty, Teams, Amazon SNS, Twilio SMS or ntfy delivery, set a minimum severity, and send a test.
page_type: task
sidebar_position: 2
---

# Configure a notification channel

A notification channel is how an alert reaches a person. Correlix carries seven
channel types, each with its own credentials, its own minimum severity, and its
own test button.

Channels are platform-global plumbing. They are configured once by the platform
owner, and they carry product and tenant alerts.

## Before you begin

- **Platform-owner access.** Every channel route is gated by the platform-admin
  check. An organization or tenant admin receives `403` with
  `platform administrator required`. See
  [identity and access](/administration/identity-access).
- The credential for the channel you are configuring, from the table below.
- A decision on the minimum severity for that channel.

## Steps

### Step 1: open the channel list

1. Go to **Administration → Incident Response → Notifications**.
2. Pick a tile. Six tiles cover the seven configurations: **Email**, **SMS &
   Push**, **Slack**, **PagerDuty**, **Microsoft Teams** and **Amazon SNS**.
   Twilio and ntfy share the **SMS & Push** tile.

The tiles render only for the platform principal. Contact points below them are
visible to everyone.

### Step 2: enter the credential

Enter the values for the channel you picked.

| Channel | Route | What it needs |
|---|---|---|
| Email | `/api/notify/smtp` | Host, port, security mode, from address, recipients, user and password. |
| Twilio SMS | `/api/notify/twilio` | Account SID, auth token, from number, to numbers. |
| ntfy | `/api/notify/ntfy` | Topic, server, token. |
| Slack | `/api/notify/slack` | Incoming webhook URL. |
| PagerDuty | `/api/notify/pagerduty` | Events v2 routing key. |
| Microsoft Teams | `/api/notify/teams` | Incoming webhook URL. |
| Amazon SNS | `/api/notify/sns` | Topic ARN or phone numbers, and a region. |

Amazon SNS credentials stay in the environment as `AWS_ACCESS_KEY_ID` and
`AWS_SECRET_ACCESS_KEY`. They are never stored in the channel configuration.

### Step 3: set the minimum severity

Choose a value from `info`, `notice`, `warning`, `error` or `critical`. Anything
else is refused with `400` and `invalid min_severity`.

The shipped defaults follow one rule: push-class channels gate at critical,
chatter-class channels gate at warning.

| Channel | Default minimum severity |
|---|---|
| Email | `warning` |
| Slack | `warning` |
| Microsoft Teams | `warning` |
| Twilio SMS | `critical` |
| ntfy | `critical` |
| PagerDuty | `critical` |
| Amazon SNS | `critical` |

An alert below the threshold is filtered, not failed. Resolutions are not gated,
so a channel that was told about a firing alert is always told when it clears.

### Step 4: send a test

1. Select the channel's test control. The console posts to the channel's
   `/test` route.
2. Confirm the message arrived.

The test bypasses the severity gate and sends at `critical`, so a test proves the
transport works regardless of where you set the threshold.

## Result

The channel tile reports it is configured, and the stored secret is never
returned again. A `GET` on a channel route reads the secret back as a boolean:

| Channel | Field on read |
|---|---|
| Email | `pass_set` |
| Twilio SMS | `token_set` |
| ntfy | `token_set` |
| Slack | `webhook_set` |
| PagerDuty | `routing_set` |
| Microsoft Teams | `webhook_set` |
| Amazon SNS | `credentials_set` |

A `PUT` that omits the secret preserves the stored one, which is what lets the
console mask a value it can never re-read. Secrets are encrypted at rest with the
platform data key before they are persisted. A Teams or Slack incoming webhook
URL embeds a bearer token, so the whole URL is treated as the secret and the API
returns a boolean for it on read, on write and on test.

## Scope filters on the paging channels

Two channels carry a scope setting on top of the severity gate.

| Channel | Default scope | What it means |
|---|---|---|
| PagerDuty | `platform` | Only platform self-health alerts page. `all` restores the legacy raw-alert paging. |
| Amazon SNS | `all` | Every alert the severity gate passes. |

## Environment variables seed the configuration once

A deployment that configures a channel through the environment has that wiring
migrated into the stored configuration on first run, and then never again. The
latch is persisted with the configuration, so an operator who disables Teams in
the console is not overruled at the next boot by a `TEAMS_WEBHOOK_URL` still
sitting in `.env`.

**The stored configuration is authoritative.** The environment is a bootstrap.

| Channel | Feature flag | Other variables |
|---|---|---|
| Email | `FEATURE_EMAIL_NOTIFICATIONS` | `SMTP_HOST`, `SMTP_FROM`, `SMTP_USER`, `SMTP_PASS`, `SMTP_TO`, `SMTP_TLS_ON_CONNECT` |
| Twilio SMS | `FEATURE_TWILIO_NOTIFICATIONS` | `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM_NUMBER`, `TWILIO_TO_NUMBERS` |
| Slack | `FEATURE_SLACK_NOTIFICATIONS` | `SLACK_WEBHOOK_URL` |
| PagerDuty | `FEATURE_PAGERDUTY_NOTIFICATIONS` | `PAGERDUTY_KEY`, `PLATFORM_ENV`, `PLATFORM_REGION` |
| Microsoft Teams | `FEATURE_TEAMS_NOTIFICATIONS` | `TEAMS_WEBHOOK_URL` |
| Amazon SNS | `FEATURE_SNS_NOTIFICATIONS` | `SNS_TOPIC_ARN`, `SNS_PHONE_NUMBERS`, `AWS_REGION` |
| ntfy | `FEATURE_NTFY_NOTIFICATIONS` | `NTFY_ALERT_TOPIC`, `NTFY_ALERT_SERVER`, `NTFY_ALERT_TOKEN` |

The Teams and Amazon SNS environment paths are deprecated and log a warning when
used. The ntfy environment path is not deprecated: it is the appliance install
path.

:::caution
The ntfy topic used for product alerting must not be the external watchdog's
topic. A `PUT` that sets it to the value of `WATCHDOG_NTFY_TOPIC` is refused with
`400` and
`this topic is reserved for the stack watchdog — use a dedicated topic for platform alerts (watchdog independence)`.
At boot, an `NTFY_ALERT_TOPIC` equal to the watchdog topic refuses to enable ntfy
and logs an error every boot until the deployment gives product alerting its own
topic. The watchdog must stay able to report the stack's own death.
:::

## Contact points

Below the channel tiles, contact points are reusable, tenant-scoped audiences of
type `email`, `slack` or `webhook`. Reading them needs `administration:read` and
creating one needs `administration:admin`, so a tenant admin manages their own
without touching platform channels.

| Route | What it does |
|---|---|
| `GET`, `POST` `/api/notify/contact-points` | List and create. |
| `PUT`, `DELETE` `/api/notify/contact-points/{id}` | Update and remove. |

## Related

- [Connect ServiceNow or Jira](/incident-response/integrations)
- [Open tickets automatically from RCA](/incident-response/rca-ticketing)
- [Monitor Correlix itself](/monitoring/host-monitoring)
- [Work the alert queue](/monitoring/manage-alerts)
