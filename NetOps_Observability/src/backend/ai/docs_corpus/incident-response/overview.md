---
title: Incident response
sidebar_label: Overview
description: Where notification channels, ITSM connectors and RCA-driven ticketing are configured, and the order to set them up in.
page_type: index
sidebar_position: 1
---

# Incident response

Delivery has four parts: the channels that carry an alert to a person, the
connectors that project an incident into a system of record, the policy that
decides which root causes are worth a ticket, and the clock that measures how
long each phase took. A platform owner or tenant admin configures all four.

| Page | What it covers |
|---|---|
| [Configure a notification channel](/incident-response/notifications) | Email, Slack, PagerDuty, Teams, Amazon SNS, Twilio SMS and ntfy delivery. |
| [Connect ServiceNow or Jira](/incident-response/integrations) | ITSM connectors, two-way sync and webhook signing secrets. |
| [Open tickets automatically from RCA](/incident-response/rca-ticketing) | The policy that files one ticket per root cause. |
| [Incident timing and recovery](/incident-response/rca-time-intelligence) | How each lifecycle stamp is derived and what confidence it carries. |

## The order to configure in

1. **Channels first.** Nothing downstream delivers until at least one channel is
   configured and enabled. Channel administration lives at **Administration →
   Incident Response → Notifications** and is restricted to the platform owner.
2. **Connectors second.** ServiceNow and Jira are configured per tenant at
   **Administration → Incident Response → Integrations**, so each tenant reaches
   its own system of record.
3. **The ticketing policy last.** **Administration → Incident Response →
   Ticketing & Automation** decides which RCA cases are worth a ticket. It is
   dormant until `FEATURE_RCA_TICKETING` is enabled.

## Two delivery lanes that are not the same

Correlix keeps platform self-health and tenant-facing product alerts on separate
routes. The channels configured here carry product and tenant alerts: monitor
rules, BGP watch, per-tenant security findings.

Correlix's own health goes somewhere else, because a stack that can only report
its own failure through a channel someone had to configure first is not
self-reporting. That route is documented under
[Monitor Correlix itself](/monitoring/host-monitoring), and a tenant-facing
channel can never be pointed at the operator's host-monitoring topic.

## What drives a ticket

Paging and ticketing are driven off correlated RCA cases, never off raw alerts.
Each destination derives a stable deduplication identity from the tenant and the
correlation id, so a storm of 57 alerts that correlate into one cause produces
one incident rather than 57 tickets.

The legacy path that filed tickets straight from raw alerts was removed. It is
re-enablable only with `FEATURE_LEGACY_ALERT_ITSM`, and it is deprecated.

## Related

- [Incidents](/incidents/overview)
- [Monitoring and alerting](/monitoring/overview)
- [Monitor Correlix itself](/monitoring/host-monitoring)
- [Feature flags reference](/reference/feature-flags)
